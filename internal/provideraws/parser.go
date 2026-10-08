// Package provideraws parses terraform-provider-aws Go source files to
// extract the exact AWS SDK API calls required by each resource type.
//
// This provides a more precise alternative to CloudFormation schema resolution,
// capturing only the permissions actually used by the provider, not the
// maximal set of permissions the resource *could* need.
package provideraws

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// ConditionKind says what a gated SDK call needs from its gating attribute.
// The two kinds are evaluated from different data: presence from the planned
// state, change from the difference between prior and planned state.
type ConditionKind string

const (
	// ConditionPresence gates on the attribute being set, from a d.GetOk or
	// d.Get guard.
	ConditionPresence ConditionKind = "presence"
	// ConditionChange gates on the attribute having changed, from a d.HasChange
	// guard.
	ConditionChange ConditionKind = "change"
)

// ExtractedAction represents an AWS IAM action extracted from a provider
// source file, with metadata about whether it is conditionally called.
type ExtractedAction struct {
	Action        string        // e.g., "backup:CreateBackupVault"
	Conditional   bool          // true if this SDK call is inside a conditional block
	Condition     string        // attribute name guarding the call, e.g. "kms_key_arn"
	ConditionKind ConditionKind // what the guard requires of that attribute; empty if unconditional

	// ValueGuarded is true when the guard compares the attribute's value
	// rather than its presence — a set that must be non-empty, say. The
	// attribute then carries a default, so a non-zero value in the planned
	// state says nothing about the configuration and the call only happens
	// when the author set the attribute. Scalar comparisons are not flagged:
	// a defaulted scalar is usually non-zero, which would make the call
	// required, so presence stays the gate there.
	ValueGuarded bool

	// BestEffort is true when the provider ignores the call's failure: it
	// discards the error, or makes the call only on the path that handles an
	// earlier failure. A denied best-effort call does not fail the apply.
	BestEffort bool
}

// discardKind says how a call site drops the error its callee returns.
type discardKind int

const (
	discardNone discardKind = iota
	// discardAlways: the syntax shows the error is dropped, as in
	// `if v, err := f(); err == nil { ... }`.
	discardAlways
	// discardIfError: the call drops its last result, as in `f(...)` as a
	// statement or `x, _ := f(...)`. It drops an error only when the callee's
	// last result is one.
	discardIfError
)

// helperCall records a call to a function of the same package and the
// conditional context at the call site (e.g., if d.GetOk("replica") {
// removeSecretReplicas(...) }).
type helperCall struct {
	Pkg        string        // service package of the helper, "" for the caller's own
	Name       string        // helper function name
	CondReason string        // attribute from call-site d.GetOk/d.Get/d.HasChange guard, empty if unconditional
	CondKind   ConditionKind // kind of the call-site guard, empty if unconditional
	BestEffort bool          // the call site sits on a path that handles a failure
	Discard    discardKind   // how the call site drops the callee's error
}

// ParseResourceFile parses a Go source file from the terraform-provider-aws
// and extracts the IAM permissions (actions) required by each CRUD function.
//
// It handles:
// - Direct conn.Method() calls in CRUD function bodies, closures included
// - Paginators: pkg.NewXxxPaginator(conn, input) → service:Xxx
// - Conditional calls gated by d.GetOk(), d.Get(), or d.HasChange()
// - Calls to other functions of the file, followed transitively:
// retryCreateRole(ctx, conn, ...) → conn.CreateRole, and Create returning
// Read includes the Read permissions
// - Calls whose failure the provider ignores, marked BestEffort: a discarded
// or swallowed error, or a cleanup in the branch that returns an earlier
// failure
//
// Returns all actions (both unconditional and conditional) as plain strings.
func ParseResourceFile(src string, tfType string, resourceName string) (map[string][]string, error) {
	structured, err := ParseResourceFileStructured(src, tfType, resourceName)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]string)
	for k, v := range structured {
		for _, ea := range v {
			result[k] = append(result[k], ea.Action)
		}
		result[k] = dedup(result[k])
	}
	return result, nil
}

// ParseResourceFileStructured parses a Go source file and returns extracted
// actions with conditional metadata (whether the call is inside an if-statement
// guarded by d.GetOk() or d.Get()). Follows helper function call chains
// transitively within the same file. ParsePackage does the same across all the
// files of a service package.
func ParseResourceFileStructured(src string, tfType string, resourceName string) (map[string][]ExtractedAction, error) {
	name := tfType + ".go"
	pkg, err := ParsePackage(map[string]string{name: src})
	if err != nil {
		return nil, err
	}
	actions, _ := pkg.ResourceActions(name, resourceName)
	return actions, nil
}

// Package is the parsed source of one provider service package. A resource's
// CRUD functions often call helpers that live in another file of the package
// (the S3 bucket read calls findBucketPolicy from bucket_policy.go), so the
// call graph is built over every file.
type Package struct {
	files map[string]*ast.File
	idx   *pkgIndex
}

// ParsePackage parses the given files (file name → Go source) as one package.
func ParsePackage(srcs map[string]string) (*Package, error) {
	fset := token.NewFileSet()
	files := make(map[string]*ast.File, len(srcs))
	for name, src := range srcs {
		f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse Go source: %w", err)
		}
		files[name] = f
	}
	return newPackage(files), nil
}

// newPackage indexes already parsed files as one package.
func newPackage(files map[string]*ast.File) *Package {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make([]*ast.File, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, files[name])
	}
	return &Package{files: files, idx: newPkgIndex(ordered)}
}

// ResourceActions returns the actions each CRUD operation of the resource in
// fileName needs, and the function bound to each operation the resource
// declares. An operation bound to something other than a package function,
// such as schema.NoopContext, maps to "": it is declared but makes no call.
//
// The bindings come from the schema.Resource literal (CreateWithoutTimeout:
// resourceBucketCreate). A file without one falls back to the naming
// convention resource<Name><Op>.
func (p *Package) ResourceActions(fileName, resourceName string) (map[string][]ExtractedAction, map[string]string) {
	funcs := p.resourceFuncs(fileName, resourceName)
	if funcs == nil {
		return nil, nil
	}
	return p.actionsFor(funcs), boundFuncs(funcs)
}

// resourceFuncs returns the functions bound to each operation of the resource
// in fileName, or nil when the package has no such file.
func (p *Package) resourceFuncs(fileName, resourceName string) map[string][]string {
	f := p.files[fileName]
	if f == nil {
		return nil
	}
	byName := operationsByName(f, resourceName)
	funcs := operationBindings(f)
	if len(funcs) == 0 {
		return byName
	}
	// An importer bound inline or not at all still has its function found
	// by name, as resource<Name>Import.
	if _, ok := funcs["import"]; !ok && len(byName["import"]) > 0 {
		funcs["import"] = byName["import"]
	}
	return funcs
}

// actionsFor resolves the actions of each operation's functions.
func (p *Package) actionsFor(funcs map[string][]string) map[string][]ExtractedAction {
	actions := make(map[string][]ExtractedAction)
	for op, fns := range funcs {
		var acts []ExtractedAction
		for _, fn := range fns {
			if fn != "" {
				acts = append(acts, p.idx.resolve(fn)...)
			}
		}
		if len(acts) > 0 {
			actions[op] = dedupActions(acts)
		}
	}
	return actions
}

// boundFuncs keeps the first function of each operation.
func boundFuncs(funcs map[string][]string) map[string]string {
	bound := make(map[string]string, len(funcs))
	for op, fns := range funcs {
		bound[op] = fns[0]
	}
	return bound
}

// schemaOperationKeys maps the schema.Resource fields that bind a CRUD
// function to the operation they bind.
var schemaOperationKeys = map[string]string{
	"Create": "create", "CreateContext": "create", "CreateWithoutTimeout": "create",
	"Read": "read", "ReadContext": "read", "ReadWithoutTimeout": "read",
	"Update": "update", "UpdateContext": "update", "UpdateWithoutTimeout": "update",
	"Delete": "delete", "DeleteContext": "delete", "DeleteWithoutTimeout": "delete",
}

// importerOperationKeys are the schema.ResourceImporter fields that bind the
// import function.
var importerOperationKeys = map[string]string{"State": "import", "StateContext": "import"}

// operationBindings reads the CRUD bindings from the first schema.Resource
// literal that declares each operation. A binding is a function name
// (resourceBucketCreate) or a call to a factory that returns the function
// (resourceResourcePolicyPut(cond)), in which case the factory's body, closure
// included, holds the calls. Any other binding (schema.NoopContext) maps to "".
func operationBindings(f *ast.File) map[string][]string {
	bound := make(map[string][]string)
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		keys := schemaOperationKeys
		if !isSchemaResourceType(lit.Type) {
			if !isSchemaType(lit.Type, "ResourceImporter") {
				return true
			}
			keys = importerOperationKeys
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			op, ok := keys[key.Name]
			if !ok || bound[op] != nil {
				continue
			}
			fn := ""
			switch v := kv.Value.(type) {
			case *ast.Ident:
				fn = v.Name
			case *ast.CallExpr:
				if ident, ok := v.Fun.(*ast.Ident); ok {
					fn = ident.Name
				}
			}
			bound[op] = []string{fn}
		}
		return true
	})
	return bound
}

// isSchemaResourceType reports whether a composite literal's type is
// schema.Resource.
func isSchemaResourceType(expr ast.Expr) bool {
	return isSchemaType(expr, "Resource")
}

// isSchemaType reports whether a composite literal's type is schema.<name>.
func isSchemaType(expr ast.Expr, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "schema"
}

// operationsByName maps the file's resource<...><Op> functions whose name
// contains resourceName to their operation.
func operationsByName(f *ast.File, resourceName string) map[string][]string {
	suffixes := []struct{ suffix, op string }{
		{"Create", "create"}, {"Read", "read"}, {"Update", "update"}, {"Delete", "delete"}, {"Import", "import"},
	}
	out := make(map[string][]string)
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil {
			continue
		}
		name := fd.Name.Name
		if !strings.HasPrefix(name, "resource") || !containsIgnoreCase(name, resourceName) {
			continue
		}
		for _, s := range suffixes {
			if strings.HasSuffix(name, s.suffix) {
				out[s.op] = append(out[s.op], name)
				break
			}
		}
	}
	return out
}

// servicePackagePrefix is the import path prefix of the provider's service
// packages. A call into another one, such as tfiam.FindRoleByName, is followed
// when that package is linked in.
const servicePackagePrefix = "github.com/hashicorp/terraform-provider-aws/internal/service/"

// pkgIndex holds every function of a package with its direct SDK calls and
// the functions it calls, and memoizes the transitive resolution. It keeps no
// syntax tree, so the indexes of every service package fit in memory at once.
type pkgIndex struct {
	funcs      map[string]bool // every function and method, by name
	plain      map[string]bool // the functions without a receiver
	direct     map[string][]ExtractedAction
	calls      map[string][]helperCall
	memo       map[string][]ExtractedAction
	inProgress map[string]bool

	// errResult names the functions whose last result is an error, so a
	// call site that drops that result drops the error.
	errResult map[string]bool

	// clients names the functions that obtain or receive an SDK client
	// themselves; reach memoizes reachesClient.
	clients map[string]bool
	reach   map[string]bool

	// others resolves calls into other service packages, by package
	// directory name. It is nil until the packages are linked.
	others map[string]*pkgIndex
}

func newPkgIndex(files []*ast.File) *pkgIndex {
	idx := &pkgIndex{
		funcs:      make(map[string]bool),
		plain:      make(map[string]bool),
		direct:     make(map[string][]ExtractedAction),
		calls:      make(map[string][]helperCall),
		memo:       make(map[string][]ExtractedAction),
		inProgress: make(map[string]bool),
		errResult:  make(map[string]bool),
		clients:    make(map[string]bool),
		reach:      make(map[string]bool),
	}

	// A plain function wins over a method of the same name, since call sites
	// name plain functions directly.
	type declared struct {
		fd      *ast.FuncDecl
		imports map[string]string
	}
	decls := make(map[string]declared)
	for _, f := range files {
		imports := serviceImports(f)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if prev, ok := decls[fd.Name.Name]; ok && (prev.fd.Recv == nil || fd.Recv != nil) {
				continue
			}
			decls[fd.Name.Name] = declared{fd, imports}
			idx.funcs[fd.Name.Name] = true
			idx.plain[fd.Name.Name] = fd.Recv == nil
			idx.errResult[fd.Name.Name] = lastResultIsError(fd.Type.Results)
		}
	}
	// exports.go publishes unexported helpers to other packages as
	// var FindRoleByName = findRoleByName; such an alias calls its target.
	for _, f := range files {
		for alias, target := range funcAliases(f) {
			if _, ok := decls[target]; ok && !idx.funcs[alias] {
				idx.funcs[alias] = true
				idx.plain[alias] = true
				idx.calls[alias] = []helperCall{{Name: target}}
				idx.errResult[alias] = idx.errResult[target]
			}
		}
	}
	for name, d := range decls {
		if calls := extractSDKCallsWithConnInfo(d.fd); len(calls) > 0 {
			idx.direct[name] = calls
		}
		if helpers := findHelperCalls(d.fd, idx, d.imports); len(helpers) > 0 {
			idx.calls[name] = helpers
		}
		if touchesClient(d.fd) {
			idx.clients[name] = true
		}
	}
	return idx
}

// touchesClient reports whether a function obtains an SDK client through an
// accessor such as meta.(*conns.AWSClient).S3Client(ctx), or receives one as
// a parameter.
func touchesClient(fd *ast.FuncDecl) bool {
	ctx := &walkContext{}
	bindConnParams(fd.Type, ctx)
	if len(ctx.conns) > 0 {
		return true
	}
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && clientAccessorService(call) != "" {
			found = true
		}
		return !found
	})
	return found
}

// reachesClient reports whether a function, or any function it calls, uses
// an SDK client. A function that never does, such as a delete that only logs
// that the resource cannot be destroyed, makes no AWS call by design.
func (idx *pkgIndex) reachesClient(name string) bool {
	if r, ok := idx.reach[name]; ok {
		return r
	}
	idx.reach[name] = false // a cycle adds nothing
	found := idx.clients[name]
	for _, hc := range idx.calls[name] {
		if found {
			break
		}
		target := idx
		if hc.Pkg != "" {
			if target = idx.others[hc.Pkg]; target == nil {
				continue
			}
		}
		found = target.reachesClient(hc.Name)
	}
	idx.reach[name] = found
	return found
}

// funcAliases returns the package-level variables a file sets to a plain
// identifier, alias → identifier, as in var FindRoleByName = findRoleByName.
func funcAliases(f *ast.File) map[string]string {
	out := make(map[string]string)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, name := range vs.Names {
				if ident, ok := vs.Values[i].(*ast.Ident); ok {
					out[name.Name] = ident.Name
				}
			}
		}
	}
	return out
}

// serviceImports maps the names a file imports provider service packages
// under to the packages' directory names, e.g. "tfiam" → "iam".
func serviceImports(f *ast.File) map[string]string {
	var out map[string]string
	for _, spec := range f.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if !strings.HasPrefix(path, servicePackagePrefix) {
			continue
		}
		dir := strings.TrimPrefix(path, servicePackagePrefix)
		name := dir
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if out == nil {
			out = make(map[string]string)
		}
		out[name] = dir
	}
	return out
}

// has reports whether the package declares a function or method with this
// name.
func (idx *pkgIndex) has(name string) bool {
	return idx.funcs[name]
}

// hasPlain reports whether the package declares a function without a receiver
// with this name, the only kind a bare identifier can name.
func (idx *pkgIndex) hasPlain(name string) bool {
	return idx.plain[name]
}

// resolve collects the SDK calls of a function and of every function it
// calls, transitively. When a call site sits inside a conditional block (if
// d.GetOk("attr")), the call-site condition is given to the callee's actions,
// unless an action already carries a more specific condition of its own. A
// recursive call contributes nothing beyond what the cycle already resolved.
func (idx *pkgIndex) resolve(name string) []ExtractedAction {
	if r, ok := idx.memo[name]; ok {
		return r
	}
	if idx.inProgress[name] {
		return nil
	}
	idx.inProgress[name] = true
	defer delete(idx.inProgress, name)

	resolved := append([]ExtractedAction(nil), idx.direct[name]...)
	for _, hc := range idx.calls[name] {
		target := idx
		if hc.Pkg != "" {
			if target = idx.others[hc.Pkg]; target == nil {
				continue
			}
		}
		// A failure the call site ignores makes every action reached only
		// through it best-effort.
		bestEffort := hc.BestEffort || hc.Discard == discardAlways ||
			(hc.Discard == discardIfError && target.errResult[hc.Name])
		for _, ea := range target.resolve(hc.Name) {
			if bestEffort {
				ea.BestEffort = true
			}
			if hc.CondReason != "" && ea.Condition == "" {
				ea.Conditional = true
				ea.Condition = hc.CondReason
				ea.ConditionKind = hc.CondKind
			}
			resolved = append(resolved, ea)
		}
	}
	resolved = dedupActions(resolved)
	idx.memo[name] = resolved
	return resolved
}

// walkContext is the state the traversal owns: how many conditional blocks
// deep the traversal is, the attribute name of the guard that put it there,
// and the client variables currently in scope. Observers read it to label
// what they find; the traversal restores it when a block ends.
type walkContext struct {
	condDepth  int           // how many conditional if-blocks deep we are
	condReason string        // attribute name from the outermost conditional guard
	condKind   ConditionKind // kind of that guard

	// conns maps each client variable in scope to the AWS service it talks
	// to, e.g. "conn" → "backup". It is copied on write, so restoring a saved
	// context also restores the scope.
	conns map[string]string

	// valueGuard is the attribute from the innermost value-comparison guard,
	// empty when the call is not under one.
	valueGuard string

	// bestEffort is true on a path that only runs after a call failed and
	// that returns the failure, such as the cleanup in
	// `if err != nil { deleteRole(...); return err }`.
	bestEffort bool

	// discarded is the call whose error the enclosing statement drops, and
	// discard says how; nil when the statement drops none.
	discarded *ast.CallExpr
	discard   discardKind

	// results are the result types of the function or closure being walked.
	results *ast.FieldList
}

// withDiscard walks call as a call whose error its statement drops.
func withDiscard(call *ast.CallExpr, kind discardKind, ctx *walkContext, obs walker) {
	prevCall, prevKind := ctx.discarded, ctx.discard
	ctx.discarded, ctx.discard = call, kind
	walkBody(call, ctx, obs)
	ctx.discarded, ctx.discard = prevCall, prevKind
}

// discardOf returns how the statement being walked drops call's error.
func (c *walkContext) discardOf(call *ast.CallExpr) discardKind {
	if call == c.discarded {
		return c.discard
	}
	return discardNone
}

// bindConn records that variable name holds a client for service.
func (c *walkContext) bindConn(name, service string) {
	m := make(map[string]string, len(c.conns)+1)
	for k, v := range c.conns {
		m[k] = v
	}
	m[name] = service
	c.conns = m
}

// walker observes one traversal of a function body. The traversal owns body
// walking, conditional tracking and client scope; an observer only decides
// what to do with the call expressions it is handed, and never sees the
// recursion itself.
type walker interface {
	// onCall is called for every call expression the traversal reaches.
	// Returning true means the observer consumed the node, and the traversal
	// will not descend into the call's function or arguments.
	onCall(call *ast.CallExpr, ctx *walkContext) bool
}

// funcRefObserver is a walker that also wants every identifier the traversal
// reaches as a value, such as a function assigned to a variable or passed as
// an argument rather than called.
type funcRefObserver interface {
	onFuncRef(ident *ast.Ident, ctx *walkContext)
}

// sdkCallObserver collects the AWS SDK calls the traversal reaches, each tagged
// with the conditional context it was reached under.
type sdkCallObserver struct {
	actions []ExtractedAction
}

func (o *sdkCallObserver) onCall(call *ast.CallExpr, ctx *walkContext) bool {
	// SDK API call: conn.MethodName(ctx, ...), or a paginator over one.
	action := extractCallAction(call, ctx.conns)
	if action == "" {
		return false
	}
	// An SDK client method always returns an error last, so a statement
	// that drops the last result drops the error.
	discarded := ctx.discardOf(call) != discardNone && isClientMethodCall(call, ctx.conns)
	o.actions = append(o.actions, ExtractedAction{
		Action:        action,
		Conditional:   ctx.condDepth > 0,
		Condition:     ctx.condReason,
		ConditionKind: ctx.condKind,
		ValueGuarded:  ctx.valueGuard != "",
		BestEffort:    ctx.bestEffort || discarded,
	})
	return true
}

// walkBody is the single AST traversal of this package. It walks every
// statement and expression, function literals included: the provider makes
// most of its retried calls inside the closure it passes to tfresource.Retry*.
// It tracks conditional context from if-statements that gate on d.GetOk(),
// d.Get(), or d.HasChange(), binds client variables as they are assigned, and
// reports call expressions to obs.
func walkBody(node ast.Node, ctx *walkContext, obs walker) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.IfStmt:
		// Save the whole context so nested guards and nested client
		// assignments cannot leak out of the block.
		saved := *ctx

		// The init statement and the condition run whether or not the body
		// does, so they are walked in the enclosing context. A call in the
		// init whose error the if-statement only uses to skip the body, or
		// swallows, is dropped.
		if call := initErrorDropped(n, ctx.results); call != nil {
			walkAssign(n.Init.(*ast.AssignStmt), call, discardAlways, ctx, obs)
		} else {
			walkBody(n.Init, ctx, obs)
		}
		walkBody(n.Cond, ctx, obs)

		// A guard here is one of three kinds: presence (d.GetOk/d.Get), change
		// (d.HasChange), or a value comparison. The outermost guard wins as the
		// reason and kind, except under a value guard: its default already
		// satisfies the guard, so a nested guard decides the call instead.
		guard := extractConditionGuard(n)
		valueAttr := extractValueGuardAttribute(n)
		if guard.Attribute != "" || valueAttr != "" {
			ctx.condDepth++
			if ctx.condReason == "" || ctx.valueGuard != "" {
				if valueAttr != "" {
					// A value guard is a presence guard whose value is also
					// tested, so presence is its kind and ValueGuarded records
					// that the provider's default satisfies it on its own.
					ctx.condReason = valueAttr
					ctx.condKind = ConditionPresence
					ctx.valueGuard = valueAttr
				} else {
					ctx.condReason = guard.Attribute
					ctx.condKind = guard.Kind
					ctx.valueGuard = ""
				}
			}
		}

		// The body is walked in the guard's conditional context. The body of
		// a branch that handles a failed call and returns the failure runs
		// only when the apply is already failing.
		if isFailureBranch(n, ctx.results) {
			ctx.bestEffort = true
		}
		walkBody(n.Body, ctx, obs)
		ctx.bestEffort = saved.bestEffort

		// The else branch (including an else-if chain) is walked in the same
		// context, except after a d.HasChange guard: that branch runs when the
		// attribute did NOT change, so inheriting the change gate would drop the
		// call exactly when it runs. It takes the context from before the guard.
		if guard.Kind == ConditionChange {
			*ctx = saved
		}
		walkBody(n.Else, ctx, obs)

		// Restore conditional depth/reason and connection scope.
		*ctx = saved

	case *ast.AssignStmt:
		// `x, _ := f()` drops f's last result.
		if call := blankLastResult(n); call != nil {
			walkAssign(n, call, discardIfError, ctx, obs)
		} else {
			walkAssign(n, nil, discardNone, ctx, obs)
		}

	case *ast.ExprStmt:
		// A call made as a statement drops every result it returns.
		if call, ok := unwrapExpr(n.X).(*ast.CallExpr); ok {
			withDiscard(call, discardIfError, ctx, obs)
			return
		}
		walkBody(n.X, ctx, obs)

	case *ast.BlockStmt:
		walkStmts(n.List, ctx, obs)

	case *ast.CaseClause:
		for _, expr := range n.List {
			walkBody(expr, ctx, obs)
		}
		walkStmts(n.Body, ctx, obs)

	case *ast.CommClause:
		walkBody(n.Comm, ctx, obs)
		walkStmts(n.Body, ctx, obs)

	case *ast.CallExpr:
		if obs.onCall(n, ctx) {
			return
		}
		// A function called by name was reported by onCall, so only a
		// computed callee, such as conn.Foo(ctx).Bar, is walked.
		if _, named := unwrapIndex(n.Fun).(*ast.Ident); !named {
			walkBody(n.Fun, ctx, obs)
		}
		for _, arg := range n.Args {
			walkBody(arg, ctx, obs)
		}

	case *ast.Ident:
		if o, ok := obs.(funcRefObserver); ok {
			o.onFuncRef(n, ctx)
		}

	case *ast.SelectorExpr:
		// The selected name is a field or method, and a bare operand is a
		// variable or an imported package, so neither refers to a package
		// function. Only a computed operand is walked.
		if _, bare := n.X.(*ast.Ident); !bare {
			walkBody(n.X, ctx, obs)
		}

	case *ast.KeyValueExpr:
		// A composite literal key names a field, not a value.
		walkBody(n.Value, ctx, obs)

	case *ast.CompositeLit:
		// A nested schema.Resource literal declares a resource rather than
		// running it: its CRUD bindings are references to functions the
		// literal does not call.
		if isSchemaResourceType(n.Type) {
			return
		}
		for _, elt := range n.Elts {
			walkBody(elt, ctx, obs)
		}

	case *ast.FuncLit:
		// A closure runs in the context it is written in, but client
		// variables it binds stay inside it.
		saved := *ctx
		bindConnParams(n.Type, ctx)
		ctx.results = n.Type.Results
		walkBody(n.Body, ctx, obs)
		*ctx = saved

	default:
		// Every other node: walk its direct children in order.
		ast.Inspect(node, func(child ast.Node) bool {
			if child == node {
				return true
			}
			if child != nil {
				walkBody(child, ctx, obs)
			}
			return false
		})
	}
}

// walkAssign walks an assignment, binding the client it assigns, if any.
// When call is not nil, it is the right-hand call whose error the statement
// drops, the way kind says.
func walkAssign(n *ast.AssignStmt, call *ast.CallExpr, kind discardKind, ctx *walkContext, obs walker) {
	// Install a new connection scope, as in
	// conn := meta.(*conns.AWSClient).BackupClient(ctx).
	if svc, conn := findClientAssignment(n); svc != "" {
		ctx.bindConn(conn, svc)
	}
	for _, expr := range n.Lhs {
		walkBody(expr, ctx, obs)
	}
	for _, expr := range n.Rhs {
		if c, ok := unwrapExpr(expr).(*ast.CallExpr); ok && c == call {
			withDiscard(c, kind, ctx, obs)
			continue
		}
		walkBody(expr, ctx, obs)
	}
}

// walkStmts walks a statement list. An assignment that binds a call's error
// and is followed by a guard that swallows it, as in
//
//	dk, err := kms.FindDefaultKeyARNForService(...)
//	if err != nil {
//		return sseList
//	}
//
// drops that error.
func walkStmts(list []ast.Stmt, ctx *walkContext, obs walker) {
	for i, stmt := range list {
		assign, ok := stmt.(*ast.AssignStmt)
		if ok && i+1 < len(list) {
			if call, errName := errorBinding(assign); call != nil {
				if next, ok := list[i+1].(*ast.IfStmt); ok && next.Init == nil && swallowsError(next, errName, ctx.results) {
					walkAssign(assign, call, discardAlways, ctx, obs)
					continue
				}
			}
		}
		walkBody(stmt, ctx, obs)
	}
}

// errorBinding returns the call of an assignment such as `x, err := f()` and
// the name of the error variable it binds last, or nil when the assignment
// binds no error from a single call.
func errorBinding(assign *ast.AssignStmt) (*ast.CallExpr, string) {
	if len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
		return nil, ""
	}
	call, ok := unwrapExpr(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return nil, ""
	}
	last, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
	if !ok || !isErrorName(last.Name) {
		return nil, ""
	}
	return call, last.Name
}

// isErrorName reports whether a variable name reads like an error: err,
// derr, putErr.
func isErrorName(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), "err")
}

// blankLastResult returns the call of an assignment that discards the call's
// last result, as in `x, _ := f()` or `_ = f()`, or nil.
func blankLastResult(assign *ast.AssignStmt) *ast.CallExpr {
	if len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
		return nil
	}
	call, ok := unwrapExpr(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return nil
	}
	if last, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident); !ok || last.Name != "_" {
		return nil
	}
	return call
}

// initErrorDropped returns the call in an if-statement's init whose error the
// statement drops, or nil. It drops the error when it only tests it to skip
// the body, as in `if v, err := f(); err == nil { ... }` with no else branch,
// or when the body swallows it.
func initErrorDropped(n *ast.IfStmt, results *ast.FieldList) *ast.CallExpr {
	assign, ok := n.Init.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE {
		return nil
	}
	call, errName := errorBinding(assign)
	if call == nil {
		return nil
	}
	if n.Else == nil && condTestsNoError(n.Cond, errName) {
		return call
	}
	if swallowsError(n, errName, results) {
		return call
	}
	return nil
}

// condTestsNoError reports whether cond is `err == nil`, alone or as an
// operand of &&.
func condTestsNoError(cond ast.Expr, errName string) bool {
	bin, ok := unwrapExpr(cond).(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op == token.LAND {
		return condTestsNoError(bin.X, errName) || condTestsNoError(bin.Y, errName)
	}
	return bin.Op == token.EQL && comparesToNil(bin, errName)
}

// testsError returns the name of the error variable cond tests in the form
// `err != nil`, or "".
func testsError(cond ast.Expr) string {
	bin, ok := unwrapExpr(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return ""
	}
	for _, side := range []ast.Expr{bin.X, bin.Y} {
		if id, ok := side.(*ast.Ident); ok && id.Name != "nil" && isErrorName(id.Name) && comparesToNil(bin, id.Name) {
			return id.Name
		}
	}
	return ""
}

// comparesToNil reports whether a comparison sets name against nil.
func comparesToNil(bin *ast.BinaryExpr, name string) bool {
	isIdent := func(e ast.Expr, n string) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == n
	}
	return (isIdent(bin.X, name) && isIdent(bin.Y, "nil")) || (isIdent(bin.X, "nil") && isIdent(bin.Y, name))
}

// swallowsError reports whether an if-statement `if err != nil { ... }`
// handles the error by leaving without it: the body never names the error
// and ends in a return, continue or break, and every return in it reports no
// failure (see successReturn). The call that set the error then cannot fail
// the apply.
func swallowsError(n *ast.IfStmt, errName string, results *ast.FieldList) bool {
	if n.Else != nil || errName == "" || testsError(n.Cond) != errName {
		return false
	}
	if len(n.Body.List) == 0 || mentions(n.Body, errName) {
		return false
	}
	switch last := n.Body.List[len(n.Body.List)-1].(type) {
	case *ast.ReturnStmt:
	case *ast.BranchStmt:
		if last.Tok == token.GOTO || last.Tok == token.FALLTHROUGH {
			return false
		}
	default:
		return false
	}
	ok := true
	inspectSkippingFuncLits(n.Body, func(node ast.Node) {
		if ret, isRet := node.(*ast.ReturnStmt); isRet && !successReturn(ret, results) {
			ok = false
		}
	})
	return ok
}

// isFailureBranch reports whether an if-statement is a branch that handles a
// failed call and returns the failure, as in
//
//	if err := addRoleInlinePolicies(...); err != nil {
//		deleteRole(...)
//		return sdkdiag.AppendErrorf(diags, "...: %s", err)
//	}
//
// The body ends in a return that reports a failure, and it does not test the
// error further: a body that tells errors apart, such as one that creates
// what a find did not find, can lead to a successful apply.
func isFailureBranch(n *ast.IfStmt, results *ast.FieldList) bool {
	errName := testsError(n.Cond)
	if errName == "" || len(n.Body.List) == 0 {
		return false
	}
	ret, ok := n.Body.List[len(n.Body.List)-1].(*ast.ReturnStmt)
	if !ok || successReturn(ret, results) {
		return false
	}
	tests := false
	inspectSkippingFuncLits(n.Body, func(node ast.Node) {
		if inner, ok := node.(*ast.IfStmt); ok && (mentions(inner.Cond, errName) || mentions(inner.Init, errName)) {
			tests = true
		}
	})
	return !tests
}

// successReturn reports whether a return statement reports no failure: it
// returns nil in every error position, and a plain variable (diags, not a
// call that appends to it) in every diag.Diagnostics position. A bare return
// counts only when the function has no results.
func successReturn(ret *ast.ReturnStmt, results *ast.FieldList) bool {
	types := resultTypes(results)
	if len(ret.Results) == 0 {
		return len(types) == 0
	}
	if len(ret.Results) != len(types) {
		return false
	}
	for i, t := range types {
		switch {
		case isErrorType(t):
			if id, ok := ret.Results[i].(*ast.Ident); !ok || id.Name != "nil" {
				return false
			}
		case isDiagnosticsType(t):
			if _, ok := ret.Results[i].(*ast.Ident); !ok {
				return false
			}
		}
	}
	return true
}

// resultTypes lists a function's result types, one per result.
func resultTypes(results *ast.FieldList) []ast.Expr {
	if results == nil {
		return nil
	}
	var out []ast.Expr
	for _, f := range results.List {
		n := len(f.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			out = append(out, f.Type)
		}
	}
	return out
}

// lastResultIsError reports whether a function's last result is an error.
func lastResultIsError(results *ast.FieldList) bool {
	types := resultTypes(results)
	return len(types) > 0 && isErrorType(types[len(types)-1])
}

func isErrorType(t ast.Expr) bool {
	id, ok := t.(*ast.Ident)
	return ok && id.Name == "error"
}

func isDiagnosticsType(t ast.Expr) bool {
	sel, ok := t.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Diagnostics"
}

// mentions reports whether node names the identifier name.
func mentions(node ast.Node, name string) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// inspectSkippingFuncLits calls f for every node under root, except the
// bodies of closures, whose statements belong to another function.
func inspectSkippingFuncLits(root ast.Node, f func(ast.Node)) {
	ast.Inspect(root, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if n != nil {
			f(n)
		}
		return true
	})
}

// isClientMethodCall reports whether a call is a method of an SDK client,
// such as conn.DeleteRole(ctx, input), which returns an error last.
func isClientMethodCall(call *ast.CallExpr, conns map[string]string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && clientService(sel.X, conns) != ""
}

// condGuard is a gating attribute found on an if-statement, with the kind of
// gate the provider applies to it.
type condGuard struct {
	Attribute string
	Kind      ConditionKind
}

// extractConditionGuard checks if an if-statement's condition involves a
// d.GetOk("attr"), d.Get("attr"), or d.HasChange("attr") guard and returns the
// gating attribute together with the kind of gate.
func extractConditionGuard(ifStmt *ast.IfStmt) condGuard {
	// Check Init statement: if v, ok := d.GetOk("attr"); ok { ...
	if ifStmt.Init != nil {
		if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok {
			for _, rhs := range assign.Rhs {
				guard := extractGuardAttribute(rhs)
				if guard.Attribute == "" {
					continue
				}
				// A change guard bound in the init statement gates the body
				// only when the condition is the bare variable it binds, as in
				// `if changed := d.HasChange("x"); changed`. A negated or
				// compound condition runs the body when the attribute did NOT
				// change, so it is no change gate.
				if guard.Kind == ConditionChange && !condIsBoundVar(ifStmt.Cond, assign) {
					return condGuard{}
				}
				return guard
			}
		}
	}

	// Check condition expression: d.Get("attr").(bool)
	// The condition may be wrapped in a type assertion or a negation.
	cond := ifStmt.Cond
	if ta, ok := cond.(*ast.TypeAssertExpr); ok {
		cond = ta.X
	}
	return extractGuardAttribute(cond)
}

// condIsBoundVar reports whether cond is a bare identifier that the assignment
// binds, as `changed` in `changed := d.HasChange("x")`.
func condIsBoundVar(cond ast.Expr, assign *ast.AssignStmt) bool {
	id, ok := unwrapExpr(cond).(*ast.Ident)
	if !ok {
		return false
	}
	for _, lhs := range assign.Lhs {
		if l, ok := lhs.(*ast.Ident); ok && l.Name == id.Name && l.Name != "_" {
			return true
		}
	}
	return false
}

// extractGuardAttribute checks if an expression is d.GetOk("attr"),
// d.Get("attr"), or d.HasChange("attr") on the resource data and returns the
// attribute name with the kind of gate. Parenthesised and negated expressions
// are unwrapped, so `!d.HasChange("attr")` reads the same as the plain form.
func extractGuardAttribute(expr ast.Expr) condGuard {
	expr = unwrapExpr(expr)

	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return condGuard{}
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return condGuard{}
	}

	// Must be a method call on something named "d"
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "d" {
		return condGuard{}
	}

	// Map the guard method to the kind of gate it applies. Only the
	// single-attribute forms count: d.HasChanges spans several attributes and
	// d.HasChangesExcept is a filter, so neither names one gating attribute.
	var kind ConditionKind
	switch sel.Sel.Name {
	case "GetOk", "Get":
		kind = ConditionPresence
	case "HasChange":
		kind = ConditionChange
	default:
		return condGuard{}
	}

	// First argument must be a string literal
	if len(call.Args) < 1 {
		return condGuard{}
	}

	bl, ok := call.Args[0].(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return condGuard{}
	}

	// Return the attribute name without quotes
	return condGuard{Attribute: strings.Trim(bl.Value, "\""), Kind: kind}
}

// unwrapExpr strips parentheses from an expression, so a guard written as
// `(d.HasChange("attr"))` is recognized. It does not strip a negation: the body
// of `if !d.HasChange("attr")` runs when the attribute did NOT change, so
// reading it as a change gate would drop the call exactly when it runs. A
// negated guard gates nothing the validator can evaluate, and its body stays
// unconditional, which keeps the permission in the report.
func unwrapExpr(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// extractValueGuardAttribute returns the attribute a guard tests for emptiness,
// e.g. `ok && v.(*schema.Set).Len() > 0` on a d.GetOk("version_stages") call.
// The call it guards only runs when the author set the attribute, because the
// provider's default alone leaves the value non-zero.
//
// Only emptiness tests count. A comparison on a scalar (`d.Get("x") != ""`,
// `n > 0`) reads a value the default usually satisfies, so treating those as
// needing configuration would drop permissions the provider really needs.
// Returns "" when the guard tests presence alone, or compares something the
// parser cannot tie back to an attribute.
func extractValueGuardAttribute(ifStmt *ast.IfStmt) string {
	if ifStmt == nil {
		return ""
	}

	bindings := localAttrBindings(ifStmt.Init)

	var attr string
	found := false
	scan := func(node ast.Node) {
		if found || node == nil {
			return
		}
		ast.Inspect(node, func(n ast.Node) bool {
			if found {
				return false
			}
			bin, ok := n.(*ast.BinaryExpr)
			if !ok || !isEmptinessTest(bin) {
				return true
			}
			if a := attributeUnderLengthCall(bin, bindings); a != "" {
				attr, found = a, true
				return false
			}
			return true
		})
	}

	scan(ifStmt.Init)
	scan(ifStmt.Cond)
	return attr
}

// isEmptinessTest reports whether a binary expression compares a length
// against a bound that holds exactly when the collection is non-empty
// (`> 0`, `!= 0`, `>= 1`, or the mirrored forms).
func isEmptinessTest(bin *ast.BinaryExpr) bool {
	left, right := isLengthCall(bin.X), isLengthCall(bin.Y)
	if (left == nil) == (right == nil) {
		return false
	}

	// Normalise to `length OP literal`, mirroring the operator when the
	// length sits on the right.
	op, other := bin.Op, bin.Y
	if left == nil {
		other = bin.X
		switch op {
		case token.LSS:
			op = token.GTR
		case token.LEQ:
			op = token.GEQ
		case token.GTR:
			op = token.LSS
		case token.GEQ:
			op = token.LEQ
		}
	}
	lit, ok := other.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}

	// Only the forms that hold exactly when the collection is non-empty.
	switch {
	case lit.Value == "0" && (op == token.GTR || op == token.NEQ):
		return true
	case lit.Value == "1" && op == token.GEQ:
		return true
	}
	return false
}

// attributeUnderLengthCall returns the attribute whose collection size an
// emptiness test compares against zero.
func attributeUnderLengthCall(bin *ast.BinaryExpr, bindings map[string]string) string {
	if side := isLengthCall(bin.X); side != nil {
		return attributeUnder(side, bindings)
	}
	return attributeUnder(isLengthCall(bin.Y), bindings)
}

// isLengthCall reports whether an expression reads a collection's size
// (v.Len(), v.Length(), len(v)) and returns the collection expression itself,
// or "" when the expression reads no size.
func isLengthCall(expr ast.Node) ast.Expr {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil
	}

	// len(v) — the builtin.
	if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "len" {
		if len(call.Args) != 1 {
			return nil
		}
		return call.Args[0]
	}

	// v.Len() / v.Length() — a method on the collection.
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Len" && sel.Sel.Name != "Length") {
		return nil
	}
	return sel.X
}

// attributeUnder returns the attribute a collection expression reads, either
// through a d.Get/d.GetOk call or through a local bound to one. Returns "" when
// the collection has no traceable attribute read.
func attributeUnder(collection ast.Expr, bindings map[string]string) string {
	if collection == nil {
		return ""
	}
	var attr string
	ast.Inspect(collection, func(n ast.Node) bool {
		if attr != "" {
			return false
		}
		if a := extractGetOkAttribute(n); a != "" {
			attr = a
			return false
		}
		if ident, ok := n.(*ast.Ident); ok {
			if a, bound := bindings[ident.Name]; bound {
				attr = a
				return false
			}
		}
		return true
	})
	return attr
}

// localAttrBindings maps the locals an if-statement's init assigns from a
// d.Get/d.GetOk call to their attribute names, e.g. the "v" of
// `if v, ok := d.GetOk("version_stages"); ok`.
func localAttrBindings(init ast.Stmt) map[string]string {
	bindings := make(map[string]string)
	assign, ok := init.(*ast.AssignStmt)
	if !ok {
		return bindings
	}
	for i, rhs := range assign.Rhs {
		attr := extractGetOkAttribute(rhs)
		if attr == "" || i >= len(assign.Lhs) {
			continue
		}
		if ident, ok := assign.Lhs[i].(*ast.Ident); ok {
			bindings[ident.Name] = attr
		}
	}
	return bindings
}

// findClientAssignment detects a client connection assignment like:
//
//	conn := meta.(*conns.AWSClient).BackupClient(ctx)
//
// Returns (service, connVar) where service is "backup" and connVar is "conn".
func findClientAssignment(stmt *ast.AssignStmt) (string, string) {
	if len(stmt.Lhs) != 1 || len(stmt.Rhs) != 1 || stmt.Tok != token.DEFINE {
		return "", ""
	}
	lhsIdent, ok := stmt.Lhs[0].(*ast.Ident)
	if !ok {
		return "", ""
	}
	service := clientAccessorService(stmt.Rhs[0])
	if service == "" {
		return "", ""
	}
	return service, lhsIdent.Name
}

// clientAccessorService returns the service of a client accessor call such as
// meta.(*conns.AWSClient).S3Client(ctx) or awsClient.EC2Client(ctx), or "" when
// the expression is not one.
func clientAccessorService(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if !isClientAccessor(sel.Sel.Name) {
		return ""
	}
	return clientMethodToService(sel.Sel.Name)
}

// isClientAccessor reports whether a method name reads like an AWSClient
// accessor for one service's SDK client, e.g. "BackupClient".
func isClientAccessor(name string) bool {
	if !strings.HasSuffix(name, "Client") || len(name) == len("Client") {
		return false
	}
	if name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	// A constructor such as s3.NewPresignClient builds a client from
	// another rather than reading one off the AWSClient.
	if strings.HasPrefix(name, "New") || name == "HTTPClient" {
		return false
	}
	return true
}

// clientService returns the service an expression's client talks to: a
// client variable in scope, or an inline client accessor call.
func clientService(expr ast.Expr, conns map[string]string) string {
	if ident, ok := expr.(*ast.Ident); ok {
		return conns[ident.Name]
	}
	return clientAccessorService(expr)
}

// extractCallAction checks if a call expression is an AWS SDK API call on a
// client, e.g., conn.CreateBackupVault(ctx, input), or builds a paginator over
// one, e.g., cloudwatchlogs.NewDescribeLogGroupsPaginator(conn, input).
// Returns the IAM action string (e.g., "backup:CreateBackupVault") or "".
func extractCallAction(call *ast.CallExpr, conns map[string]string) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}

	method := sel.Sel.Name // e.g., "CreateBackupVault"
	if service := clientService(sel.X, conns); service != "" {
		if isAWSMethod(method) {
			return sdKMethodToIAMAction(method, service)
		}
		return ""
	}

	// A paginator calls the operation it is named after on every page.
	if op := paginatorOperation(method); op != "" && len(call.Args) > 0 {
		if service := clientService(call.Args[0], conns); service != "" {
			return sdKMethodToIAMAction(op, service)
		}
	}

	// The S3 feature manager makes S3 calls with the client it is handed.
	if op, ok := s3ManagerCalls[method]; ok {
		for _, arg := range call.Args {
			if clientService(arg, conns) == "s3" {
				return sdKMethodToIAMAction(op, "s3")
			}
		}
	}
	return ""
}

// s3ManagerCalls maps the S3 feature manager functions
// (github.com/aws/aws-sdk-go-v2/feature/s3/manager) to the S3 operation they
// make. An upload needs s3:PutObject whether it goes in one part or many.
var s3ManagerCalls = map[string]string{
	"NewUploader":     "PutObject",
	"NewDownloader":   "GetObject",
	"GetBucketRegion": "HeadBucket",
}

// paginatorOperation returns the operation a paginator constructor pages
// through, "DescribeLogGroups" for "NewDescribeLogGroupsPaginator", or "".
func paginatorOperation(name string) string {
	if !strings.HasPrefix(name, "New") || !strings.HasSuffix(name, "Paginator") {
		return ""
	}
	op := strings.TrimSuffix(strings.TrimPrefix(name, "New"), "Paginator")
	if !isAWSMethod(op) {
		return ""
	}
	return op
}

// isAWSMethod checks if a method name looks like an AWS SDK API method
// (PascalCase, not something like Error, HandleError, etc.).
func isAWSMethod(name string) bool {
	if len(name) == 0 {
		return false
	}
	// Must start with uppercase
	if name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	// Options returns the client's configuration; it calls no API.
	return name != "Options"
}

// sdKMethodToIAMAction converts an AWS SDK method name and service to an IAM
// action string. Convention: backup + CreateBackupVault -> backup:CreateBackupVault.
// A method that IAM does not know as an action is renamed to the action the
// AWS service reference says it needs, e.g. s3 HeadObject -> s3:GetObject.
func sdKMethodToIAMAction(method string, service string) string {
	if canonical := normalizeSDKMethod(service, method); canonical != "" {
		return service + ":" + canonical
	}
	return service + ":" + method
}

// normalizeSDKMethod returns the IAM action an SDK method needs when IAM spells
// it differently, or "" when the method name is the action.
func normalizeSDKMethod(service, method string) string {
	return sdkOperationActions[service][method]
}

// clientMethodToService returns the IAM service prefix of the client an
// AWSClient accessor returns ("ELBV2Client" -> "elasticloadbalancing"). An
// accessor the provider does not declare falls back to its name less Client,
// read as an SDK package name.
func clientMethodToService(clientMethod string) string {
	if svc, ok := clientAccessorIAMPrefixes[clientMethod]; ok {
		return svc
	}
	base := strings.TrimSuffix(clientMethod, "Client")
	base = strings.TrimSuffix(base, "Regional")
	base = strings.TrimSuffix(base, "Global")
	base = strings.ToLower(base)
	if svc := sdkPackageToIAMService(base); svc != "" {
		return svc
	}
	return base
}

// containsIgnoreCase reports whether s contains substr, case-insensitively.
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && len(substr) > 0 &&
		strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// dedup removes duplicate strings while preserving order.
func dedup(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// dedupActions removes duplicate ExtractedActions (by Action string) while
// preserving order. When deduplicating, marks the action as unconditional
// if any occurrence was unconditional (union).
func dedupActions(actions []ExtractedAction) []ExtractedAction {
	seen := make(map[string]bool)
	var out []ExtractedAction
	for _, ea := range actions {
		if !seen[ea.Action] {
			seen[ea.Action] = true
			out = append(out, ea)
		} else {
			// If a duplicate exists and this one is unconditional, upgrade
			for i := range out {
				if out[i].Action != ea.Action {
					continue
				}
				// A path whose failure counts decides the action: its gates
				// replace those of best-effort paths, which a best-effort
				// path never loosens.
				if out[i].BestEffort != ea.BestEffort {
					if out[i].BestEffort {
						out[i] = ea
					}
					continue
				}
				// A path that is not value-guarded needs the attribute's
				// configuration, so the default no longer covers the action.
				if !ea.ValueGuarded {
					out[i].ValueGuarded = false
				}
				if !ea.Conditional {
					out[i].Conditional = false
					out[i].Condition = ""
					out[i].ConditionKind = ""
				}
			}
		}
	}
	return out
}

// extractSDKCallsWithConnInfo walks the body of a function and extracts all AWS
// SDK API calls. Clients come from client assignments
// (conn := meta.(*conns.AWSClient).XxxClient(ctx)), from typed parameters
// (func helper(ctx, conn *iam.Client)), and from inline accessor calls.
func extractSDKCallsWithConnInfo(fd *ast.FuncDecl) []ExtractedAction {
	if fd.Body == nil {
		return nil
	}
	ctx := &walkContext{results: fd.Type.Results}
	bindConnParams(fd.Type, ctx)
	obs := &sdkCallObserver{}
	walkBody(fd.Body, ctx, obs)
	return dedupActions(obs.actions)
}

// bindConnParams binds every parameter typed as an SDK client, such as
// conn *iam.Client or svc *backup.Client.
func bindConnParams(ft *ast.FuncType, ctx *walkContext) {
	if ft == nil || ft.Params == nil {
		return
	}
	for _, param := range ft.Params.List {
		svc := paramTypeToService(param.Type)
		if svc == "" {
			continue
		}
		for _, name := range param.Names {
			ctx.bindConn(name.Name, svc)
		}
	}
}

// paramTypeToService returns the IAM service prefix of a parameter typed as an
// SDK client: *iam.Client -> "iam", *cloudwatchlogs.Client -> "logs". Any type
// other than a pointer to a package's Client yields "".
func paramTypeToService(expr ast.Expr) string {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return ""
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Client" {
		return ""
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	// ident.Name is the package, or the name the file imports it under.
	if svc := sdkPackageToIAMService(ident.Name); svc != "" {
		return svc
	}
	return ident.Name
}

// sdkPackageToIAMService maps an AWS SDK Go package name, or an alias the
// provider imports one under, to its IAM service prefix
// ("elasticloadbalancingv2" -> "elasticloadbalancing"). It returns "" for a
// package the generated table does not know.
func sdkPackageToIAMService(pkg string) string {
	return sdkPackageIAMPrefixes[pkg]
}

// findHelperCalls finds the calls a function body makes to other functions of
// the package, or to functions of the service packages in imports, tracking
// the conditional context at each call site.
func findHelperCalls(fd *ast.FuncDecl, idx *pkgIndex, imports map[string]string) []helperCall {
	if fd.Body == nil {
		return nil
	}
	ctx := &walkContext{results: fd.Type.Results}
	bindConnParams(fd.Type, ctx)
	obs := &helperCallObserver{idx: idx, imports: imports}
	walkBody(fd.Body, ctx, obs)
	return obs.helpers
}

// helperCallObserver collects the calls to functions of the same package, each
// tagged with the conditional reason in force at the call site (e.g.
// removeSecretReplicas(ctx, conn, id) reached from inside
// if _, ok := d.GetOk("replica"); ok).
type helperCallObserver struct {
	idx     *pkgIndex
	imports map[string]string // import name → service package directory
	helpers []helperCall
}

// onCall records a helper call but never consumes it: its arguments may hold
// further helper calls or closures that make some.
func (o *helperCallObserver) onCall(call *ast.CallExpr, ctx *walkContext) bool {
	if pkg, name := o.callee(call, ctx); name != "" {
		o.record(pkg, name, ctx.discardOf(call), ctx)
	}
	return false
}

// onFuncRef records a package function used as a value, as in
// routeFinder = findRouteByIPv4Destination: the code calls it later.
func (o *helperCallObserver) onFuncRef(ident *ast.Ident, ctx *walkContext) {
	if o.idx.hasPlain(ident.Name) {
		o.record("", ident.Name, discardNone, ctx)
	}
}

func (o *helperCallObserver) record(pkg, name string, discard discardKind, ctx *walkContext) {
	o.helpers = append(o.helpers, helperCall{
		Pkg: pkg, Name: name,
		CondReason: ctx.condReason, CondKind: ctx.condKind,
		BestEffort: ctx.bestEffort, Discard: discard,
	})
}

// callee returns the function a call invokes, with the service package it
// lives in ("" for this one), or "" for the name. A call by plain name
// (findBucket(...), or a generic findX[T](...)) counts when the package
// declares it, and so does an exported function of an imported service
// package (tfiam.FindRoleByName(...)). Another selector call (r.findX(...))
// counts only when it hands over an SDK client, since the selector may name
// some other package.
func (o *helperCallObserver) callee(call *ast.CallExpr, ctx *walkContext) (string, string) {
	switch fn := unwrapIndex(call.Fun).(type) {
	case *ast.Ident:
		if o.idx.hasPlain(fn.Name) {
			return "", fn.Name
		}
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok {
			if pkg, ok := o.imports[x.Name]; ok {
				return pkg, fn.Sel.Name
			}
		}
		if !o.idx.has(fn.Sel.Name) || clientService(fn.X, ctx.conns) != "" {
			return "", ""
		}
		for _, arg := range call.Args {
			if clientService(arg, ctx.conns) != "" {
				return "", fn.Sel.Name
			}
		}
	}
	return "", ""
}

// unwrapIndex strips the type arguments of a generic function reference, so
// findX[T] reads as findX.
func unwrapIndex(expr ast.Expr) ast.Expr {
	switch e := expr.(type) {
	case *ast.IndexExpr:
		return e.X
	case *ast.IndexListExpr:
		return e.X
	}
	return expr
}

// extractGetOkAttribute checks if an expression is d.GetOk("attr") or
// d.Get("attr") and returns the attribute name. It is the presence-only reader
// the value-guard helpers use; extractGuardAttribute performs the same
// inspection but also reports which kind of gate the call applies.
func extractGetOkAttribute(expr ast.Node) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}

	// Must be a method call on something named "d"
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "d" {
		return ""
	}

	// Method must be GetOk or Get
	if sel.Sel.Name != "GetOk" && sel.Sel.Name != "Get" {
		return ""
	}

	// First argument must be a string literal
	if len(call.Args) < 1 {
		return ""
	}

	bl, ok := call.Args[0].(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return ""
	}

	return strings.Trim(bl.Value, "\"")
}
