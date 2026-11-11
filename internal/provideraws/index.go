package provideraws

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

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
	direct     map[string][]iam.Requirement
	calls      map[string][]helperCall
	memo       map[string][]iam.Requirement
	inProgress map[string]bool

	// errResult names the functions whose last result is an error, so a
	// call site that drops that result drops the error.
	errResult map[string]bool

	// clients names the functions that obtain or receive an SDK client
	// themselves; reach memoizes reachesClient.
	clients map[string]bool
	reach   map[string]bool

	// alwaysCalls maps each function to the package functions its body calls
	// on every run: from a top-level statement, not under a condition, a
	// loop or a closure. See setsTagsOut.
	alwaysCalls map[string][]string

	// others resolves calls into other service packages, by package
	// directory name. It is nil until the packages are linked.
	others map[string]*pkgIndex

	// models maps the package's tfsdk-tagged struct types to the attribute
	// each field holds, for the guards of framework resources.
	models modelTable

	// embeds maps each struct type to the struct types of the package it
	// embeds, whose methods it gets.
	embeds map[string][]string

	// virtual maps each method to the methods it calls on its receiver that
	// neither its type nor an embedded one declares, as create in
	// r.securityGroupRule.create(...). The type that embeds the method's
	// type supplies them.
	virtual map[string][]string

	// ifaces maps the package's client interfaces to the SDK operations
	// their methods make; see clientInterfaces.
	ifaces map[string][]iam.Requirement
}

func newPkgIndex(files []*ast.File) *pkgIndex {
	idx := &pkgIndex{
		funcs:       make(map[string]bool),
		plain:       make(map[string]bool),
		direct:      make(map[string][]iam.Requirement),
		calls:       make(map[string][]helperCall),
		memo:        make(map[string][]iam.Requirement),
		inProgress:  make(map[string]bool),
		errResult:   make(map[string]bool),
		clients:     make(map[string]bool),
		reach:       make(map[string]bool),
		alwaysCalls: make(map[string][]string),
		models:      newModelTable(files),
		embeds:      newEmbedTable(files),
		virtual:     make(map[string][]string),
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
			// A method is also indexed under its receiver type, so the
			// Create methods of two framework resources stay apart.
			if recv := receiverType(fd); recv != "" {
				key := methodKey(recv, fd.Name.Name)
				decls[key] = declared{fd, imports}
				idx.funcs[key] = true
				idx.errResult[key] = lastResultIsError(fd.Type.Results)
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
	idx.ifaces = clientInterfaces(files)
	for name, d := range decls {
		idx.index(name, d.fd, d.imports)
	}
	return idx
}

// index records the direct SDK calls and the helper calls of one function
// under name. imports are the service packages its file imports.
func (idx *pkgIndex) index(name string, fd *ast.FuncDecl, imports map[string]string) {
	calls := extractSDKCalls(fd, idx.models)
	if ops := interfaceParamCalls(fd.Type, idx.ifaces); len(ops) > 0 {
		calls = mergeRequirements(append(calls, ops...))
		idx.clients[name] = true
	}
	if len(calls) > 0 {
		idx.direct[name] = calls
	}
	helpers, virtual := findCalls(fd, idx, imports)
	if len(helpers) > 0 {
		idx.calls[name] = helpers
	}
	if len(virtual) > 0 {
		idx.virtual[name] = virtual
	}
	if touchesClient(fd) {
		idx.clients[name] = true
	}
	if calls := alwaysCalled(fd); len(calls) > 0 {
		idx.alwaysCalls[name] = calls
	}
}

// alwaysCalled returns the names of the plain functions fd calls on every
// run that gets past its early returns: calls in the expressions of its
// top-level statements, closures excluded. A call inside an if, a loop or a
// switch runs only sometimes, so it is left out.
func alwaysCalled(fd *ast.FuncDecl) []string {
	var out []string
	for _, stmt := range fd.Body.List {
		switch stmt.(type) {
		case *ast.ExprStmt, *ast.AssignStmt, *ast.ReturnStmt, *ast.DeclStmt:
		default:
			continue
		}
		ast.Inspect(stmt, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.CallExpr:
				if id, ok := n.Fun.(*ast.Ident); ok {
					out = append(out, id.Name)
				}
			}
			return true
		})
	}
	return dedup(out)
}

// setTagsOutFunc is the generated helper with which a resource's read hands
// the provider the tags it got from the service API.
const setTagsOutFunc = "setTagsOut"

// setsTagsOut reports whether a function sets the resource's tags from the
// service API on every run, itself or through the functions it always calls.
// The provider's tag interceptor then skips the service's ListTags after a
// create or read: it calls it only when the read set no tags.
func (idx *pkgIndex) setsTagsOut(name string) bool {
	return idx.searchTagsOut(name, make(map[string]bool))
}

func (idx *pkgIndex) searchTagsOut(name string, seen map[string]bool) bool {
	if seen[name] {
		return false
	}
	seen[name] = true
	for _, callee := range idx.alwaysCalls[name] {
		if !idx.hasPlain(callee) {
			continue
		}
		if callee == setTagsOutFunc || idx.searchTagsOut(callee, seen) {
			return true
		}
	}
	return false
}

// clientInterfaces maps each interface type the package declares whose
// methods are SDK operations to the actions of those methods. The provider
// generates paginators into some service packages, such as
// paginator_DescribeVpcEncryptionControls_gen.go in ec2: the constructor takes
// the client as describeVpcEncryptionControlsAPIClient, whose one method is
// DescribeVpcEncryptionControls(context.Context,
// *ec2.DescribeVpcEncryptionControlsInput, ...), and NextPage calls it on the
// client it stored. A method counts as an operation when its second parameter
// is a pointer to the SDK input type named after it.
func clientInterfaces(files []*ast.File) map[string][]iam.Requirement {
	out := make(map[string][]iam.Requirement)
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				it, ok := ts.Type.(*ast.InterfaceType)
				if !ok || it.Methods == nil {
					continue
				}
				var reqs []iam.Requirement
				for _, m := range it.Methods.List {
					ft, ok := m.Type.(*ast.FuncType)
					if !ok || len(m.Names) != 1 {
						continue
					}
					if svc := operationInputService(ft, m.Names[0].Name); svc != "" {
						reqs = append(reqs, iam.Requirement{Action: sdKMethodToIAMAction(m.Names[0].Name, svc)})
					}
				}
				if len(reqs) > 0 {
					out[ts.Name.Name] = reqs
				}
			}
		}
	}
	return out
}

// operationInputService returns the service of an SDK operation's signature,
// "ec2" for (context.Context, *ec2.DescribeVpcsInput, ...) when method is
// DescribeVpcs, or "" when the second parameter is not that input type.
func operationInputService(ft *ast.FuncType, method string) string {
	if ft.Params == nil || len(ft.Params.List) < 2 || !isAWSMethod(method) {
		return ""
	}
	star, ok := ft.Params.List[1].Type.(*ast.StarExpr)
	if !ok {
		return ""
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method+"Input" {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	if svc := sdkPackageToIAMService(pkg.Name); svc != "" {
		return svc
	}
	return pkg.Name
}

// interfaceParamCalls returns the actions of the client interfaces a function
// takes as parameters: a function handed such a client makes those calls on
// it, as a paginator constructor does on every page.
func interfaceParamCalls(ft *ast.FuncType, ifaces map[string][]iam.Requirement) []iam.Requirement {
	if ft == nil || ft.Params == nil || len(ifaces) == 0 {
		return nil
	}
	var out []iam.Requirement
	for _, param := range ft.Params.List {
		if ident, ok := param.Type.(*ast.Ident); ok {
			out = append(out, ifaces[ident.Name]...)
		}
	}
	return out
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
	found, _ := idx.searchClient(name, make(map[*pkgIndex]map[string]bool))
	if !found {
		// The outermost search explored everything the function reaches.
		idx.reach[name] = false
	}
	return found
}

// searchClient is the depth-first search behind reachesClient. complete is
// false when the search met a function still on the search stack: the answer
// for that function is not known yet, so a false result from below it is not
// stored. A true result always is.
func (idx *pkgIndex) searchClient(name string, onStack map[*pkgIndex]map[string]bool) (found, complete bool) {
	if r, ok := idx.reach[name]; ok {
		return r, true
	}
	if onStack[idx][name] {
		return false, false
	}
	if onStack[idx] == nil {
		onStack[idx] = make(map[string]bool)
	}
	onStack[idx][name] = true
	defer delete(onStack[idx], name)

	if idx.clients[name] {
		idx.reach[name] = true
		return true, true
	}
	complete = true
	for _, hc := range idx.calls[name] {
		target := idx
		if hc.Pkg != "" {
			if target = idx.others[hc.Pkg]; target == nil {
				continue
			}
		}
		f, c := target.searchClient(hc.Name, onStack)
		if f {
			idx.reach[name] = true
			return true, true
		}
		complete = complete && c
	}
	if complete {
		idx.reach[name] = false
	}
	return false, complete
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
func (idx *pkgIndex) resolve(name string) []iam.Requirement {
	if r, ok := idx.memo[name]; ok {
		return r
	}
	if idx.inProgress[name] {
		return nil
	}
	idx.inProgress[name] = true
	defer delete(idx.inProgress, name)

	resolved := append([]iam.Requirement(nil), idx.direct[name]...)
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
		for _, r := range target.resolve(hc.Name) {
			if bestEffort {
				r.BestEffort = true
			}
			if len(hc.Cond) == 0 || !r.Ungated() {
				resolved = append(resolved, r)
				continue
			}
			for _, g := range hc.Cond {
				resolved = append(resolved, iam.Requirement{Action: r.Action, Gate: g.gate(r.BestEffort)})
			}
		}
	}
	resolved = mergeRequirements(resolved)
	idx.memo[name] = resolved
	return resolved
}
