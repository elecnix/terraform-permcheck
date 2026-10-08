package provideraws

import (
	"go/ast"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// walkContext is the state the traversal owns: the guards of the path it is
// on and the client variables currently in scope. Observers read it to label
// what they find; the traversal restores it when a block ends.
type walkContext struct {
	// cond is the gate of the path the traversal is on: the path runs only
	// when one of these guards holds. Empty when the path tests nothing.
	cond []condGuard

	// priorGuards maps the boolean locals that the statements before an
	// if-statement bound to a guard, such as nameOk in
	// `_, nameOk := d.GetOk("x")`. It is set only while the traversal
	// enters that if-statement.
	priorGuards map[string][]condGuard

	// conns maps each client variable in scope to the AWS service it talks
	// to, e.g. "conn" → "backup". It is copied on write, so restoring a saved
	// context also restores the scope.
	conns map[string]string

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

	// structs are the package's model types, and models maps each variable
	// in scope that holds one to its type. Copied on write, like conns.
	structs modelTable
	models  map[string]string
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

// enterGuard puts the path under gs: from here on, the path runs only when
// one of those guards holds. The outermost guard decides the gate, except under value guards: the
// provider's default already satisfies them, so a nested guard decides the
// call instead.
func (c *walkContext) enterGuard(gs []condGuard) {
	if len(gs) == 0 {
		return
	}
	for _, g := range c.cond {
		if !g.Value {
			return
		}
	}
	c.cond = gs
}

// gates returns the gate of each guard the path may run under, or one
// ungated path when it runs under none.
func (c *walkContext) gates(bestEffort bool) []iam.Gate {
	if len(c.cond) == 0 {
		return []iam.Gate{{BestEffort: bestEffort}}
	}
	out := make([]iam.Gate, len(c.cond))
	for i, g := range c.cond {
		out[i] = g.gate(bestEffort)
	}
	return out
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

		// The body runs when the condition holds and the else branch when it
		// does not, so each branch takes the gate its own outcome implies:
		// the else branch of `if _, ok := d.GetOk("x"); ok` tests nothing,
		// and the else branch of `if _, ok := d.GetOk("x"); !ok` runs only
		// when x is set.
		vars := initGuardVars(n.Init, ctx.priorGuards)
		thenGuard, elseGuard := branchGuards(n, vars, ctx)
		ctx.priorGuards = nil
		branch := *ctx

		// The body of a branch that handles a failed call and returns the
		// failure runs only when the apply is already failing.
		ctx.enterGuard(thenGuard)
		if isFailureBranch(n, ctx.results) {
			ctx.bestEffort = true
		}
		walkBody(n.Body, ctx, obs)

		// An else-if reads the locals the init of this if-statement binds.
		*ctx = branch
		ctx.enterGuard(elseGuard)
		if _, chained := n.Else.(*ast.IfStmt); chained {
			ctx.priorGuards = vars
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

	case *ast.DeclStmt:
		// var data resourceModel: the guards on data's fields name
		// attributes.
		bindModelDecl(n, ctx)
		walkChildren(n, ctx, obs)

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
		bindModelParams(n.Type, ctx)
		ctx.results = n.Type.Results
		walkBody(n.Body, ctx, obs)
		*ctx = saved

	default:
		walkChildren(node, ctx, obs)
	}
}

// walkChildren walks the direct children of node in order.
func walkChildren(node ast.Node, ctx *walkContext, obs walker) {
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
//
// It also tracks the boolean locals the list binds to a guard, such as
// nameOk in `_, nameOk := d.GetOk("x")`, so an if-statement later in the list
// that tests them reads their guard.
func walkStmts(list []ast.Stmt, ctx *walkContext, obs walker) {
	var vars map[string][]condGuard
	for i, stmt := range list {
		ctx.priorGuards = nil
		if _, ok := stmt.(*ast.IfStmt); ok {
			ctx.priorGuards = vars
		}
		vars = trackGuardVars(vars, stmt)
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

// unwrapExpr strips parentheses from an expression, so a guard written as
// `(d.HasChange("attr"))` is recognized. It does not strip a negation, which
// flips the branch a guard gates (see guardReader.implied).
func unwrapExpr(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// newWalkContext is the context a traversal of fd's body starts in, with its
// client and model parameters bound.
func newWalkContext(fd *ast.FuncDecl, models modelTable) *walkContext {
	ctx := &walkContext{results: fd.Type.Results, structs: models}
	bindConnParams(fd.Type, ctx)
	bindModelParams(fd.Type, ctx)
	return ctx
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
