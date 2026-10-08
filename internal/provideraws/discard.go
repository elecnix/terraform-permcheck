package provideraws

import (
	"go/ast"
	"go/token"
	"strings"
)

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
