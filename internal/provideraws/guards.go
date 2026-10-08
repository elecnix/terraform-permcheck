package provideraws

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// trackGuardVars returns the guard locals in scope after stmt: an assignment
// binds or rebinds them (see bindGuardVars), and a local that stmt may assign
// in any other way, in a nested block or closure or through a pointer, no
// longer holds a guard.
func trackGuardVars(vars map[string][]condGuard, stmt ast.Stmt) map[string][]condGuard {
	if assign, ok := stmt.(*ast.AssignStmt); ok {
		vars = bindGuardVars(vars, assign)
		for _, rhs := range assign.Rhs {
			vars = dropAssigned(vars, rhs)
		}
		return vars
	}
	return dropAssigned(vars, stmt)
}

// dropAssigned returns vars without the locals node may assign.
func dropAssigned(vars map[string][]condGuard, node ast.Node) map[string][]condGuard {
	if len(vars) == 0 {
		return vars
	}
	var names []string
	ast.Inspect(node, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					names = append(names, id.Name)
				}
			}
		case *ast.UnaryExpr:
			if id, ok := n.X.(*ast.Ident); ok && n.Op == token.AND {
				names = append(names, id.Name)
			}
		case *ast.ValueSpec:
			for _, id := range n.Names {
				names = append(names, id.Name)
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{n.Key, n.Value} {
				if id, ok := e.(*ast.Ident); ok {
					names = append(names, id.Name)
				}
			}
		}
		return true
	})
	// The map may be shared with a saved context, so it is copied on write.
	out, copied := vars, false
	for _, name := range names {
		if _, ok := out[name]; !ok {
			continue
		}
		if !copied {
			out, copied = make(map[string][]condGuard, len(vars)), true
			for k, v := range vars {
				out[k] = v
			}
		}
		delete(out, name)
	}
	return out
}

// condGuard is a gating attribute found on an if-statement, with the kind of
// gate the provider applies to it.
type condGuard struct {
	Attribute string
	// Change is true for a change guard (d.HasChange), false for a presence
	// guard (d.GetOk or d.Get).
	Change bool
	// Value is true for a presence guard that also tests the value is not
	// empty, so the provider's default does not satisfy it.
	Value bool
}

// gate returns the gate of a path that runs under the guard.
func (g condGuard) gate(bestEffort bool) iam.Gate {
	if g.Change {
		return iam.Gate{Changed: g.Attribute, BestEffort: bestEffort}
	}
	return iam.Gate{Attribute: g.Attribute, ValueGuarded: g.Value, BestEffort: bestEffort}
}

// branchGuards returns the gate of an if-statement's body and the gate of its
// else branch. A branch runs only when one of its guards holds; nil means
// the branch tests no attribute. vars maps the boolean locals in scope that
// hold a guard (see initGuardVars).
func branchGuards(n *ast.IfStmt, vars map[string][]condGuard, ctx *walkContext) (then, els []condGuard) {
	r := guardReader{vars: vars, values: localAttrBindings(n.Init), ctx: ctx}
	return r.implied(n.Cond, true), r.implied(n.Cond, false)
}

// guardReader reads the guards a condition implies.
type guardReader struct {
	// vars maps boolean locals to the guards they hold, as ok in
	// `v, ok := d.GetOk("x")`.
	vars map[string][]condGuard
	// values maps locals to the attribute whose value they hold, as v in
	// the same statement, for emptiness tests.
	values map[string]string
	ctx    *walkContext
}

// implied returns guards one of which holds whenever expr evaluates to truth,
// or nil when that outcome tests no attribute the parser can name.
//
// A negation flips the outcome. When both operands of && or || take the
// outcome (&& true, || false), the gate of either operand holds, so the
// stronger one is kept. When only one of them needs to (&& false, || true),
// the gate holds only if each operand has one, and it is their union.
func (r guardReader) implied(expr ast.Expr, truth bool) []condGuard {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return r.implied(e.X, truth)
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return r.implied(e.X, !truth)
		}
		return nil
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND, token.LOR:
			left, right := r.implied(e.X, truth), r.implied(e.Y, truth)
			if (e.Op == token.LAND) == truth {
				return strongerGuard(left, right)
			}
			if left == nil || right == nil {
				return nil
			}
			return append(append([]condGuard(nil), left...), right...)
		}
		// A collection that is not empty was set by the author.
		if truth && isEmptinessTest(e) {
			if attr := attributeUnderLengthCall(e, r.values); attr != "" {
				return []condGuard{{Attribute: attr, Value: true}}
			}
		}
		return nil
	}
	guards, when := r.atom(expr)
	if when != truth {
		return nil
	}
	return guards
}

// atom returns the guards a condition that is not a negation or a boolean
// operator tests, and the outcome under which one of them holds.
func (r guardReader) atom(expr ast.Expr) ([]condGuard, bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		return r.vars[e.Name], true
	case *ast.TypeAssertExpr:
		// d.Get("x").(bool)
		return resourceDataGuards(e.X), true
	case *ast.CallExpr:
		if gs := resourceDataGuards(e); gs != nil {
			return gs, true
		}
		return frameworkGuard(e, r.ctx)
	}
	return nil, false
}

// strongerGuard returns the gate of two that both hold: a single guard over a
// choice of several, and a value guard over a presence guard.
func strongerGuard(a, b []condGuard) []condGuard {
	rank := func(gs []condGuard) int {
		switch {
		case len(gs) == 0:
			return 0
		case len(gs) > 1:
			return 1
		case !gs[0].Value:
			return 2
		}
		return 3
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// initGuardVars returns the boolean locals that hold a guard in the scope of
// an if-statement: those bound before it (prior), and those its init binds.
// A local the init binds to anything else is no longer a guard.
func initGuardVars(init ast.Stmt, prior map[string][]condGuard) map[string][]condGuard {
	assign, ok := init.(*ast.AssignStmt)
	if !ok {
		return prior
	}
	return bindGuardVars(prior, assign)
}

// bindGuardVars returns vars updated by an assignment: a local it binds to
// the ok result of d.GetOk, or to d.HasChange, holds that guard, and any
// other local it assigns holds none.
func bindGuardVars(vars map[string][]condGuard, assign *ast.AssignStmt) map[string][]condGuard {
	bound := make(map[string][]condGuard)
	switch {
	case len(assign.Rhs) == 1 && len(assign.Lhs) == 2:
		// v, ok := d.GetOk("x")
		if call, ok := unwrapExpr(assign.Rhs[0]).(*ast.CallExpr); ok && isResourceDataMethod(call, "GetOk") {
			if id, ok := assign.Lhs[1].(*ast.Ident); ok {
				bound[id.Name] = resourceDataGuards(call)
			}
		}
	case len(assign.Rhs) == len(assign.Lhs):
		// changed := d.HasChange("x"), enabled := d.Get("x").(bool)
		for i, rhs := range assign.Rhs {
			var gs []condGuard
			switch e := unwrapExpr(rhs).(type) {
			case *ast.TypeAssertExpr:
				if t, ok := e.Type.(*ast.Ident); ok && t.Name == "bool" {
					gs = resourceDataGuards(e.X)
				}
			case *ast.CallExpr:
				if isResourceDataMethod(e, "HasChange") || isResourceDataMethod(e, "HasChanges") {
					gs = resourceDataGuards(e)
				}
			}
			if id, ok := assign.Lhs[i].(*ast.Ident); ok && gs != nil {
				bound[id.Name] = gs
			}
		}
	}
	out := make(map[string][]condGuard, len(vars)+len(bound))
	for name, gs := range vars {
		out[name] = gs
	}
	for _, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); ok {
			delete(out, id.Name)
		}
	}
	for name, gs := range bound {
		out[name] = gs
	}
	return out
}

// isResourceDataMethod reports whether call is d.<method>(...).
func isResourceDataMethod(call *ast.CallExpr, method string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "d"
}

// resourceDataGuards returns the guards a call on the resource data tests
// when it returns true: d.GetOk("attr") and d.Get("attr") test presence,
// d.HasChange("attr") a change, and d.HasChanges("a", "b") a change to any of
// its attributes. d.HasChangesExcept is a filter and names no attribute.
// Returns nil for any other expression.
func resourceDataGuards(expr ast.Expr) []condGuard {
	call, ok := unwrapExpr(expr).(*ast.CallExpr)
	if !ok {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "d" {
		return nil
	}
	var change bool
	args := call.Args
	switch sel.Sel.Name {
	case "GetOk", "Get":
		args = args[:min(len(args), 1)]
	case "HasChange":
		change = true
		args = args[:min(len(args), 1)]
	case "HasChanges":
		change = true
	default:
		return nil
	}
	var guards []condGuard
	for _, arg := range args {
		attr := attributeName(arg)
		if attr == "" {
			return nil
		}
		guards = append(guards, condGuard{Attribute: attr, Change: change})
	}
	return guards
}

// attributeName returns the attribute name an argument spells, as a string
// literal or as a constant of the provider's names package
// (names.AttrKMSKeyID), or "".
func attributeName(arg ast.Expr) string {
	switch a := arg.(type) {
	case *ast.BasicLit:
		if a.Kind == token.STRING {
			return strings.Trim(a.Value, "\"")
		}
	case *ast.SelectorExpr:
		if pkg, ok := a.X.(*ast.Ident); ok && pkg.Name == "names" {
			return namesAttrConsts[a.Sel.Name]
		}
	}
	return ""
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
// `if v, ok := d.GetOk("version_stages"); ok`, or of
// `if v := d.Get("replica").(*schema.Set); v.Len() > 0`.
func localAttrBindings(init ast.Stmt) map[string]string {
	bindings := make(map[string]string)
	assign, ok := init.(*ast.AssignStmt)
	if !ok {
		return bindings
	}
	for i, rhs := range assign.Rhs {
		if ta, ok := rhs.(*ast.TypeAssertExpr); ok {
			rhs = ta.X
		}
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

// extractGetOkAttribute checks if an expression is d.GetOk("attr") or
// d.Get("attr") and returns the attribute name. It is the presence-only reader
// the value-guard helpers use; resourceDataGuards performs the same
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

	if len(call.Args) < 1 {
		return ""
	}
	return attributeName(call.Args[0])
}
