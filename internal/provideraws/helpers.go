package provideraws

import "go/ast"

// helperCall records a call to a function of the same package and the
// conditional context at the call site (e.g., if d.GetOk("replica") {
// removeSecretReplicas(...) }).
type helperCall struct {
	Pkg        string      // service package of the helper, "" for the caller's own
	Name       string      // helper function name
	Cond       []condGuard // guards of the call site, any of which lets the call run; empty if unconditional
	BestEffort bool        // the call site sits on a path that handles a failure
	Discard    discardKind // how the call site drops the callee's error
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

// findCalls finds the calls a function body makes to other functions of the
// package, or to functions of the service packages in imports, tracking the
// conditional context at each call site. It also returns the methods a method
// calls on its receiver that the package does not declare for the receiver's
// type (see pkgIndex.virtual).
func findCalls(fd *ast.FuncDecl, idx *pkgIndex, imports map[string]string) ([]helperCall, []string) {
	if fd.Body == nil {
		return nil, nil
	}
	ctx := newWalkContext(fd, idx.models)
	obs := &helperCallObserver{idx: idx, imports: imports, recvName: receiverName(fd), recvType: receiverType(fd)}
	walkBody(fd.Body, ctx, obs)
	return obs.helpers, dedup(obs.virtual)
}

// helperCallObserver collects the calls to functions of the same package, each
// tagged with the conditional reason in force at the call site (e.g.
// removeSecretReplicas(ctx, conn, id) reached from inside
// if _, ok := d.GetOk("replica"); ok).
type helperCallObserver struct {
	idx     *pkgIndex
	imports map[string]string // import name → service package directory
	helpers []helperCall

	// recvName and recvType are the receiver of the method walked, as r and
	// dataLakeResource; both are "" for a plain function.
	recvName, recvType string

	// virtual are the receiver methods the package does not declare for
	// recvType.
	virtual []string
}

// onCall records a helper call but never consumes it: its arguments may hold
// further helper calls or closures that make some.
func (o *helperCallObserver) onCall(call *ast.CallExpr, ctx *walkContext) bool {
	if pkg, name := o.callee(call, ctx); name != "" {
		o.record(pkg, name, ctx.discardOf(call), ctx)
	} else if name := o.receiverCall(call); name != "" {
		o.virtual = append(o.virtual, name)
	}
	return false
}

// receiverCall returns the method a call makes on the receiver, or on a field
// of it, as create in r.securityGroupRule.create(...), or "".
func (o *helperCallObserver) receiverCall(call *ast.CallExpr) string {
	if o.recvName == "" {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	x := sel.X
	if field, ok := x.(*ast.SelectorExpr); ok {
		x = field.X
	}
	if id, ok := x.(*ast.Ident); ok && id.Name == o.recvName {
		return sel.Sel.Name
	}
	return ""
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
		Cond:       ctx.cond,
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
			// A method of the receiver, as r.putPolicy(...).
			if x.Name == o.recvName && o.recvType != "" {
				if key := o.idx.method(o.recvType, fn.Sel.Name); key != "" {
					return "", key
				}
			}
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
