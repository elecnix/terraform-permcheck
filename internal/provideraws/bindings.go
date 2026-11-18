package provideraws

import (
	"go/ast"
	"go/token"
	"strings"
)

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
// included, holds the calls. A method value on a local of a named type
// (h.Upsert, where h := &queueAttributeHandler{...}) is the method's index key,
// queueAttributeHandler.Upsert; resolveMethodBindings drops it when the package
// declares no such method. A func literal written in place (StateContext:
// func(ctx context.Context, ...) {...}) is named after the declaration that
// holds it and its operation, as resourceStream[import], and returned in lits
// under that name for the package to index. Any other binding
// (schema.NoopContext) maps to "".
func operationBindings(f *ast.File) (bound map[string][]string, lits map[string]*ast.FuncLit) {
	bound = make(map[string][]string)
	lits = make(map[string]*ast.FuncLit)
	for _, decl := range f.Decls {
		var locals map[string]string
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
			locals = localTypes(fd.Body)
		}
		collectBindings(decl, declName(decl), locals, bound, lits)
	}
	return bound, lits
}

// declName returns the name of a top-level declaration whose func literals
// the index can resolve: a plain function's, or the first name of a var or
// const declaration. A method gets "": its literals call through the receiver,
// as the OpsWorks layers' lt.Create, and the index has no value for it.
func declName(decl ast.Decl) string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv != nil {
			return ""
		}
		return d.Name.Name
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
				return vs.Names[0].Name
			}
		}
	}
	return ""
}

// literalName is the index name of a func literal bound to op in the
// declaration owner. The brackets keep it apart from every declared name.
func literalName(owner, op string) string {
	return owner + "[" + op + "]"
}

// localTypes maps each local variable the block declares with a named type to
// that type: h := &T{...}, h := T{...}, var h T and var h *T. A name declared
// twice with different types is ambiguous and left out.
func localTypes(body *ast.BlockStmt) map[string]string {
	types := make(map[string]string)
	ambiguous := make(map[string]bool)
	record := func(name, typ string) {
		if name == "_" || typ == "" {
			return
		}
		if old, ok := types[name]; ok && old != typ {
			ambiguous[name] = true
		}
		types[name] = typ
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			if v.Tok != token.DEFINE || len(v.Lhs) != len(v.Rhs) {
				return true
			}
			for i, lhs := range v.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				rhs := v.Rhs[i]
				if u, ok := rhs.(*ast.UnaryExpr); ok && u.Op == token.AND {
					rhs = u.X
				}
				if lit, ok := rhs.(*ast.CompositeLit); ok {
					record(id.Name, namedType(lit.Type))
				}
			}
		case *ast.ValueSpec:
			typ := namedType(v.Type)
			for _, id := range v.Names {
				record(id.Name, typ)
			}
		}
		return true
	})
	for name := range ambiguous {
		delete(types, name)
	}
	return types
}

// namedType returns the name of a type of the package, T or *T, or "".
func namedType(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// resolveMethodBindings keeps a method binding only when the package declares
// the method; otherwise the operation maps to "" and stays unresolved.
func resolveMethodBindings(funcs map[string][]string, idx *pkgIndex) {
	for op, fns := range funcs {
		for i, fn := range fns {
			if strings.Contains(fn, ".") && !idx.has(fn) {
				funcs[op][i] = ""
			}
		}
	}
}

// collectBindings adds the bindings of the schema literals under n, which the
// declaration owner holds, to bound, and the func literals they bind to lits.
func collectBindings(n ast.Node, owner string, locals map[string]string, bound map[string][]string, lits map[string]*ast.FuncLit) {
	ast.Inspect(n, func(n ast.Node) bool {
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
			case *ast.SelectorExpr:
				if recv, ok := v.X.(*ast.Ident); ok && locals[recv.Name] != "" {
					fn = methodKey(locals[recv.Name], v.Sel.Name)
				}
			case *ast.FuncLit:
				if owner != "" {
					fn = literalName(owner, op)
					lits[fn] = v
				}
			}
			bound[op] = []string{fn}
		}
		return true
	})
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

// containsIgnoreCase reports whether s contains substr, case-insensitively.
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && len(substr) > 0 &&
		strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
