package provideraws

import (
	"go/ast"
	"go/token"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// frameworkResourceAnnotationRE matches the @FrameworkResource annotation of
// a Terraform Plugin Framework resource. The provider spells it three ways:
//
//	// @FrameworkResource("aws_api_gateway_account", name="Account")
//	// @FrameworkResource( "aws_datazone_domain", name="Domain")
//	// @FrameworkResource(aws_verifiedpermissions_policy, name="Policy")
var frameworkResourceAnnotationRE = regexp.MustCompile(`@FrameworkResource\(\s*"?(aws_[A-Za-z0-9_]+)"?\s*[,)]`)

// frameworkResourceType returns the resource type a @FrameworkResource
// annotation in src names, or "".
func frameworkResourceType(src string) string {
	if m := frameworkResourceAnnotationRE.FindStringSubmatch(src); m != nil {
		return m[1]
	}
	return ""
}

// frameworkOperations maps the methods of a framework resource type to the
// operation each implements.
var frameworkOperations = []struct{ method, op string }{
	{"Create", "create"}, {"Read", "read"}, {"Update", "update"}, {"Delete", "delete"}, {"ImportState", "import"},
}

// frameworkResourceStruct returns the type a framework resource's annotated
// constructor builds, as in
//
//	// @FrameworkResource("aws_s3_bucket_lifecycle_configuration", ...)
//	func newResourceBucketLifecycleConfiguration(context.Context) (resource.ResourceWithConfigure, error) {
//		r := &resourceBucketLifecycleConfiguration{}
//
// The constructor is the function whose doc comment holds the annotation, and
// the type is the first composite literal of a named type in its body. It
// returns "" when the file has no such constructor.
func frameworkResourceStruct(f *ast.File) string {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Body == nil || fd.Doc == nil || frameworkResourceType(fd.Doc.Text()) == "" {
			continue
		}
		name := ""
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.CompositeLit); ok && name == "" {
				if id, ok := lit.Type.(*ast.Ident); ok {
					name = id.Name
				}
			}
			return name == ""
		})
		return name
	}
	return ""
}

// frameworkFuncs binds each operation of a framework resource to the method
// of its type that implements it. A method the type gets from an embedded
// type of another package, such as framework.WithNoOpDelete, binds nothing.
//
// A method the type gets from an embedded type of the package may call
// methods on its receiver that only the embedding type declares, as the
// security group rules do: securityGroupRuleResource.Create calls
// r.securityGroupRule.create, which securityGroupIngressRuleResource
// implements. Those methods of typeName are bound to the operation too,
// without the guards of their call sites.
func (p *Package) frameworkFuncs(typeName string) map[string][]string {
	funcs := make(map[string][]string)
	for _, m := range frameworkOperations {
		key := p.idx.method(typeName, m.method)
		if key == "" {
			continue
		}
		funcs[m.op] = []string{key}
		for _, name := range p.idx.virtual[key] {
			if v := p.idx.method(typeName, name); v != "" && v != key {
				funcs[m.op] = append(funcs[m.op], v)
			}
		}
	}
	return funcs
}

// method returns the index key of the method typeName declares or gets from
// a struct type of the package it embeds, or "".
func (idx *pkgIndex) method(typeName, name string) string {
	seen := make(map[string]bool)
	queue := []string{typeName}
	for len(queue) > 0 {
		t := queue[0]
		queue = queue[1:]
		if seen[t] {
			continue
		}
		seen[t] = true
		if key := methodKey(t, name); idx.has(key) {
			return key
		}
		queue = append(queue, idx.embeds[t]...)
	}
	return ""
}

// methodKey is the index key of a method: its receiver type and its name,
// as in "resourceBucketLifecycleConfiguration.Create". Framework resources of
// one package all have a Create method, so the name alone is ambiguous.
func methodKey(typeName, method string) string {
	return typeName + "." + method
}

// receiverType returns the name of a method's receiver type, without the
// pointer and the type parameters, or "" for a plain function.
func receiverType(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := unwrapIndex(t).(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// receiverName returns the name a method binds its receiver to, or "".
func receiverName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 || len(fd.Recv.List[0].Names) == 0 {
		return ""
	}
	return fd.Recv.List[0].Names[0].Name
}

// modelTable maps each struct type of a package to the attribute each of its
// fields holds, from the fields' tfsdk tags: Policy types.String
// `tfsdk:"policy"` maps Policy to "policy". Fields of an embedded struct of the
// same package are promoted.
type modelTable map[string]map[string]string

// structTypes returns the struct types the files declare, by name.
func structTypes(files []*ast.File) map[string]*ast.StructType {
	structs := make(map[string]*ast.StructType)
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
				if st, ok := ts.Type.(*ast.StructType); ok {
					structs[ts.Name.Name] = st
				}
			}
		}
	}
	return structs
}

// newEmbedTable maps each struct type of the files to the struct types of
// the same files it embeds.
func newEmbedTable(files []*ast.File) map[string][]string {
	structs := structTypes(files)
	out := make(map[string][]string)
	for name, st := range structs {
		for _, field := range st.Fields.List {
			if len(field.Names) > 0 {
				continue
			}
			t := field.Type
			if star, ok := t.(*ast.StarExpr); ok {
				t = star.X
			}
			if id, ok := t.(*ast.Ident); ok && structs[id.Name] != nil {
				out[name] = append(out[name], id.Name)
			}
		}
	}
	return out
}

// newModelTable reads the tfsdk-tagged struct types of the files.
func newModelTable(files []*ast.File) modelTable {
	structs := structTypes(files)
	table := make(modelTable)
	var fields func(name string, seen map[string]bool) map[string]string
	fields = func(name string, seen map[string]bool) map[string]string {
		st := structs[name]
		if st == nil || seen[name] {
			return nil
		}
		seen[name] = true
		out := make(map[string]string)
		for _, field := range st.Fields.List {
			if len(field.Names) == 0 {
				if id, ok := field.Type.(*ast.Ident); ok {
					for k, v := range fields(id.Name, seen) {
						out[k] = v
					}
				}
				continue
			}
			attr := tfsdkTag(field.Tag)
			if attr == "" {
				continue
			}
			for _, n := range field.Names {
				out[n.Name] = attr
			}
		}
		return out
	}
	for name := range structs {
		if m := fields(name, map[string]bool{}); len(m) > 0 {
			table[name] = m
		}
	}
	return table
}

// tfsdkTag returns the attribute name a struct field's tfsdk tag gives, or "".
func tfsdkTag(tag *ast.BasicLit) string {
	if tag == nil {
		return ""
	}
	s, err := strconv.Unquote(tag.Value)
	if err != nil {
		return ""
	}
	attr, _, _ := strings.Cut(reflect.StructTag(s).Get("tfsdk"), ",")
	if attr == "-" {
		return ""
	}
	return attr
}

// bindModel records that variable name holds a value of the model type
// typeName, when the package declares that type with tfsdk tags.
func (c *walkContext) bindModel(name string, typ ast.Expr) {
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	id, ok := typ.(*ast.Ident)
	if !ok || c.structs[id.Name] == nil {
		return
	}
	m := make(map[string]string, len(c.models)+1)
	for k, v := range c.models {
		m[k] = v
	}
	m[name] = id.Name
	c.models = m
}

// bindModelParams binds every parameter typed as a model.
func bindModelParams(ft *ast.FuncType, ctx *walkContext) {
	if ft == nil || ft.Params == nil || ctx.structs == nil {
		return
	}
	for _, param := range ft.Params.List {
		for _, name := range param.Names {
			ctx.bindModel(name.Name, param.Type)
		}
	}
}

// bindModelDecl binds the variables a declaration such as
// `var old, new dataLakeResourceModel` gives a model type.
func bindModelDecl(decl *ast.DeclStmt, ctx *walkContext) {
	gd, ok := decl.Decl.(*ast.GenDecl)
	if !ok || gd.Tok != token.VAR || ctx.structs == nil {
		return
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || vs.Type == nil {
			continue
		}
		for _, name := range vs.Names {
			ctx.bindModel(name.Name, vs.Type)
		}
	}
}

// modelAttribute returns the attribute a selector such as data.Policy reads,
// when data holds a model, or "".
func (c *walkContext) modelAttribute(expr ast.Expr) string {
	sel, ok := unwrapExpr(expr).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	typ, ok := c.models[id.Name]
	if !ok {
		return ""
	}
	return c.structs[typ][sel.Sel.Name]
}

// frameworkGuard returns the guard a framework resource's condition tests,
// read from the model the plan was decoded into, and the outcome under which
// it holds:
//
//	data.Policy.IsNull()                         presence of policy, when false
//	new.Configuration.Equal(old.Configuration)   change of configuration, when false
//
// Any other call tests nothing.
func frameworkGuard(call *ast.CallExpr, ctx *walkContext) ([]condGuard, bool) {
	if ctx == nil || ctx.models == nil {
		return nil, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	attr := ctx.modelAttribute(sel.X)
	if attr == "" {
		return nil, false
	}
	switch {
	case sel.Sel.Name == "IsNull" && len(call.Args) == 0:
		return []condGuard{{Attribute: attr, Kind: ConditionPresence}}, false
	case sel.Sel.Name == "Equal" && len(call.Args) == 1 && ctx.modelAttribute(call.Args[0]) == attr:
		return []condGuard{{Attribute: attr, Kind: ConditionChange}}, false
	}
	return nil, false
}
