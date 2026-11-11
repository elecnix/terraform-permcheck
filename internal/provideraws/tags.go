package provideraws

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
)

// tagsAnnotationRE matches the @Tags annotation in provider resource source,
// which marks a resource as subject to the provider's transparent tagging:
//
//	// @Tags(identifierAttribute="id")
//
// Such resources make additional SDK tagging calls (e.g. kms:TagResource) when
// the `tags` attribute is set — calls that live in the service's generated
// tags_gen.go, not in the resource's own CRUD functions.
var tagsAnnotationRE = regexp.MustCompile(`(?m)^//\s*@Tags\(`)

// hasTagsAnnotation reports whether the source declares the @Tags annotation.
func hasTagsAnnotation(src []byte) bool {
	return tagsAnnotationRE.Match(src)
}

// TagActions holds the IAM actions a service uses for transparent tagging,
// split into additive (apply), subtractive (remove), and read-side (list) calls.
//
// Apply actions (e.g. kms:TagResource) are needed whenever tags are set, on
// both create and update. Remove actions (e.g. kms:UntagResource) are only
// needed on update, when existing tags change. List actions (e.g.
// kms:ListResourceTags) are always needed on read — the provider calls
// listTags unconditionally on every Read for resources with the @Tags annotation.
type TagActions struct {
	Apply  []string
	Remove []string
	List   []string
}

// Empty reports whether no tagging actions were found.
func (t TagActions) Empty() bool {
	return len(t.Apply) == 0 && len(t.Remove) == 0 && len(t.List) == 0
}

// tagsResourceTypeRE matches the resourceType argument of a @Tags annotation,
// as in @Tags(identifierAttribute="name", resourceType="Stream").
var tagsResourceTypeRE = regexp.MustCompile(`(?m)^//\s*@Tags\([^)\n]*resourceType="([^"]+)"`)

// tagsResourceType returns the resourceType a source's @Tags annotation
// names, or "" when it names none.
func tagsResourceType(src []byte) string {
	if m := tagsResourceTypeRE.FindSubmatch(src); m != nil {
		return string(m[1])
	}
	return ""
}

// tagEntries names the package functions that make a resource's transparent
// tagging calls: list reads the tags, update applies and removes them.
type tagEntries struct {
	list, update []string
}

// tagEntriesFor finds the functions that tag a resource whose @Tags
// annotation names resourceType. The provider calls the service package's
// ListTags and UpdateTags methods, wherever they live: tags_gen.go, or a
// hand-written tags.go as in kinesis, ram and s3 since provider 6.x. Such a
// method may switch on its resourceType parameter to tag each type through
// its own API, so the entry is the method as it runs for resourceType. A
// package without the methods falls back to its listTags, updateTags and
// createTags functions.
func (p *Package) tagEntriesFor(resourceType string) tagEntries {
	entries := func(method string, fallback ...string) []string {
		for _, f := range p.files {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if ok && fd.Body != nil && fd.Name.Name == method && receiverType(fd) == "servicePackage" {
					return []string{p.forResourceType(fd, serviceImports(f), resourceType)}
				}
			}
		}
		var out []string
		for _, name := range fallback {
			if p.idx.hasPlain(name) {
				out = append(out, name)
			}
		}
		return out
	}
	return tagEntries{
		list:   entries("ListTags", "listTags"),
		update: entries("UpdateTags", "updateTags", "createTags"),
	}
}

// forResourceType returns the index name of a servicePackage method as it
// runs for resourceType. When the method's body switches on resourceType,
// the switch is replaced by the statements of the case that names
// resourceType, or of the default case, and that copy is indexed under its
// own name. Otherwise the method runs the same for every type.
func (p *Package) forResourceType(fd *ast.FuncDecl, imports map[string]string, resourceType string) string {
	method := methodKey("servicePackage", fd.Name.Name)
	at := -1
	for i, stmt := range fd.Body.List {
		if sw, ok := stmt.(*ast.SwitchStmt); ok {
			if tag, ok := sw.Tag.(*ast.Ident); ok && tag.Name == "resourceType" {
				at = i
				break
			}
		}
	}
	if at < 0 {
		return method
	}
	name := method + "[" + resourceType + "]"
	if p.idx.has(name) {
		return name
	}
	var chosen, def *ast.CaseClause
	for _, stmt := range fd.Body.List[at].(*ast.SwitchStmt).Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if cc.List == nil {
			def = cc
		}
		for _, e := range cc.List {
			if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Trim(lit.Value, "\"`") == resourceType {
				chosen = cc
			}
		}
	}
	if chosen == nil {
		chosen = def
	}
	body := append([]ast.Stmt(nil), fd.Body.List[:at]...)
	if chosen != nil {
		body = append(body, &ast.BlockStmt{List: chosen.Body})
	}
	body = append(body, fd.Body.List[at+1:]...)
	copied := *fd
	copied.Body = &ast.BlockStmt{List: body}
	p.idx.funcs[name] = true
	p.idx.errResult[name] = lastResultIsError(fd.Type.Results)
	p.idx.index(name, &copied, imports)
	return name
}

// tagActions resolves tagging entry points to the actions they make, through
// every helper they call in the package.
func (p *Package) tagActions(e tagEntries) TagActions {
	var ta TagActions
	for _, name := range e.list {
		for _, r := range p.idx.resolve(name) {
			ta.List = append(ta.List, r.Action)
		}
	}
	for _, name := range e.update {
		for _, r := range p.idx.resolve(name) {
			if isRemoveTagAction(r.Action) {
				ta.Remove = append(ta.Remove, r.Action)
			} else {
				ta.Apply = append(ta.Apply, r.Action)
			}
		}
	}
	ta.List, ta.Apply, ta.Remove = dedup(ta.List), dedup(ta.Apply), dedup(ta.Remove)
	return ta
}

// ExtractTagActions parses a service's tagging source, such as its generated
// tags_gen.go, and returns the SDK tagging actions its ListTags and
// UpdateTags entry points make, for a resource that names no resourceType.
func ExtractTagActions(src string) (TagActions, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "tags_gen.go", src, parser.ParseComments)
	if err != nil {
		return TagActions{}, fmt.Errorf("parse tags source: %w", err)
	}
	pkg := newPackage(map[string]*ast.File{"tags_gen.go": f})
	return pkg.tagActions(pkg.tagEntriesFor("")), nil
}

// isRemoveTagAction reports whether a tagging action removes tags (so it is
// only relevant on update). Covers Untag*/Delete*/Remove* method conventions
// across services (kms:UntagResource, ec2:DeleteTags, etc.), and the HTTP
// DELETE that API Gateway authorizes for UntagResource.
func isRemoveTagAction(action string) bool {
	verb := action
	if idx := strings.Index(action, ":"); idx >= 0 {
		verb = action[idx+1:]
	}
	return verb == "DELETE" ||
		strings.HasPrefix(verb, "Untag") ||
		strings.HasPrefix(verb, "Delete") ||
		strings.HasPrefix(verb, "Remove")
}
