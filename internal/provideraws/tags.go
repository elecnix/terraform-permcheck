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

// ExtractTagActions parses a service's generated tags_gen.go source and returns
// the SDK tagging actions used by its updateTags, createTags, and listTags
// helpers. The connection variable is a typed SDK client parameter
// (conn *kms.Client), from which the service prefix is derived.
func ExtractTagActions(src string) (TagActions, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "tags_gen.go", src, parser.ParseComments)
	if err != nil {
		return TagActions{}, fmt.Errorf("parse tags source: %w", err)
	}

	var ta TagActions
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Name.Name == "updateTags" || fd.Name.Name == "createTags" {
			calls, _, _ := extractSDKCallsWithConnInfo(fd)
			for _, ea := range calls {
				if isRemoveTagAction(ea.Action) {
					ta.Remove = dedup(append(ta.Remove, ea.Action))
				} else {
					ta.Apply = dedup(append(ta.Apply, ea.Action))
				}
			}
		}
		if fd.Name.Name == "listTags" {
			calls, _, _ := extractSDKCallsWithConnInfo(fd)
			for _, ea := range calls {
				ta.List = dedup(append(ta.List, ea.Action))
			}
		}
	}
	return ta, nil
}

// isRemoveTagAction reports whether a tagging action removes tags (so it is
// only relevant on update). Covers Untag*/Delete*/Remove* method conventions
// across services (kms:UntagResource, ec2:DeleteTags, etc.).
func isRemoveTagAction(action string) bool {
	verb := action
	if idx := strings.Index(action, ":"); idx >= 0 {
		verb = action[idx+1:]
	}
	return strings.HasPrefix(verb, "Untag") ||
		strings.HasPrefix(verb, "Delete") ||
		strings.HasPrefix(verb, "Remove")
}
