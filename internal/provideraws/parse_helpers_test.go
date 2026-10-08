package provideraws

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// The helpers in this file parse Go source given as strings, so a test can
// feed the parser a fixture. Production code indexes whole service
// directories instead, in indexService.

// ParseResourceFileStructured parses a Go source file from the
// terraform-provider-aws and extracts the requirements of each CRUD function,
// one per path that reaches an action. ParsePackage does the same across all
// the files of a service package.
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
func ParseResourceFileStructured(src string, tfType string, resourceName string) (map[string][]iam.Requirement, error) {
	name := tfType + ".go"
	pkg, err := ParsePackage(map[string]string{name: src})
	if err != nil {
		return nil, err
	}
	actions, _ := pkg.ResourceActions(name, resourceName)
	return actions, nil
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

// ResourceActions returns the actions each CRUD operation of the resource in
// fileName needs, and the function bound to each operation the resource
// declares. An operation bound to something other than a package function,
// such as schema.NoopContext, maps to "": it is declared but makes no call.
//
// The bindings come from the schema.Resource literal (CreateWithoutTimeout:
// resourceBucketCreate). A file without one falls back to the naming
// convention resource<Name><Op>.
func (p *Package) ResourceActions(fileName, resourceName string) (map[string][]iam.Requirement, map[string]string) {
	funcs := p.resourceFuncs(fileName, resourceName)
	if funcs == nil {
		return nil, nil
	}
	return p.actionsFor(funcs), boundFuncs(funcs)
}

// findHelperCalls returns the helper calls findCalls finds.
func findHelperCalls(fd *ast.FuncDecl, idx *pkgIndex, imports map[string]string) []helperCall {
	helpers, _ := findCalls(fd, idx, imports)
	return helpers
}
