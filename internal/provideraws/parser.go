// Package provideraws parses terraform-provider-aws Go source files to
// extract the exact AWS SDK API calls required by each resource type.
//
// This provides a more precise alternative to CloudFormation schema resolution,
// capturing only the permissions actually used by the provider, not the
// maximal set of permissions the resource *could* need.
package provideraws

import (
	"go/ast"
	"sort"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// Package is the parsed source of one provider service package. A resource's
// CRUD functions often call helpers that live in another file of the package
// (the S3 bucket read calls findBucketPolicy from bucket_policy.go), so the
// call graph is built over every file.
type Package struct {
	files map[string]*ast.File
	idx   *pkgIndex
}

// newPackage indexes already parsed files as one package.
func newPackage(files map[string]*ast.File) *Package {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make([]*ast.File, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, files[name])
	}
	return &Package{files: files, idx: newPkgIndex(ordered)}
}

// resourceFuncs returns the functions bound to each operation of the resource
// in fileName, or nil when the package has no such file.
func (p *Package) resourceFuncs(fileName, resourceName string) map[string][]string {
	f := p.files[fileName]
	if f == nil {
		return nil
	}
	byName := operationsByName(f, resourceName)
	funcs := operationBindings(f)
	if len(funcs) == 0 {
		return byName
	}
	// An importer bound inline or not at all still has its function found
	// by name, as resource<Name>Import.
	if _, ok := funcs["import"]; !ok && len(byName["import"]) > 0 {
		funcs["import"] = byName["import"]
	}
	return funcs
}

// actionsFor resolves the actions of each operation's functions.
func (p *Package) actionsFor(funcs map[string][]string) map[string][]iam.Requirement {
	actions := make(map[string][]iam.Requirement)
	for op, fns := range funcs {
		var reqs []iam.Requirement
		for _, fn := range fns {
			if fn != "" {
				reqs = append(reqs, p.idx.resolve(fn)...)
			}
		}
		if len(reqs) > 0 {
			actions[op] = mergeRequirements(reqs)
		}
	}
	return actions
}
