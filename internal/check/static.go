package check

import (
	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// staticMutationOps are the operations static mode checks, in report order.
var staticMutationOps = []string{"create", "update", "delete"}

// staticChanges turns the parsed HCL blocks into the resource changes worth
// validating. It deduplicates by resource type, resolves each type's schema
// once, and emits one entry per operation that adds a permission the create
// check does not already cover. It returns the changes and the number of
// distinct resource types checked, which is not len(changes): a single type
// can carry several entries.
//
// A type the resolver cannot map is skipped, since validation has nothing to
// check it against.
func staticChanges(blocks []hcl.ResourceBlock, resolver Resolver) ([]*plan.ResourceChange, int) {
	var changes []*plan.ResourceChange
	checked := 0

	seen := make(map[string]bool)
	for _, b := range blocks {
		if seen[b.Type] {
			continue
		}
		seen[b.Type] = true

		schema, err := resolver.Resolve(b.Type)
		if err != nil {
			continue
		}
		ops := staticOpsFor(schema.GetPermissions())
		if len(ops) == 0 {
			continue
		}
		checked++

		var attrs map[string]bool
		if len(b.Attributes) > 0 {
			attrs = make(map[string]bool, len(b.Attributes))
			for _, a := range b.Attributes {
				attrs[a] = true
			}
		}

		for _, op := range ops {
			changes = append(changes, &plan.ResourceChange{
				Type:       b.Type,
				Name:       b.Name,
				Change:     op,
				Attributes: attrs,
			})
		}
	}

	return changes, checked
}

// staticOpsFor picks the mutation operations a schema makes worth checking.
// "create" is always worth it when the schema defines it. Another operation is
// worth it only when it carries at least one action the create set does not:
// the validator falls back to create when an operation is absent, and an
// operation whose actions the create check already reports would repeat that
// result. Read and list are not mutation operations and are never checked.
func staticOpsFor(perms map[string][]string) []string {
	create := make(map[string]bool, len(perms["create"]))
	for _, a := range perms["create"] {
		create[a] = true
	}

	var ops []string
	for _, op := range staticMutationOps {
		actions := perms[op]
		if len(actions) == 0 {
			continue
		}
		if op != "create" {
			distinct := false
			for _, a := range actions {
				if !create[a] {
					distinct = true
					break
				}
			}
			if !distinct {
				continue
			}
		}
		ops = append(ops, op)
	}
	return ops
}
