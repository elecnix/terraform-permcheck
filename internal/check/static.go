package check

import (
	"errors"

	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// staticMutationOps are the operations static mode checks, in report order.
var staticMutationOps = []string{"create", "update", "delete"}

// staticChanges turns the parsed HCL blocks into the resource changes worth
// validating. It resolves each type's schema once, picks the operations that
// add a permission the create check does not already cover, and emits one
// entry per block and operation. Each entry carries its own block's
// attributes, so a permission gated on an attribute that only one block of a
// type sets is checked, and reported on that block. Data blocks only read, so
// they are skipped. It returns the changes and the number of distinct
// resource types checked, which is not len(changes).
//
// A type the resolver does not know gets one create entry per block, so
// validation reports every address of it as unresolved. It does not count as
// checked. A failed lookup (iam.ErrLookupFailed) is returned as an error.
func staticChanges(blocks []hcl.ResourceBlock, resolver iam.Resolver) ([]*plan.ResourceChange, int, error) {
	var changes []*plan.ResourceChange
	checked := 0

	opsByType := make(map[string][]string)
	unresolved := make(map[string]bool)
	for _, b := range blocks {
		if b.Mode == "data" {
			continue
		}
		if unresolved[b.Type] {
			changes = append(changes, &plan.ResourceChange{Type: b.Type, Name: b.Name, Change: "create"})
			continue
		}
		ops, seen := opsByType[b.Type]
		if !seen {
			schema, err := resolver.Resolve(b.Type)
			if errors.Is(err, iam.ErrLookupFailed) {
				return nil, 0, err
			}
			if err != nil {
				unresolved[b.Type] = true
				changes = append(changes, &plan.ResourceChange{Type: b.Type, Name: b.Name, Change: "create"})
				continue
			}
			ops = staticOpsFor(schema)
			opsByType[b.Type] = ops
			if len(ops) > 0 {
				checked++
			}
		}
		if len(ops) == 0 {
			continue
		}

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

	return changes, checked, nil
}

// staticOpsFor picks the mutation operations a schema makes worth checking.
// "create" is always worth it when the schema defines it. Another operation is
// worth it only when it carries at least one action the create set does not:
// the validator falls back to create when an operation is absent, and an
// operation whose actions the create check already reports would repeat that
// result. Read and list are not mutation operations and are never checked.
func staticOpsFor(schema *iam.Schema) []string {
	createReqs, _ := schema.Requirements("create")
	create := make(map[string]bool, len(createReqs))
	for _, r := range createReqs {
		create[r.Action] = true
	}

	var ops []string
	for _, op := range staticMutationOps {
		reqs, _ := schema.Requirements(op)
		if len(reqs) == 0 {
			continue
		}
		if op != "create" {
			distinct := false
			for _, r := range reqs {
				if !create[r.Action] {
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
