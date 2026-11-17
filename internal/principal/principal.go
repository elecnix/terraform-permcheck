// Package principal checks the needs of a mapped principal against the
// policies that the plan attaches to it.
//
// The config's principals map gives a need's principal label a role in the
// plan. A need with such a label is a mapped need. It reads its policies
// from the plan, not from the --policy-* document of the run.
package principal

import (
	"fmt"
	"maps"
	"slices"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// Entry is the value of one key of the config's principals map: the role
// that the label stands for. It names the role by its terraform address. A
// later version may let an entry name a role outside the plan by its name or
// ARN, and then an entry sets exactly one of them.
type Entry struct {
	// Address is the terraform instance address of the role, as
	// `terraform show -json` prints it, such as aws_iam_role.task or
	// module.app["eu"].aws_iam_role.task[0].
	Address string `json:"address,omitempty"`
}

// roleType is the resource type a principal's address must have.
const roleType = "aws_iam_role"

// userType is the resource type of an IAM user, which a principal can't be
// yet.
const userType = "aws_iam_user"

// Validate checks the principals map of a config file against its needs.
// Each entry needs the address of an aws_iam_role, and some need must use
// each key as its principal, as an unknown --principal is an error.
func Validate(entries map[string]Entry, needs []iam.Need) error {
	used := map[string]bool{}
	for _, n := range needs {
		used[n.Principal] = true
	}
	for _, label := range slices.Sorted(maps.Keys(entries)) {
		e := entries[label]
		if label == "" {
			return fmt.Errorf("principals: a key must be the principal label of a need, not empty")
		}
		if e.Address == "" {
			return fmt.Errorf("principals[%q]: address is required", label)
		}
		typ, ok := plan.AddressType(e.Address)
		switch {
		case !ok:
			return fmt.Errorf("principals[%q]: address %q is not the terraform address of a resource, such as aws_iam_role.task", label, e.Address)
		case typ == userType:
			return fmt.Errorf("principals[%q]: address %q names an IAM user, and principals supports IAM roles only: users aren't supported yet", label, e.Address)
		case typ != roleType:
			return fmt.Errorf("principals[%q]: address %q has the type %s, and a principal must be an %s", label, e.Address, typ, roleType)
		}
		if !used[label] {
			return fmt.Errorf("principals[%q]: no need has the principal %q", label, label)
		}
	}
	return nil
}

// Find returns the change of the role at address in the plan. A replace has
// a delete and a create at one address, and Find returns the create, whose
// planned state the role has after the apply. It returns an error when the
// plan has no change at address, so a typo does not pass as a principal with
// no policies, and when the plan deletes the role.
func Find(changes []*plan.ResourceChange, label, address string) (*plan.ResourceChange, error) {
	deleted := false
	for _, rc := range changes {
		if rc.Address != address {
			continue
		}
		if rc.Change == "delete" {
			deleted = true
			continue
		}
		return rc, nil
	}
	if deleted {
		return nil, fmt.Errorf("principals[%q]: the plan deletes %s, so it has no policies to check the needs of %q against", label, address, label)
	}
	return nil, fmt.Errorf("principals[%q]: address %s matches no resource change in the plan", label, address)
}
