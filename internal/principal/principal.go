// Package principal checks the needs of a mapped principal against the
// policies that the plan attaches to it.
//
// The config's principals map gives a need's principal label a role, by its
// address in the plan, or by its name or ARN for a role outside the plan. A
// need with such a label is a mapped need. It reads its policies from the
// plan, not from the --policy-* document of the run.
package principal

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// Entry is the value of one key of the config's principals map: the role
// that the label stands for. An entry sets exactly one of Address, Name and
// ARN. Address names a role that the plan creates or keeps. Name and ARN
// name a role outside the plan.
type Entry struct {
	// Address is the terraform instance address of the role, as
	// `terraform show -json` prints it, such as aws_iam_role.task or
	// module.app["eu"].aws_iam_role.task[0].
	Address string `json:"address,omitempty"`
	// Name is the name of a role that the plan doesn't contain, such as
	// ops-admin.
	Name string `json:"name,omitempty"`
	// ARN is the ARN of a role that the plan doesn't contain, such as
	// arn:aws:iam::123456789012:role/ops-admin.
	ARN string `json:"arn,omitempty"`
}

// Outside returns the role outside the plan that a name or arn entry gives.
// A role known by its ARN has the last part of the ARN's path as its name.
func (e Entry) Outside() plan.OutsideRole {
	if e.ARN != "" {
		return plan.OutsideRole{Name: e.ARN[strings.LastIndex(e.ARN, "/")+1:], ARN: e.ARN}
	}
	return plan.OutsideRole{Name: e.Name}
}

// roleType is the resource type a principal's address must have.
const roleType = "aws_iam_role"

// userType is the resource type of an IAM user, which a principal can't be
// yet.
const userType = "aws_iam_user"

// Validate checks the principals map of a config file against its needs.
// Each entry sets exactly one of the address of an aws_iam_role, the name of
// a role, and the ARN of a role, and some need must use each key as its
// principal, as an unknown --principal is an error.
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
		if err := validateEntry(label, e); err != nil {
			return err
		}
		if !used[label] {
			return fmt.Errorf("principals[%q]: no need has the principal %q", label, label)
		}
	}
	return nil
}

// validateEntry checks one entry of the principals map.
func validateEntry(label string, e Entry) error {
	set := 0
	for _, v := range []string{e.Address, e.Name, e.ARN} {
		if v != "" {
			set++
		}
	}
	switch {
	case set == 0:
		return fmt.Errorf("principals[%q]: address is required, or name or arn for a role outside the plan", label)
	case set > 1:
		return fmt.Errorf("principals[%q]: set only one of address, name and arn", label)
	case e.Name != "":
		return validateName(label, e.Name)
	case e.ARN != "":
		return validateARN(label, e.ARN)
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
	return nil
}

// validateName checks the role name of an entry. A name gives one role, so
// it can't hold a wildcard, and it has no path.
func validateName(label, name string) error {
	switch {
	case strings.HasPrefix(name, "arn:"):
		return fmt.Errorf("principals[%q]: name %q is an ARN: set it as arn", label, name)
	case strings.ContainsAny(name, "*?"):
		return fmt.Errorf("principals[%q]: name %q has a wildcard, and an entry gives one role", label, name)
	case strings.Contains(name, "/"):
		return fmt.Errorf("principals[%q]: name %q has a path: give the role's name alone, or its arn", label, name)
	}
	return nil
}

// validateARN checks the role ARN of an entry: arn:PARTITION:iam::ACCOUNT:role/NAME,
// with an optional path before the name
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns).
func validateARN(label, arn string) error {
	if strings.ContainsAny(arn, "*?") {
		return fmt.Errorf("principals[%q]: arn %q has a wildcard, and an entry gives one role", label, arn)
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && parts[1] != "" && parts[2] == "iam" && parts[3] == "" && parts[4] != "" {
		resource := parts[5]
		switch {
		case strings.HasPrefix(resource, "user/"):
			return fmt.Errorf("principals[%q]: arn %q names an IAM user, and principals supports IAM roles only: users aren't supported yet", label, arn)
		case strings.HasPrefix(resource, "role/") && !strings.HasSuffix(resource, "/"):
			return nil
		}
	}
	return fmt.Errorf("principals[%q]: arn %q is not the ARN of an IAM role, such as arn:aws:iam::123456789012:role/ops-admin", label, arn)
}

// FindOutside checks that the role a name or arn entry gives is outside the
// plan. A role of the plan has one way to be named, its address, so FindOutside
// returns an error that gives the address when a role change of the plan has
// the entry's known ARN, or the entry's known name. A role of the plan whose
// known ARN differs from the entry's ARN is another role, in another account
// or with another path.
func FindOutside(changes []*plan.ResourceChange, label string, e Entry) error {
	r := e.Outside()
	for _, rc := range changes {
		if rc.Type != roleType {
			continue
		}
		arn, name := rc.AttributeValues["arn"], rc.AttributeValues["name"]
		if name == "" && arn != "" {
			name = arn[strings.LastIndex(arn, "/")+1:]
		}
		same := false
		switch {
		case r.ARN != "" && arn != "":
			same = strings.EqualFold(arn, r.ARN)
		default:
			same = name != "" && strings.EqualFold(name, r.Name)
		}
		if same {
			given := `"name": ` + fmt.Sprintf("%q", e.Name)
			if e.ARN != "" {
				given = `"arn": ` + fmt.Sprintf("%q", e.ARN)
			}
			return fmt.Errorf("principals[%q]: the role of %s is in the plan as %s: map it with \"address\": %q", label, given, rc.Address, rc.Address)
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
