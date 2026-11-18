// Package principal checks the needs of a mapped principal against the
// policies that the plan attaches to it.
//
// The config's principals map gives a need's principal label an IAM role or
// user, by its address in the plan, or by its name or ARN for a principal
// outside the plan. A need with such a label is a mapped need. It reads its
// policies from the plan, not from the --policy-* document of the run.
package principal

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// Entry is the value of one key of the config's principals map: the role or
// user that the label stands for. An entry sets exactly one of Address, Name
// and ARN. Address gives a role or user that the plan creates or keeps. Name
// and ARN give a role or user outside the plan.
type Entry struct {
	// Address is the terraform instance address of the role or user, as
	// `terraform show -json` prints it, such as aws_iam_role.task or
	// module.app["eu"].aws_iam_user.ci[0].
	Address string `json:"address,omitempty"`
	// Name is the name of a role or user that the plan doesn't contain, such
	// as ops-admin.
	Name string `json:"name,omitempty"`
	// ARN is the ARN of a role or user that the plan doesn't contain, such as
	// arn:aws:iam::123456789012:role/ops-admin or
	// arn:aws:iam::123456789012:user/ci.
	ARN string `json:"arn,omitempty"`
	// Type is "role" or "user". A name entry needs it for a user, since a
	// name alone doesn't say which kind of principal it is, and it is a role
	// when Type is empty. An address or an ARN already gives the kind, and a
	// Type that differs from it is an error.
	Type string `json:"type,omitempty"`
}

// The values of Entry.Type.
const (
	TypeRole = "role"
	TypeUser = "user"
)

// User reports whether the entry gives an IAM user.
func (e Entry) User() bool {
	return e.kind() == TypeUser
}

// kind returns the kind of principal the entry gives: TypeRole or TypeUser.
func (e Entry) kind() string {
	switch {
	case e.Address != "":
		if typ, _ := plan.AddressType(e.Address); typ == userType {
			return TypeUser
		}
		return TypeRole
	case e.ARN != "":
		if parts := strings.SplitN(e.ARN, ":", 6); len(parts) == 6 && strings.HasPrefix(parts[5], "user/") {
			return TypeUser
		}
		return TypeRole
	case e.Type == TypeUser:
		return TypeUser
	}
	return TypeRole
}

// resourceType returns the resource type of the principal the entry gives:
// aws_iam_role or aws_iam_user.
func (e Entry) resourceType() string {
	if e.kind() == TypeUser {
		return userType
	}
	return roleType
}

// Outside returns the role or user outside the plan that a name or arn entry
// gives. A principal known by its ARN has the last part of the ARN's path as
// its name.
func (e Entry) Outside() plan.OutsidePrincipal {
	if e.ARN != "" {
		return plan.OutsidePrincipal{Type: e.resourceType(), Name: e.ARN[strings.LastIndex(e.ARN, "/")+1:], ARN: e.ARN}
	}
	return plan.OutsidePrincipal{Type: e.resourceType(), Name: e.Name}
}

// roleType is the resource type of an IAM role.
const roleType = "aws_iam_role"

// userType is the resource type of an IAM user.
const userType = "aws_iam_user"

// groupType is the resource type of an IAM group.
const groupType = "aws_iam_group"

// Validate checks the principals map of a config file against its needs.
// Each entry sets exactly one of the address of an aws_iam_role or
// aws_iam_user, the name of a role or user, and the ARN of a role or user,
// and some need must use each key as its principal, as an unknown
// --principal is an error.
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
		return fmt.Errorf("principals[%q]: address is required, or name or arn for a role or user outside the plan", label)
	case set > 1:
		return fmt.Errorf("principals[%q]: set only one of address, name and arn", label)
	case e.Type != "" && e.Type != TypeRole && e.Type != TypeUser:
		return fmt.Errorf("principals[%q]: type %q must be %q or %q", label, e.Type, TypeRole, TypeUser)
	case e.Name != "":
		return validateName(label, e.Name)
	case e.ARN != "":
		if err := validateARN(label, e.ARN); err != nil {
			return err
		}
		return validateType(label, e, "arn", e.ARN)
	}
	typ, ok := plan.AddressType(e.Address)
	switch {
	case !ok:
		return fmt.Errorf("principals[%q]: address %q is not the terraform address of a resource, such as aws_iam_role.task", label, e.Address)
	case typ != roleType && typ != userType:
		return fmt.Errorf("principals[%q]: address %q has the type %s, and a principal must be an %s or an %s", label, e.Address, typ, roleType, userType)
	}
	return validateType(label, e, "address", e.Address)
}

// validateType checks that the type of an address or arn entry, when the
// entry sets one, is the kind of principal the address or ARN gives.
func validateType(label string, e Entry, key, value string) error {
	if e.Type != "" && e.Type != e.kind() {
		return fmt.Errorf("principals[%q]: %s %q gives an IAM %s, and type is %q: drop type, or set it to %q", label, key, value, e.kind(), e.Type, e.kind())
	}
	return nil
}

// validateName checks the name of an entry. A name gives one role or user,
// so it can't hold a wildcard, and it has no path.
func validateName(label, name string) error {
	switch {
	case strings.HasPrefix(name, "arn:"):
		return fmt.Errorf("principals[%q]: name %q is an ARN: set it as arn", label, name)
	case strings.ContainsAny(name, "*?"):
		return fmt.Errorf("principals[%q]: name %q has a wildcard, and an entry gives one role or user", label, name)
	case strings.Contains(name, "/"):
		return fmt.Errorf("principals[%q]: name %q has a path: give the name alone, or the arn", label, name)
	}
	return nil
}

// validateARN checks the ARN of an entry: arn:PARTITION:iam::ACCOUNT:role/NAME
// or arn:PARTITION:iam::ACCOUNT:user/NAME, with an optional path before the
// name
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns).
func validateARN(label, arn string) error {
	if strings.ContainsAny(arn, "*?") {
		return fmt.Errorf("principals[%q]: arn %q has a wildcard, and an entry gives one role or user", label, arn)
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && parts[1] != "" && parts[2] == "iam" && parts[3] == "" && parts[4] != "" {
		resource := parts[5]
		if (strings.HasPrefix(resource, "role/") || strings.HasPrefix(resource, "user/")) && !strings.HasSuffix(resource, "/") {
			return nil
		}
	}
	return fmt.Errorf("principals[%q]: arn %q is not the ARN of an IAM role or user, such as arn:aws:iam::123456789012:role/ops-admin", label, arn)
}

// FindOutside checks that the role or user a name or arn entry gives is
// outside the plan. A principal of the plan has one way to be named, its
// address, so FindOutside returns an error that gives the address when a
// change of the plan of the entry's type has the entry's known ARN, or the
// entry's known name. A principal of the plan whose known ARN differs from
// the entry's ARN is another one, in another account or with another path.
func FindOutside(changes []*plan.ResourceChange, label string, e Entry) error {
	r := e.Outside()
	for _, rc := range changes {
		if rc.Type != r.Type {
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
			return fmt.Errorf("principals[%q]: the %s of %s is in the plan as %s: map it with \"address\": %q", label, e.kind(), given, rc.Address, rc.Address)
		}
	}
	return nil
}

// Find returns the change of the role or user at address in the plan. A
// replace has a delete and a create at one address, and Find returns the
// create, whose planned state the principal has after the apply. It returns
// an error when the plan has no change at address, so a typo does not pass
// as a principal with no policies, and when the plan deletes the principal.
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
