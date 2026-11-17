package plan

import (
	"strconv"
	"strings"
)

// roleType is the resource type of an IAM role.
const roleType = "aws_iam_role"

// rolePolicyType is the resource type of an inline policy of a role.
const rolePolicyType = "aws_iam_role_policy"

// OutsideRole is an IAM role that the plan doesn't contain, known by the
// name or ARN that the config gives it.
type OutsideRole struct {
	// Name is the role's name, without its path. A role known by its ARN
	// has the last part of the ARN's path as its name.
	Name string
	// ARN is the role's ARN, such as arn:aws:iam::123456789012:role/ops-admin.
	// It is empty for a role known by its name only.
	ARN string
}

// MatchOutside reports whether the link points to the role r, which the plan
// doesn't contain. A link that references only roles of the plan points to
// another role. Otherwise the known value of the link attribute decides: a
// name equal to the role's name gives LinkYes, and another name gives
// LinkNo. An unknown value gives LinkMaybe.
//
// IAM role names are unique without regard to case
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-names),
// so the comparison folds case.
func (l PolicyLink) MatchOutside(r OutsideRole) LinkMatch {
	if l.Type != roleType || l.Self != "" {
		return LinkNo
	}
	var role, opaque bool
	for _, ref := range l.References {
		typ, _, _, ok := parseResourceRef(ref)
		switch {
		case !ok && (strings.HasPrefix(ref, "count.index") || strings.HasPrefix(ref, "each.key")):
		case ok && typ == roleType:
			role = true
		default:
			// A variable, a data source or another resource's attribute
			// may hold any role's name.
			opaque = true
		}
	}
	if role && !opaque {
		return LinkNo
	}
	if l.Values != nil {
		out := LinkNo
		for _, v := range l.Values {
			switch matchOutsideValue(v, r) {
			case LinkYes:
				return LinkYes
			case LinkMaybe:
				out = LinkMaybe
			}
		}
		return out
	}
	return matchOutsideValue(l.Value, r)
}

// matchOutsideValue compares one known value of a link attribute with the
// role r. An ARN compares with the role's ARN. When the role is known by its
// name only, an ARN with the same name may name it in another account.
func matchOutsideValue(value string, r OutsideRole) LinkMatch {
	switch {
	case value == "":
		return LinkMaybe
	case !strings.HasPrefix(value, "arn:"):
		if strings.EqualFold(value, r.Name) {
			return LinkYes
		}
		return LinkNo
	case r.ARN != "":
		if strings.EqualFold(value, r.ARN) {
			return LinkYes
		}
		return LinkNo
	case strings.EqualFold(value[strings.LastIndex(value, "/")+1:], r.Name):
		return LinkMaybe
	default:
		return LinkNo
	}
}

// ExclusiveKind says which policies of a role an exclusive resource lists.
type ExclusiveKind string

const (
	// ExclusiveInline is an aws_iam_role_policies_exclusive, which lists the
	// names of the role's inline policies.
	ExclusiveInline ExclusiveKind = "inline"
	// ExclusiveManaged is an aws_iam_role_policy_attachments_exclusive,
	// which lists the ARNs of the managed policies attached to the role.
	ExclusiveManaged ExclusiveKind = "managed"
)

// exclusiveTypes maps each exclusive resource type to its kind and to the
// attribute of its list.
var exclusiveTypes = map[string]struct {
	kind ExclusiveKind
	attr string
}{
	"aws_iam_role_policies_exclusive":           {ExclusiveInline, "policy_names"},
	"aws_iam_role_policy_attachments_exclusive": {ExclusiveManaged, "policy_arns"},
}

// Exclusive is a resource that lists every policy of one kind that a role
// has after the apply. The provider removes any policy of that kind that the
// list omits
// (https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policies_exclusive,
// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachments_exclusive).
type Exclusive struct {
	// Address is the terraform address of the exclusive resource.
	Address string
	// Kind says which policies the list names.
	Kind ExclusiveKind
	// Attribute is the attribute of the list: policy_names or policy_arns.
	Attribute string
	// Link ties the resource to its role, through role_name.
	Link PolicyLink
	// Computed is true when terraform computes the whole list at apply
	// time.
	Computed bool
	// Entries are the entries of the list in order: policy names or policy
	// ARNs. An entry that terraform computes at apply time is empty. It is
	// nil when Computed is true.
	Entries []string
	// References are the references of the list attribute, from the plan's
	// configuration section.
	References []string
}

// Exclusives returns the exclusive resources of the plan, in plan order. A
// delete adds none, since destroying an exclusive resource leaves the role's
// policies as they are.
func Exclusives(changes []*ResourceChange) []Exclusive {
	var out []Exclusive
	for _, rc := range changes {
		t, ok := exclusiveTypes[rc.Type]
		if !ok || rc.Change == "delete" {
			continue
		}
		ex := Exclusive{
			Address:    rc.Address,
			Kind:       t.kind,
			Attribute:  t.attr,
			Link:       attributeLink("role_name", roleType)(rc),
			References: rc.References[t.attr],
		}
		if rc.paths == nil || unknownAlong(rc.paths.unknown, t.attr) {
			ex.Computed = true
		} else {
			list, _ := walk(rc.paths.state, t.attr)
			items, _ := list.([]any)
			ex.Entries = make([]string, len(items))
			for i, item := range items {
				if unknownAlong(rc.paths.unknown, t.attr+"."+strconv.Itoa(i)) {
					continue
				}
				ex.Entries[i], _ = item.(string)
			}
		}
		out = append(out, ex)
	}
	return out
}

// EntriesFromPlan reports whether each entry of the list that terraform
// computes at apply time comes from a resource of the given type in the
// plan, such as the name of an aws_iam_role_policy. It is true when the
// list's references name resources of that type only.
func (e Exclusive) EntriesFromPlan(typ string) bool {
	found := false
	for _, ref := range e.References {
		t, _, _, ok := parseResourceRef(ref)
		switch {
		case !ok && (strings.HasPrefix(ref, "count.index") || strings.HasPrefix(ref, "each.key")):
		case ok && t == typ:
			found = true
		default:
			return false
		}
	}
	return found
}

// ListsInline reports whether the list of an aws_iam_role_policies_exclusive
// provably names the inline policy of the source s: the list holds the
// source's known policy name, or it references the source's resource.
func (e Exclusive) ListsInline(s PolicySource) bool {
	if e.Kind != ExclusiveInline {
		return false
	}
	if s.PolicyName != "" {
		for _, n := range e.Entries {
			if n == s.PolicyName {
				return true
			}
		}
	}
	return e.references(s.Address)
}

// references reports whether a reference of the list names the resource at
// address, or every instance of it.
func (e Exclusive) references(address string) bool {
	prefix := ""
	if e.Link.Module != "" {
		prefix = e.Link.Module + "."
	}
	for _, ref := range e.References {
		typ, name, key, ok := parseResourceRef(ref)
		if !ok {
			continue
		}
		base := prefix + typ + "." + name
		if address == base+key {
			return true
		}
		if key == "" && strings.HasPrefix(address, base+"[") {
			return true
		}
	}
	return false
}
