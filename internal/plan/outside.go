package plan

import (
	"strconv"
	"strings"
)

// roleType is the resource type of an IAM role.
const roleType = "aws_iam_role"

// The resource types of the inline policies of a role, a user and a group.
const (
	rolePolicyType  = "aws_iam_role_policy"
	userPolicyType  = "aws_iam_user_policy"
	groupPolicyType = "aws_iam_group_policy"
)

// userType is the resource type of an IAM user.
const userType = "aws_iam_user"

// groupType is the resource type of an IAM group.
const groupType = "aws_iam_group"

// OutsidePrincipal is an IAM role or user that the plan doesn't contain,
// known by the name or ARN that the config gives it. Package plan also uses
// it for an IAM group that the plan names but doesn't contain (see Groups).
type OutsidePrincipal struct {
	// Type is the resource type of the principal: aws_iam_role,
	// aws_iam_user, or aws_iam_group.
	Type string
	// Name is the principal's name, without its path. A principal known by
	// its ARN has the last part of the ARN's path as its name. It is empty
	// for a group whose name the plan doesn't know.
	Name string
	// ARN is the principal's ARN, such as
	// arn:aws:iam::123456789012:role/ops-admin. It is empty for a principal
	// known by its name only.
	ARN string
}

// MatchOutside reports whether the link points to r, which the plan doesn't
// contain. A link that references only resources of r's type in the plan
// points to another principal, unless it is a list whose values are all
// known. Otherwise the known value of the link
// attribute decides: a name equal to r's name gives LinkYes, or LinkMaybe
// when r is known by its ARN (see matchOutsideValue), and another name gives
// LinkNo. An unknown value gives LinkMaybe.
//
// IAM role, user and group names are unique without regard to case
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-names),
// so the comparison folds case.
func (l PolicyLink) MatchOutside(r OutsidePrincipal) LinkMatch {
	if l.Type != r.Type || l.Self != "" {
		return LinkNo
	}
	var inPlan, opaque bool
	for _, ref := range l.References {
		typ, _, _, ok := parseResourceRef(ref)
		switch {
		case !ok && (strings.HasPrefix(ref, "count.index") || strings.HasPrefix(ref, "each.key")):
		case ok && typ == r.Type:
			inPlan = true
		default:
			// A variable, a data source or another resource's attribute
			// may hold any principal's name.
			opaque = true
		}
	}
	// A list whose values are all known may mix references with constants,
	// so its known values decide.
	if inPlan && !opaque && l.Values == nil {
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

// matchOutsideValue compares one known value of a link attribute with r. An
// ARN compares with r's ARN. When r is known by its name only, an ARN with
// the same name may name it in another account.
//
// A name compares with r's name. The provider resolves a name in the account
// of its credentials, which the plan doesn't show. So when r is known by its
// ARN, the same name may name a role or user of another account, and the
// link is LinkMaybe. When r is known by its name only, its account is the
// one the plan runs in, and the same name gives LinkYes.
func matchOutsideValue(value string, r OutsidePrincipal) LinkMatch {
	switch {
	case value == "":
		return LinkMaybe
	case !strings.HasPrefix(value, "arn:"):
		switch {
		case !strings.EqualFold(value, r.Name):
			return LinkNo
		case r.ARN != "":
			return LinkMaybe
		}
		return LinkYes
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

// ExclusiveKind says which policies of a role, user or group an exclusive
// resource lists.
type ExclusiveKind string

const (
	// ExclusiveInline is an aws_iam_role_policies_exclusive, an
	// aws_iam_user_policies_exclusive or an aws_iam_group_policies_exclusive,
	// which lists the names of the inline policies.
	ExclusiveInline ExclusiveKind = "inline"
	// ExclusiveManaged is an aws_iam_role_policy_attachments_exclusive, an
	// aws_iam_user_policy_attachments_exclusive or an
	// aws_iam_group_policy_attachments_exclusive, which lists the ARNs of the
	// attached managed policies.
	ExclusiveManaged ExclusiveKind = "managed"
)

// exclusiveType says how one exclusive resource type lists policies: its
// kind, the attribute of its list, the attribute and type of its link, and
// the resource type of the inline policies it names.
type exclusiveType struct {
	kind       ExclusiveKind
	attr       string
	linkAttr   string
	target     string
	inlineType string
}

// exclusiveTypes maps each exclusive resource type to how it lists policies.
// The provider has the user and group types at both major versions that
// PermCheck parses (v5.100.0 and v6.72.0).
var exclusiveTypes = map[string]exclusiveType{
	"aws_iam_role_policies_exclusive":            {ExclusiveInline, "policy_names", "role_name", roleType, rolePolicyType},
	"aws_iam_role_policy_attachments_exclusive":  {ExclusiveManaged, "policy_arns", "role_name", roleType, rolePolicyType},
	"aws_iam_user_policies_exclusive":            {ExclusiveInline, "policy_names", "user_name", userType, userPolicyType},
	"aws_iam_user_policy_attachments_exclusive":  {ExclusiveManaged, "policy_arns", "user_name", userType, userPolicyType},
	"aws_iam_group_policies_exclusive":           {ExclusiveInline, "policy_names", "group_name", groupType, groupPolicyType},
	"aws_iam_group_policy_attachments_exclusive": {ExclusiveManaged, "policy_arns", "group_name", groupType, groupPolicyType},
}

// Exclusive is a resource that lists every policy of one kind that a role, a
// user or a group has after the apply. The provider removes any policy of
// that kind that the list omits
// (https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policies_exclusive,
// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachments_exclusive,
// and the pages of the user and group resources of the same names).
type Exclusive struct {
	// Address is the terraform address of the exclusive resource.
	Address string
	// Kind says which policies the list names.
	Kind ExclusiveKind
	// Attribute is the attribute of the list: policy_names or policy_arns.
	Attribute string
	// InlineType is the resource type of the inline policies of the
	// resource's role, user or group, such as aws_iam_role_policy.
	InlineType string
	// Link ties the resource to its role, user or group, through role_name,
	// user_name or group_name.
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
// delete adds none, since destroying an exclusive resource leaves the
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
			InlineType: t.inlineType,
			Link:       attributeLink(t.linkAttr, t.target)(rc),
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

// ListsInline reports whether the list of an exclusive resource of inline
// policies provably names the inline policy of the source s: the list holds the
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
