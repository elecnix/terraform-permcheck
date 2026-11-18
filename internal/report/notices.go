package report

import (
	"fmt"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/principal"
)

// resourcesSkippedNotice is the notice of a run that checked the needs of
// mapped principals only, because it had no --policy-* source.
const resourcesSkippedNotice = "notice: the plan's resources weren't checked, because no --policy-* source was given; only the needs of mapped principals were checked"

// notices renders the notices of a run with mapped principals, one line
// each: first the line of a run without a --policy-* source, then one line
// per policy source whose text is unknown, for each principal whose checked
// needs it may apply to. Principals come in label order and sources in plan
// order. A notice never changes the exit code.
func (r *Report) notices() string {
	var b strings.Builder
	if r.resourcesSkipped {
		b.WriteString(resourcesSkippedNotice + "\n")
	}
	for _, p := range r.principals {
		for _, s := range p.Sources {
			if s.Unknown {
				b.WriteString(sourceNotice(p, s) + "\n")
			}
		}
	}
	return b.String()
}

// sourceNotice says why the text of a policy source of the principal p is
// unknown, and that the needs of p may depend on it. A boundary can only
// limit what the other policies grant, and any other source may grant a
// need. For a managed policy outside the plan, it also gives the fix: a
// data "aws_iam_policy" block with the same arn gives PermCheck the text.
// The implicit source of a role outside the plan gives the exclusive
// resources that make the plan list the kinds of policy it doesn't show.
func sourceNotice(p check.PrincipalSources, s principal.Applied) string {
	label := p.Label
	if len(s.Unlisted) > 0 {
		return outsideRoleNotice(p, s.Unlisted)
	}
	if s.CrossAccount {
		return crossAccountNotice(p, s.Resource)
	}
	if s.ResourceOutside {
		return outsideKeyNotice(p, s.Resource)
	}
	if s.OutsideGroup {
		return outsideGroupNotice(p, s)
	}
	var why, fix string
	switch unknownReason(s) {
	case reasonOutsidePlan:
		if s.PolicyName != "" {
			why = "the plan doesn't define the inline policy " + s.PolicyName + " that the list names"
			break
		}
		why = s.PolicyARN + " is a managed policy that the plan doesn't contain"
		if s.PolicyMaybe {
			why = s.PolicyARN + " may be a managed policy that the plan doesn't contain"
		}
		if !s.Unread {
			fix = `; a data "aws_iam_policy" block with this arn gives PermCheck its text`
		}
	case reasonUnread:
		why = fmt.Sprintf("this version doesn't read the %s attribute of %s yet", s.Path, resourceType(s.Address))
	default:
		why = "policy text is known only after apply"
		if s.Path == "policy_names" {
			why = "the names of the inline policies are known only after apply"
		}
		if s.Policy != "" {
			why = "the text of " + s.Policy + " is known only after apply"
		}
	}
	effect := "granted"
	if s.Kind == plan.KindBoundary {
		effect = "limited"
	}
	return fmt.Sprintf("notice: %s: %s; needs of %q may be %s by it%s", s.Address, why, label, effect, fix)
}

// The exclusive resources that make the plan list one kind of policy of a
// role, by the kind (see principal.Applied.Unlisted).
var exclusiveFix = map[string]string{
	principal.UnlistedInline:  "aws_iam_role_policies_exclusive",
	principal.UnlistedManaged: "aws_iam_role_policy_attachments_exclusive",
}

// The exclusive resources that make the plan list one kind of policy of a
// user, by the kind.
var userExclusiveFix = map[string]string{
	principal.UnlistedInline:  "aws_iam_user_policies_exclusive",
	principal.UnlistedManaged: "aws_iam_user_policy_attachments_exclusive",
}

// outsideRoleNotice is the notice of the implicit source of a role or user
// outside the plan: other stacks may attach policies of the unlisted kinds
// to it, and may add a user to groups. No resource makes the plan list a
// user's groups, so the fix names the exclusive resources of the other
// kinds only. For a principal that its entry gives by ARN, the fix also says
// to give it by name.
func outsideRoleNotice(p check.PrincipalSources, unlisted []string) string {
	who := p.Name
	if p.ARN != "" {
		who = p.ARN
	}
	kind, fixes := "role", exclusiveFix
	if p.User {
		kind, fixes = "user", userExclusiveFix
	}
	var attached []string
	groups := false
	for _, k := range unlisted {
		if k == principal.UnlistedGroups {
			groups = true
		} else {
			attached = append(attached, k)
		}
	}
	var may []string
	if len(attached) > 0 {
		may = append(may, "attach "+strings.Join(attached, " and ")+" policies to it")
	}
	if groups {
		may = append(may, "add it to groups")
	}
	line := fmt.Sprintf("notice: %s %s is outside the plan, and other stacks may %s; needs of %q may be granted by them",
		kind, who, strings.Join(may, " or "), p.Label)
	if len(attached) == 0 {
		return line
	}
	names := make([]string, len(attached))
	for i, k := range attached {
		names[i] = "an " + fixes[k]
	}
	verb := "makes"
	if len(names) > 1 {
		verb = "make"
	}
	if p.ARN != "" {
		// The exclusive resources name the principal by its name, which
		// the provider resolves in an account the plan doesn't show, so
		// they don't count for an arn entry (see
		// plan.PolicyLink.MatchOutside).
		return fmt.Sprintf("%s; with a \"name\" entry instead of \"arn\", %s for the %s %s the plan list every policy of that kind, since the plan doesn't show the account that a name resolves in", line, strings.Join(names, " and "), kind, verb)
	}
	return fmt.Sprintf("%s; %s for the %s %s the plan list every policy of that kind", line, strings.Join(names, " and "), kind, verb)
}

// outsideGroupNotice is the notice of a group that a membership may put the
// user in, and whose policies the plan doesn't show.
func outsideGroupNotice(p check.PrincipalSources, s principal.Applied) string {
	if s.Group == "" {
		return fmt.Sprintf("notice: %s: the name of a group is known only after apply, and the group may be outside the plan, so the plan may not show its policies; needs of %q may be granted by them", s.Address, p.Label)
	}
	return fmt.Sprintf("notice: %s: group %s isn't in the plan, so the plan doesn't show its policies; needs of %q may be granted by them", s.Address, s.Group, p.Label)
}

// outsideKeyNotice is the notice of the implicit source of a KMS key outside
// the plan: its key policy decides the needs on the key, and the plan
// doesn't show it. resource is the need's resource, or empty for a need
// without resources.
func outsideKeyNotice(p check.PrincipalSources, resource string) string {
	if resource == "" {
		return fmt.Sprintf("notice: a need of %q without resources may act on a KMS key outside the plan, whose key policy is unknown; needs of %q may be granted by it", p.Label, p.Label)
	}
	return fmt.Sprintf("notice: KMS key %s isn't in the plan, so its key policy is unknown; needs of %q may be granted by it", resource, p.Label)
}

// crossAccountNotice is the notice of the implicit source of a resource in
// another account than the principal's, whose resource policy the plan
// doesn't show. Across accounts that policy must allow the needs on the
// resource too.
func crossAccountNotice(p check.PrincipalSources, resource string) string {
	return fmt.Sprintf("notice: %s is outside the account of %q, and its resource policy isn't in the plan; needs of %q on it depend on that policy", resource, p.Label, p.Label)
}

// resourceType returns the resource type of a terraform address, or the
// address itself when it has another form.
func resourceType(address string) string {
	if t, ok := plan.AddressType(address); ok {
		return t
	}
	return address
}

// The reasons a policy source's text is unknown, as the json report names
// them.
const (
	reasonComputed    = "computed"
	reasonUnread      = "unread"
	reasonOutsidePlan = "outside_plan"
	// reasonAttachedOutside is the reason of the implicit source of a role
	// outside the plan.
	reasonAttachedOutside = "attached_outside_plan"
	// reasonCrossAccount is the reason of the implicit source of a resource
	// in another account than the principal's.
	reasonCrossAccount = "cross_account"
)

// unknownReason says why the text of a policy source is unknown. A managed
// policy outside the plan says the most, since reading the source's type
// would not show its text. It is empty for a source whose text is known.
func unknownReason(s principal.Applied) string {
	switch {
	case !s.Unknown:
		return ""
	case len(s.Unlisted) > 0:
		return reasonAttachedOutside
	case s.CrossAccount:
		return reasonCrossAccount
	case s.OutsidePlan:
		return reasonOutsidePlan
	case s.Unread:
		return reasonUnread
	default:
		return reasonComputed
	}
}
