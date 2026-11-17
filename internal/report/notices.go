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

// outsideRoleNotice is the notice of the implicit source of a role outside
// the plan: other stacks may attach policies of the unlisted kinds to it.
func outsideRoleNotice(p check.PrincipalSources, unlisted []string) string {
	role := p.Name
	if p.ARN != "" {
		role = p.ARN
	}
	kinds := strings.Join(unlisted, " and ")
	fixes := make([]string, len(unlisted))
	for i, k := range unlisted {
		fixes[i] = "an " + exclusiveFix[k]
	}
	verb := "makes"
	if len(fixes) > 1 {
		verb = "make"
	}
	return fmt.Sprintf("notice: role %s is outside the plan, and other stacks may attach %s policies to it; needs of %q may be granted by them; %s for the role %s the plan list every policy of that kind",
		role, kinds, p.Label, strings.Join(fixes, " and "), verb)
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
	case s.OutsidePlan:
		return reasonOutsidePlan
	case s.Unread:
		return reasonUnread
	default:
		return reasonComputed
	}
}
