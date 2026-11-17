package report

import (
	"fmt"
	"strings"

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
				b.WriteString(sourceNotice(p.Label, s) + "\n")
			}
		}
	}
	return b.String()
}

// sourceNotice says why the text of a policy source is unknown, and that the
// needs of the principal may depend on it. A boundary can only limit what
// the other policies grant, and any other source may grant a need.
func sourceNotice(label string, s principal.Applied) string {
	var why string
	switch unknownReason(s) {
	case reasonOutsidePlan:
		why = s.PolicyARN + " is a managed policy that the plan doesn't contain"
	case reasonUnread:
		why = fmt.Sprintf("this version doesn't read the %s attribute of %s yet", s.Path, resourceType(s.Address))
	default:
		why = "policy text is known only after apply"
	}
	effect := "granted"
	if s.Kind == plan.KindBoundary {
		effect = "limited"
	}
	return fmt.Sprintf("notice: %s: %s; needs of %q may be %s by it", s.Address, why, label, effect)
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
)

// unknownReason says why the text of a policy source is unknown. A managed
// policy outside the plan says the most, since reading the source's type
// would not show its text. It is empty for a source whose text is known.
func unknownReason(s principal.Applied) string {
	switch {
	case !s.Unknown:
		return ""
	case s.OutsidePlan:
		return reasonOutsidePlan
	case s.Unread:
		return reasonUnread
	default:
		return reasonComputed
	}
}
