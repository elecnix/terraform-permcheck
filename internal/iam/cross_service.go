package iam

import (
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// crossServiceMissing returns the cross-service callback actions required by a
// resource change but not covered by the policy.
//
// When the target ARN value is known, only the callback for that ARN's service
// is returned, as an unconditional [required] action. When the target is
// unknown — the ARN is computed at apply time (the common case when it
// references a resource created in the same plan) or in static HCL mode where
// attribute values aren't available — every candidate callback is returned,
// gated on the ARN attribute so the over-approximation can be suppressed with
// --only-required.
//
// The callback acts on the target resource, so a known target ARN scopes the
// coverage check. With strict set and the target unknown, a callback the
// policy grants only on some resources is returned as unverified.
func crossServiceMissing(rc *plan.ResourceChange, policy *PolicyDocument, strict bool) []MissingAction {
	rule, ok := crossServiceRules[rc.Type]
	if !ok {
		return nil
	}

	targetARN := rc.AttributeValues[rule.arnAttribute]
	targetService := arnService(targetARN)
	var targets []string
	if isARN(targetARN) {
		targets = []string{targetARN}
	}

	var missing []MissingAction
	for _, cb := range rule.callbacks {
		if targetService != "" && cb.targetService != targetService {
			continue
		}
		verdict := policy.Coverage(cb.action, targets, strict)
		if verdict == Covered {
			continue
		}
		condAttr := ""
		if targetService == "" {
			// Target unknown: this candidate is one of several possibilities,
			// gated on what resource_arn ultimately points to.
			condAttr = rule.arnAttribute
		}
		missing = append(missing, MissingAction{
			ResourceType:       rc.Type,
			ResourceName:       rc.Name,
			Change:             rc.Change,
			Action:             cb.action,
			Service:            actionService(cb.action),
			Class:              classTag(ClassManagement),
			ConditionAttribute: condAttr,

			ResourceScopeUnverified: verdict == Unverified,
		})
	}
	return missing
}

// arnService extracts the service prefix from an AWS ARN
// (arn:partition:service:region:account:resource). Returns "" when the string
// is empty or not a well-formed ARN.
func arnService(arn string) string {
	if arn == "" {
		return ""
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 3 || parts[0] != "arn" || parts[2] == "" {
		return ""
	}
	return parts[2]
}
