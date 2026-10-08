package iam

import (
	"slices"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// crossServiceMissing returns the cross-service callback actions required by a
// resource change but not covered by the policy.
//
// When the target's service is known, only the callback for that service is
// returned, as an unconditional [required] action. The service is known when
// the target ARN value is known, or when the configuration references a
// resource of a type the rule knows, such as an aws_lb whose ARN AWS assigns
// at apply time. The target is unknown when the attribute references a
// variable, a module output or a resource of a type the rule does not list,
// and in static HCL mode, which shows no values. Then every candidate
// callback is returned, gated on the ARN attribute, and --only-required drops
// the over-approximation.
//
// The callback acts on the target resource, so a known target ARN scopes the
// coverage check. With strict set and the target unknown, a callback the
// policy grants only on some resources is returned as unverified.
func crossServiceMissing(rc *plan.ResourceChange, policy *PolicyDocument, set *changeSet, strict bool) []MissingAction {
	rule, ok := crossServiceRules[rc.Type]
	if !ok {
		return nil
	}

	services, targets := rule.target(rc, set)

	var missing []MissingAction
	for _, cb := range rule.callbacks {
		if len(services) > 0 && !services[cb.targetService] {
			continue
		}
		verdict := policy.worstVerdict(cb.action, targets, strict)
		if verdict == Covered {
			continue
		}
		condAttr := ""
		if len(services) != 1 {
			// Target unknown: this candidate is one of several possibilities,
			// gated on what resource_arn ultimately points to.
			condAttr = rule.arnAttribute
		}
		missing = append(missing, MissingAction{
			ModuleAddress:      rc.ModuleAddress,
			ResourceType:       rc.Type,
			ResourceName:       rc.InstanceName(),
			Change:             rc.Change,
			Action:             cb.action,
			Service:            actionService(cb.action),
			Class:              classTag(classManagement),
			ConditionAttribute: condAttr,

			ResourceScopeUnverified: verdict == Unverified,
		})
	}
	return missing
}

// target returns the services the target attribute of rc may name, and the
// target's ARN patterns when the plan shows them. It returns no services when
// the target is unknown, so every candidate applies.
//
// A literal ARN names its own service. Otherwise each reference of the
// attribute must name a resource or data source of a type in targetTypes.
// The ARN patterns come from the referenced planned resources: their known
// arn, or one targetTypes derives from their known attributes. A data source,
// or a resource whose ARN is not derivable, leaves the targets unknown.
func (r crossServiceRule) target(rc *plan.ResourceChange, set *changeSet) (map[string]bool, [][]string) {
	if v := rc.AttributeValues[r.arnAttribute]; isARN(v) {
		return map[string]bool{arnService(v): true}, [][]string{{v}}
	}
	refs := rc.References[r.arnAttribute]
	if len(refs) == 0 {
		return nil, nil
	}
	services := map[string]bool{}
	var types []string
	derivable := true
	for _, ref := range refs {
		typ, data, ok := referencedType(ref)
		if !ok {
			continue
		}
		t, known := r.targetTypes[typ]
		if !known {
			return nil, nil
		}
		services[t.service] = true
		if !data && !slices.Contains(types, typ) {
			types = append(types, typ)
		}
		if data {
			derivable = false
		}
	}
	if len(services) == 0 || !derivable {
		return services, nil
	}
	var targets [][]string
	for _, typ := range types {
		derive := r.targetTypes[typ].arnPatterns
		targets = append(targets, attributeTargets(rc, set, r.arnAttribute, typ, func(c *plan.ResourceChange) []string {
			return plannedARN(c, derive)
		})...)
	}
	return services, targets
}

// referencedType returns the resource type a reference names, and whether it
// names a data source. It reports false for a reference that cannot hold an
// ARN, such as count.index. Any other reference, such as var.arn or
// module.alb.arn, returns its first segment, which names no resource type.
func referencedType(ref string) (typ string, data, ok bool) {
	rest, data := strings.CutPrefix(ref, "data.")
	typ, _, _ = strings.Cut(rest, ".")
	if !data {
		switch typ {
		case "count", "each", "path", "terraform", "self":
			return "", false, false
		}
	}
	return typ, data, typ != ""
}
