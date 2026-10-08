package iam

import (
	"slices"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// Cross-service callback permissions.
//
// Some AWS APIs require IAM actions from a *different* service than the API
// being called. The primary API performs a cross-service callback at apply
// time that the terraform provider never invokes directly, so the required
// action is invisible to both the CloudFormation schema and the provider
// source parser.
//
// The canonical example is aws_wafv2_web_acl_association: the provider calls
// wafv2:AssociateWebACL, but AWS WAFv2 then calls into the target service to
// attach the ACL — elasticloadbalancing:SetWebACL for an ALB,
// apigateway:SetWebACL for an API Gateway stage, and so on. Which callback
// applies is determined by the service embedded in the target resource_arn.

// crossServiceCallback is a required IAM action in a service other than the
// one whose API the terraform provider calls directly.
type crossServiceCallback struct {
	// targetService is the AWS service prefix (as it appears in an ARN's third
	// segment) that selects this callback, e.g. "elasticloadbalancing".
	targetService string
	// action is the IAM action required in the callback service.
	action string
}

// crossServiceRule describes the cross-service callbacks of a terraform
// resource type and the attribute whose ARN value selects among them.
type crossServiceRule struct {
	// arnAttribute is the resource attribute holding the target ARN.
	arnAttribute string
	// callbacks lists the candidate callbacks keyed by target service.
	callbacks []crossServiceCallback
	// targetTypes maps each terraform type arnAttribute can reference to
	// what the reference says about the target. When the plan computes the
	// ARN at apply time, the reference still names the target's service.
	targetTypes map[string]targetType
}

// targetType is what a reference to one terraform type says about the
// target of a cross-service callback.
type targetType struct {
	// service is the ARN service prefix of the type's resources.
	service string
	// arnPatterns derives a planned resource's ARN patterns from its known
	// attributes, or returns nil. Nil when the type's ARN holds an ID that
	// AWS assigns.
	arnPatterns func(*plan.ResourceChange) []string
}

// crossServiceRequirements returns the cross-service callback actions a
// resource change requires.
//
// When the target's service is known, only the callback for that service is
// returned, ungated. The service is known when the target ARN value is known,
// or when the configuration references a resource of a type the rule knows,
// such as an aws_lb whose ARN AWS assigns at apply time. The target is
// unknown when the attribute references a variable, a module output or a
// resource of a type the rule does not list, and in static HCL mode, which
// shows no values. Then every candidate callback is returned, gated on the
// ARN attribute, and --only-required drops the over-approximation.
//
// The callback acts on the target resource, so a known target ARN scopes the
// coverage check.
func crossServiceRequirements(rc *plan.ResourceChange, set *changeSet) []targeted {
	rule := resourceRules[rc.Type].callbacks
	if rule == nil {
		return nil
	}
	services, targets := rule.target(rc, set)
	var gate Gate
	if len(services) != 1 {
		// Target unknown: each candidate is one of several possibilities,
		// gated on what the attribute ultimately points to.
		gate.Attribute = rule.arnAttribute
	}
	var reqs []targeted
	for _, cb := range rule.callbacks {
		if len(services) > 0 && !services[cb.targetService] {
			continue
		}
		reqs = append(reqs, targeted{
			Requirement: Requirement{Action: cb.action, Gate: gate},
			targets:     targets,
		})
	}
	return reqs
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
