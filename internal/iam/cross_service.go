package iam

import (
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

// crossServiceRule describes the cross-service callbacks for a terraform
// resource type and the attribute whose ARN value selects among them.
type crossServiceRule struct {
	// arnAttribute is the resource attribute holding the target ARN.
	arnAttribute string
	// callbacks lists the candidate callbacks keyed by target service.
	callbacks []crossServiceCallback
}

// crossServiceRules maps a terraform resource type to its cross-service
// callback rule. Extend this table as new cross-service gaps are found.
var crossServiceRules = map[string]crossServiceRule{
	"aws_wafv2_web_acl_association": {
		arnAttribute: "resource_arn",
		callbacks: []crossServiceCallback{
			{targetService: "elasticloadbalancing", action: "elasticloadbalancing:SetWebACL"},
			{targetService: "apigateway", action: "apigateway:SetWebACL"},
			{targetService: "appsync", action: "appsync:SetWebACL"},
		},
	},
}

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
func crossServiceMissing(rc *plan.ResourceChange, policy AllowedProvider) []MissingAction {
	rule, ok := crossServiceRules[rc.Type]
	if !ok {
		return nil
	}

	targetService := arnService(rc.AttributeValues[rule.arnAttribute])

	var missing []MissingAction
	for _, cb := range rule.callbacks {
		if targetService != "" && cb.targetService != targetService {
			continue
		}
		if coversAction(policy, cb.action) {
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
			Service:            strings.Split(cb.action, ":")[0],
			Class:              classTag(ClassManagement),
			ConditionAttribute: condAttr,
		})
	}
	return missing
}

// coversAction reports whether the policy grants an action, either directly or
// via the service wildcard (service:*).
func coversAction(policy AllowedProvider, action string) bool {
	if policy.Covers(action) {
		return true
	}
	service := strings.Split(action, ":")[0]
	return policy.Covers(service + ":*")
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
