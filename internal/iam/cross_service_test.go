package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// allowSet covers only the actions in the set.
type allowSet map[string]bool

func (a allowSet) Covers(action string) bool { return a[action] }

func TestArnService(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188", "elasticloadbalancing"},
		{"arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod", "apigateway"},
		{"arn:aws-us-gov:appsync:us-gov-west-1:123456789012:apis/abc", "appsync"},
		{"", ""},
		{"not-an-arn", ""},
		{"arn:aws", ""},
	}
	for _, c := range cases {
		if got := arnService(c.arn); got != c.want {
			t.Errorf("arnService(%q) = %q, want %q", c.arn, got, c.want)
		}
	}
}

func TestCrossServiceMissing_KnownALBTarget(t *testing.T) {
	rc := &plan.ResourceChange{
		Type:   "aws_wafv2_web_acl_association",
		Name:   "this",
		Change: "create",
		AttributeValues: map[string]string{
			"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188",
		},
	}

	missing := crossServiceMissing(rc, denyAll{})

	// Known ALB target → exactly one unconditional callback action.
	if len(missing) != 1 {
		t.Fatalf("expected 1 missing action, got %d: %+v", len(missing), missing)
	}
	m := missing[0]
	if m.Action != "elasticloadbalancing:SetWebACL" {
		t.Errorf("expected elasticloadbalancing:SetWebACL, got %q", m.Action)
	}
	if m.ConditionAttribute != "" {
		t.Errorf("known target should be unconditional, got condition %q", m.ConditionAttribute)
	}
	if m.Class != "[required]" {
		t.Errorf("expected [required] class, got %q", m.Class)
	}
}

func TestCrossServiceMissing_KnownAPIGatewayTarget(t *testing.T) {
	rc := &plan.ResourceChange{
		Type:   "aws_wafv2_web_acl_association",
		Name:   "this",
		Change: "create",
		AttributeValues: map[string]string{
			"resource_arn": "arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod",
		},
	}

	missing := crossServiceMissing(rc, denyAll{})
	if len(missing) != 1 || missing[0].Action != "apigateway:SetWebACL" {
		t.Fatalf("expected single apigateway:SetWebACL, got %+v", missing)
	}
}

func TestCrossServiceMissing_UnknownTargetOverApproximates(t *testing.T) {
	// No AttributeValues → resource_arn unknown (computed at apply time or
	// static HCL mode). Every candidate callback should be reported, gated on
	// resource_arn so --only-required can suppress the over-approximation.
	rc := &plan.ResourceChange{
		Type:   "aws_wafv2_web_acl_association",
		Name:   "this",
		Change: "create",
	}

	missing := crossServiceMissing(rc, denyAll{})
	if len(missing) < 2 {
		t.Fatalf("expected multiple candidate callbacks when target unknown, got %+v", missing)
	}
	if !hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Error("expected elasticloadbalancing:SetWebACL among candidates")
	}
	if !hasAction(missing, "apigateway:SetWebACL") {
		t.Error("expected apigateway:SetWebACL among candidates")
	}
	for _, m := range missing {
		if m.ConditionAttribute != "resource_arn" {
			t.Errorf("unknown-target callbacks should be conditional on resource_arn, got %q for %s", m.ConditionAttribute, m.Action)
		}
	}
}

func TestCrossServiceMissing_CoveredByWildcard(t *testing.T) {
	rc := &plan.ResourceChange{
		Type:   "aws_wafv2_web_acl_association",
		Name:   "this",
		Change: "create",
		AttributeValues: map[string]string{
			"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188",
		},
	}

	// elasticloadbalancing:* covers the callback → nothing missing.
	missing := crossServiceMissing(rc, allowSet{"elasticloadbalancing:*": true})
	if len(missing) != 0 {
		t.Errorf("expected no missing when covered by service wildcard, got %+v", missing)
	}

	// Exact action grant also covers it.
	missing = crossServiceMissing(rc, allowSet{"elasticloadbalancing:SetWebACL": true})
	if len(missing) != 0 {
		t.Errorf("expected no missing when covered by exact action, got %+v", missing)
	}
}

func TestCrossServiceMissing_KnownUnmappedTarget(t *testing.T) {
	// A target service we don't have a callback mapping for → no callback.
	rc := &plan.ResourceChange{
		Type:   "aws_wafv2_web_acl_association",
		Name:   "this",
		Change: "create",
		AttributeValues: map[string]string{
			"resource_arn": "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_abc",
		},
	}
	if missing := crossServiceMissing(rc, denyAll{}); len(missing) != 0 {
		t.Errorf("expected no callback for unmapped target service, got %+v", missing)
	}
}

func TestCrossServiceMissing_NonCallbackResource(t *testing.T) {
	rc := &plan.ResourceChange{Type: "aws_s3_bucket", Name: "b", Change: "create"}
	if missing := crossServiceMissing(rc, denyAll{}); missing != nil {
		t.Errorf("expected nil for non-callback resource, got %+v", missing)
	}
}

func TestValidate_CrossServiceCallback(t *testing.T) {
	// Schema grants all wafv2 actions via the policy; the cross-service
	// callback into elasticloadbalancing must still surface as missing.
	schema := fakeSchema{
		perms: map[string][]string{
			"create": {"wafv2:AssociateWebACL", "wafv2:GetWebACLForResource"},
		},
	}
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{
			Type:   "aws_wafv2_web_acl_association",
			Name:   "this",
			Change: "create",
			AttributeValues: map[string]string{
				"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188",
			},
		},
	}

	// Policy grants every wafv2 action but nothing in elasticloadbalancing.
	missing, err := Validate(changes, allowSet{"wafv2:*": true}, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Errorf("expected elasticloadbalancing:SetWebACL to be reported missing, got %+v", missing)
	}
}

func TestValidate_CrossServiceCallback_ExcludeConditional(t *testing.T) {
	schema := fakeSchema{perms: map[string][]string{"create": {"wafv2:AssociateWebACL"}}}
	resolver := fakeResolver{schema}

	// Unknown target → conditional candidates. --only-required suppresses them.
	changes := []*plan.ResourceChange{
		{Type: "aws_wafv2_web_acl_association", Name: "this", Change: "create"},
	}
	missing, err := Validate(changes, denyAll{}, resolver, FilterConfig{ExcludeConditional: true})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Errorf("ExcludeConditional should drop over-approximated callbacks, got %+v", missing)
	}
}
