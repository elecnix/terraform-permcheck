package iam

import (
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

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

	missing := impliedMissing(rc, grantNothing(), nil, false)

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

	missing := impliedMissing(rc, grantNothing(), nil, false)
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

	missing := impliedMissing(rc, grantNothing(), nil, false)
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
	missing := impliedMissing(rc, grantActions("elasticloadbalancing:*"), nil, false)
	if len(missing) != 0 {
		t.Errorf("expected no missing when covered by service wildcard, got %+v", missing)
	}

	// Exact action grant also covers it.
	missing = impliedMissing(rc, grantActions("elasticloadbalancing:SetWebACL"), nil, false)
	if len(missing) != 0 {
		t.Errorf("expected no missing when covered by exact action, got %+v", missing)
	}
}

// TestCrossServiceMissing_LiteralTargets checks the callback each target
// service needs, from the AWS WAF Developer Guide, "Permissions for
// AssociateWebACL".
func TestCrossServiceMissing_LiteralTargets(t *testing.T) {
	cases := map[string]string{
		"arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_abc":                       "cognito-idp:AssociateWebACL",
		"arn:aws:apprunner:us-east-1:123456789012:service/web/8fe1e10304f84fd2b0df550fe98a71fa":   "apprunner:AssociateWebAcl",
		"arn:aws:ec2:us-east-1:123456789012:verified-access-instance/vai-0ce000c0b7643abea":       "ec2:AssociateVerifiedAccessInstanceWebAcl",
		"arn:aws:appsync:us-east-1:123456789012:apis/abcdefghijklmnopqrstuvwxyz":                  "appsync:SetWebACL",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c": "elasticloadbalancing:SetWebACL",
	}
	for arn, want := range cases {
		rc := &plan.ResourceChange{
			Type: "aws_wafv2_web_acl_association", Name: "this", Change: "create",
			AttributeValues: map[string]string{"resource_arn": arn},
		}
		missing := impliedMissing(rc, grantNothing(), nil, false)
		if len(missing) != 1 || missing[0].Action != want {
			t.Errorf("%s: want only %s, got %+v", arn, want, missing)
		}
	}
}

func TestCrossServiceMissing_UnmappedTarget(t *testing.T) {
	// A target service with no callback mapping → no callback.
	rc := &plan.ResourceChange{
		Type:   "aws_wafv2_web_acl_association",
		Name:   "this",
		Change: "create",
		AttributeValues: map[string]string{
			"resource_arn": "arn:aws:amplify:us-east-1:123456789012:apps/d1a2b3c4",
		},
	}
	if missing := impliedMissing(rc, grantNothing(), nil, false); len(missing) != 0 {
		t.Errorf("expected no callback for unmapped target service, got %+v", missing)
	}
}

func TestCrossServiceMissing_NonCallbackResource(t *testing.T) {
	rc := &plan.ResourceChange{Type: "aws_s3_bucket", Name: "b", Change: "create"}
	if missing := impliedMissing(rc, grantNothing(), nil, false); missing != nil {
		t.Errorf("expected nil for non-callback resource, got %+v", missing)
	}
}

func TestValidate_CrossServiceCallback(t *testing.T) {
	// Schema grants all wafv2 actions via the policy; the cross-service
	// callback into elasticloadbalancing must still surface as missing.
	schema := actionsSchema(map[string][]string{
		"create": {"wafv2:AssociateWebACL", "wafv2:GetWebACLForResource"},
	})
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
	missing, err := Validate(changes, grantActions("wafv2:*"), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Errorf("expected elasticloadbalancing:SetWebACL to be reported missing, got %+v", missing)
	}
}

func TestValidate_CrossServiceCallback_ExcludeConditional(t *testing.T) {
	schema := actionsSchema(map[string][]string{"create": {"wafv2:AssociateWebACL"}})
	resolver := fakeResolver{schema}

	// Unknown target → conditional candidates. --only-required suppresses them.
	changes := []*plan.ResourceChange{
		{Type: "aws_wafv2_web_acl_association", Name: "this", Change: "create"},
	}
	missing, err := Validate(changes, grantNothing(), resolver, FilterConfig{ExcludeConditional: true})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Errorf("ExcludeConditional should drop over-approximated callbacks, got %+v", missing)
	}
}

// TestValidate_CrossServiceReferencedTarget checks that a resource_arn the
// plan computes at apply time still selects one callback when the
// configuration references the target resource. An ALB's ARN is unknown until
// it exists, but the reference names the ALB, so only
// elasticloadbalancing:SetWebACL applies.
func TestValidate_CrossServiceReferencedTarget(t *testing.T) {
	resolver := fakeResolver{actionsSchema(map[string][]string{"create": {"wafv2:AssociateWebACL"}})}
	association := func(refs ...string) *plan.ResourceChange {
		return &plan.ResourceChange{
			Type: "aws_wafv2_web_acl_association", Name: "this", Change: "create",
			AttributeValues: map[string]string{},
			References:      map[string][]string{"resource_arn": refs},
		}
	}
	lb := &plan.ResourceChange{
		Type: "aws_lb", Name: "web", Change: "create",
		AttributeValues: map[string]string{"name": "example-web"},
	}

	cases := []struct {
		name    string
		changes []*plan.ResourceChange
		want    []string
	}{
		{"managed ALB", []*plan.ResourceChange{lb, association("aws_lb.web.arn", "aws_lb.web")}, []string{"elasticloadbalancing:SetWebACL"}},
		{"aws_alb alias", []*plan.ResourceChange{association("aws_alb.web.arn", "aws_alb.web")}, []string{"elasticloadbalancing:SetWebACL"}},
		{"ALB data source", []*plan.ResourceChange{association("data.aws_lb.web.arn", "data.aws_lb.web")}, []string{"elasticloadbalancing:SetWebACL"}},
		{"REST API stage", []*plan.ResourceChange{association("aws_api_gateway_stage.prod.arn", "aws_api_gateway_stage.prod")}, []string{"apigateway:SetWebACL"}},
		{"GraphQL API", []*plan.ResourceChange{association("aws_appsync_graphql_api.api.arn", "aws_appsync_graphql_api.api")}, []string{"appsync:SetWebACL"}},
		{"Cognito user pool", []*plan.ResourceChange{association("aws_cognito_user_pool.pool.arn", "aws_cognito_user_pool.pool")}, []string{"cognito-idp:AssociateWebACL"}},
		{"App Runner service", []*plan.ResourceChange{association("aws_apprunner_service.web.arn", "aws_apprunner_service.web")}, []string{"apprunner:AssociateWebAcl"}},
		{"Verified Access instance", []*plan.ResourceChange{association("aws_verifiedaccess_instance.vai.arn", "aws_verifiedaccess_instance.vai")}, []string{"ec2:AssociateVerifiedAccessInstanceWebAcl"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			missing, err := Validate(c.changes, grantActions("wafv2:*"), resolver, FilterConfig{})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, m := range missing {
				got = append(got, m.Action)
				if m.ConditionAttribute != "" {
					t.Errorf("%s: a referenced target makes the callback unconditional, got gate %q", m.Action, m.ConditionAttribute)
				}
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestValidate_CrossServiceReferencedALBScope checks that a planned ALB's
// name scopes the callback: a grant on another load balancer does not cover
// it, and a grant on this one does.
func TestValidate_CrossServiceReferencedALBScope(t *testing.T) {
	resolver := fakeResolver{actionsSchema(map[string][]string{"create": {"wafv2:AssociateWebACL"}})}
	changes := []*plan.ResourceChange{
		{
			Type: "aws_lb", Name: "web", Change: "create",
			AttributeValues: map[string]string{"name": "example-web"},
		},
		{
			Type: "aws_wafv2_web_acl_association", Name: "this", Change: "create",
			AttributeValues: map[string]string{},
			References:      map[string][]string{"resource_arn": {"aws_lb.web.arn", "aws_lb.web"}},
		},
	}
	grant := func(resource string) *policy.Document {
		return &policy.Document{Statements: []policy.Statement{
			{Effect: "Allow", Action: []string{"wafv2:*"}, Resource: []string{"*"}},
			{Effect: "Allow", Action: []string{"elasticloadbalancing:SetWebACL"}, Resource: []string{resource}},
		}}
	}

	missing, err := Validate(changes, grant("arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/example-other/*"), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Errorf("a grant on another load balancer must not cover, got %+v", missing)
	}

	missing, err = Validate(changes, grant("arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/example-web/*"), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("a grant on the referenced load balancer must cover, got %+v", missing)
	}
}
