package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// A cross-service callback acts on the resource named by the rule's ARN
// attribute, so a grant scoped to another resource does not cover it.
func TestCrossServiceMissing_CallbackGrantOnOtherResource(t *testing.T) {
	rc := &plan.ResourceChange{
		Type:   "aws_wafv2_web_acl_association",
		Name:   "this",
		Change: "create",
		AttributeValues: map[string]string{
			"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/example-a/50dc6c495c0c9188",
		},
	}

	other := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"elasticloadbalancing:SetWebACL",
		"Resource":"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/example-b/*"}]}`)
	missing := impliedMissing(rc, other, nil, false)
	if !hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Errorf("a grant on another load balancer must not cover the callback, got %+v", missing)
	}
	if len(missing) == 1 && missing[0].ConditionAttribute != "" {
		t.Errorf("a known target makes the callback unconditional, got gate %q", missing[0].ConditionAttribute)
	}

	same := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"elasticloadbalancing:SetWebACL",
		"Resource":"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/example-a/*"}]}`)
	if missing := impliedMissing(rc, same, nil, true); len(missing) != 0 {
		t.Errorf("a grant on the target load balancer must cover the callback, got %+v", missing)
	}
}
