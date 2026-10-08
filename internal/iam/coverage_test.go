package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

func TestCoverage_Verdicts(t *testing.T) {
	scoped := `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs:us-east-1:111122223333:example-a"}]}`
	everywhere := `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}`
	denied := `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"},{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}]}`
	targetA := []string{"arn:*:sqs:*:*:example-a"}
	targetB := []string{"arn:*:sqs:*:*:example-b"}

	cases := []struct {
		name    string
		policy  string
		targets []string
		strict  bool
		want    Verdict
	}{
		{"no grant, target unknown", `{"Statement":[]}`, nil, false, Missing},
		{"no grant, target known", `{"Statement":[]}`, targetA, false, Missing},
		{"grant everywhere, target unknown", everywhere, nil, true, Covered},
		{"scoped grant, target unknown", scoped, nil, false, Covered},
		{"scoped grant, target unknown, strict", scoped, nil, true, Unverified},
		{"scoped grant on the target", scoped, targetA, true, Covered},
		{"scoped grant on another target", scoped, targetB, false, Missing},
		{"definite deny, target unknown", denied, nil, false, Missing},
		{"definite deny, target known", denied, targetA, false, Missing},
	}
	for _, c := range cases {
		doc := mustPolicy(t, c.policy)
		if got := doc.Coverage("sqs:SendMessage", c.targets, c.strict); got != c.want {
			t.Errorf("%s: Coverage = %v, want %v", c.name, got, c.want)
		}
	}
}

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
	missing := crossServiceMissing(rc, other, nil, false)
	if !hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Errorf("a grant on another load balancer must not cover the callback, got %+v", missing)
	}
	if len(missing) == 1 && missing[0].ConditionAttribute != "" {
		t.Errorf("a known target makes the callback unconditional, got gate %q", missing[0].ConditionAttribute)
	}

	same := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"elasticloadbalancing:SetWebACL",
		"Resource":"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/example-a/*"}]}`)
	if missing := crossServiceMissing(rc, same, nil, true); len(missing) != 0 {
		t.Errorf("a grant on the target load balancer must cover the callback, got %+v", missing)
	}
}
