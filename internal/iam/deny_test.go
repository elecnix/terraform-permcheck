package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

func TestValidate_AllowPlusDenyReportsMissing(t *testing.T) {
	resolver := fakeResolver{actionsSchema(map[string][]string{
		"create": {"sqs:CreateQueue"},
	})}
	// No name, so the target is unknown and coverage is action-level.
	changes := []*plan.ResourceChange{{Type: "aws_sqs_queue", Name: "q", Change: "create"}}
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"*"}]}`)
	missing, err := Validate(changes, doc, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasActionOn(missing, "sqs:CreateQueue", "aws_sqs_queue", "q") {
		t.Errorf("expected sqs:CreateQueue missing, got %+v", missing)
	}
}

func TestValidate_DenyOnTargetQueue(t *testing.T) {
	resolver := fakeResolver{actionsSchema(map[string][]string{
		"create": {"sqs:CreateQueue"},
	})}
	changes := []*plan.ResourceChange{{
		Type: "aws_sqs_queue", Name: "q", Change: "create",
		AttributeValues: map[string]string{"name": "example-queue"},
	}}

	denied := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:CreateQueue","Resource":"arn:*:sqs:*:*:example-*"}]}`)
	missing, err := Validate(changes, denied, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasActionOn(missing, "sqs:CreateQueue", "aws_sqs_queue", "q") {
		t.Errorf("expected sqs:CreateQueue missing, got %+v", missing)
	}

	other := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:CreateQueue","Resource":"arn:*:sqs:*:*:other-*"}]}`)
	missing, err = Validate(changes, other, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("a Deny on another queue must not report, got %+v", missing)
	}
}

func TestValidate_MidStringActionGlobCovers(t *testing.T) {
	resolver := fakeResolver{actionsSchema(map[string][]string{
		"create": {"secretsmanager:PutSecretValue"},
	})}
	changes := []*plan.ResourceChange{{Type: "aws_secretsmanager_secret_version", Name: "v", Change: "create"}}
	doc := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:*SecretValue","Resource":"*"}]}`)
	missing, err := Validate(changes, doc, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("secretsmanager:*SecretValue must cover PutSecretValue, got %+v", missing)
	}
}

func TestValidate_CrossServiceCallbackHonoursDeny(t *testing.T) {
	resolver := typeKeyedResolver{"aws_wafv2_web_acl_association": actionsSchema(map[string][]string{
		"create": {"wafv2:AssociateWebACL"},
	})}
	changes := []*plan.ResourceChange{{
		Type: "aws_wafv2_web_acl_association", Name: "this", Change: "create",
		AttributeValues: map[string]string{
			"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188",
		},
	}}
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"elasticloadbalancing:*","Resource":"*"}]}`)
	missing, err := Validate(changes, doc, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Errorf("a Deny on elasticloadbalancing:* must report SetWebACL, got %+v", missing)
	}
	if hasAction(missing, "wafv2:AssociateWebACL") {
		t.Errorf("wafv2:AssociateWebACL is allowed, got %+v", missing)
	}
}

func TestPassRoleMissing_HonoursDeny(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"},
		{"Effect":"Deny","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/deploy"}]}`)
	missing := impliedMissing(lambdaChange("arn:aws:iam::111122223333:role/deploy"), doc, nil, false)
	if !hasAction(missing, "iam:PassRole") {
		t.Errorf("a Deny on the passed role must report iam:PassRole, got %+v", missing)
	}
}
