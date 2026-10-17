package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

func domainNameChange(change string) *plan.ResourceChange {
	return &plan.ResourceChange{
		Type: "aws_apigatewayv2_domain_name", Name: "this", Change: change,
		AttributeValues: map[string]string{},
	}
}

func TestServiceLinkedRole_MissingOnCreate(t *testing.T) {
	m := impliedMissing(domainNameChange("create"), grantActions("apigateway:*"), nil, false)
	if !hasActionOn(m, "iam:CreateServiceLinkedRole", "aws_apigatewayv2_domain_name", "this") {
		t.Fatalf("expected iam:CreateServiceLinkedRole missing, got %+v", m)
	}
}

func TestServiceLinkedRole_NotOnUpdateOrDelete(t *testing.T) {
	for _, change := range []string{"update", "delete"} {
		if m := impliedMissing(domainNameChange(change), grantNothing(), nil, false); len(m) != 0 {
			t.Errorf("%s: expected no service-linked-role requirement, got %+v", change, m)
		}
	}
}

func TestServiceLinkedRole_Covered(t *testing.T) {
	for name, doc := range map[string]string{
		"wildcard": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"*"}]}`,
		"path":     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"arn:aws:iam::111122223333:role/aws-service-role/ops.apigateway.amazonaws.com/*"}]}`,
	} {
		if m := impliedMissing(domainNameChange("create"), mustPolicy(t, doc), nil, false); len(m) != 0 {
			t.Errorf("%s: expected covered, got %+v", name, m)
		}
	}
}

func TestServiceLinkedRole_WrongServicePath(t *testing.T) {
	doc := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"arn:aws:iam::111122223333:role/aws-service-role/inspector2.amazonaws.com/*"}]}`)
	if m := impliedMissing(domainNameChange("create"), doc, nil, false); len(m) != 1 {
		t.Errorf("a grant for another service must not cover it, got %+v", m)
	}
}
