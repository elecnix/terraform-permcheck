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

func eventConnectionChange(change string) *plan.ResourceChange {
	return &plan.ResourceChange{
		Type: "aws_cloudwatch_event_connection", Name: "example", Change: change,
		AttributeValues: map[string]string{"name": "example-connection"},
	}
}

func TestServiceLinkedRole_EventConnectionMissingOnCreate(t *testing.T) {
	m := impliedMissing(eventConnectionChange("create"), grantActions("events:*"), nil, false)
	if !hasActionOn(m, "iam:CreateServiceLinkedRole", "aws_cloudwatch_event_connection", "example") {
		t.Fatalf("expected iam:CreateServiceLinkedRole missing, got %+v", m)
	}
}

func TestServiceLinkedRole_EventConnectionCoveredByItsPath(t *testing.T) {
	doc := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"arn:aws:iam::123456789012:role/aws-service-role/apidestinations.events.amazonaws.com/*"}]}`)
	// The connection's managed secret needs its own grant, so only the
	// service-linked role is under test here.
	m := impliedMissing(eventConnectionChange("create"), doc, nil, false)
	if hasActionOn(m, "iam:CreateServiceLinkedRole", "aws_cloudwatch_event_connection", "example") {
		t.Errorf("expected iam:CreateServiceLinkedRole covered, got %+v", m)
	}
}

func TestServiceLinkedRole_FirstUseOfAService(t *testing.T) {
	for typ, principal := range map[string]string{
		"aws_ecs_cluster":       "ecs.amazonaws.com",
		"aws_autoscaling_group": "autoscaling.amazonaws.com",
		"aws_lb":                "elasticloadbalancing.amazonaws.com",
		"aws_db_instance":       "rds.amazonaws.com",
		"aws_rds_cluster":       "rds.amazonaws.com",
		"aws_eks_cluster":       "eks.amazonaws.com",
	} {
		rc := &plan.ResourceChange{Type: typ, Name: "example", Change: "create", AttributeValues: map[string]string{}}
		if m := impliedMissing(rc, grantNothing(), nil, false); !hasActionOn(m, "iam:CreateServiceLinkedRole", typ, "example") {
			t.Errorf("%s: expected iam:CreateServiceLinkedRole missing, got %+v", typ, m)
		}
		doc := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"arn:aws:iam::123456789012:role/aws-service-role/`+principal+`/*"}]}`)
		if m := impliedMissing(rc, doc, nil, false); len(m) != 0 {
			t.Errorf("%s: a grant on %s must cover, got %+v", typ, principal, m)
		}
	}
}
