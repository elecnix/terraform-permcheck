package iam

import (
	"fmt"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

func eventConnection(change, name string) *plan.ResourceChange {
	values := map[string]string{}
	if name != "" {
		values["name"] = name
	}
	return &plan.ResourceChange{
		Type: "aws_cloudwatch_event_connection", Name: "example", Change: change,
		AttributeValues: values,
	}
}

func TestManagedSecret_EventConnectionCreate(t *testing.T) {
	m := impliedMissing(eventConnection("create", "example-connection"), grantActions("events:*"), nil, false)
	for _, action := range []string{
		"secretsmanager:CreateSecret", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue",
	} {
		if !hasActionOn(m, action, "aws_cloudwatch_event_connection", "example") {
			t.Errorf("expected %s missing, got %+v", action, m)
		}
	}
	if hasActionOn(m, "secretsmanager:UpdateSecret", "aws_cloudwatch_event_connection", "example") {
		t.Errorf("a create must not need secretsmanager:UpdateSecret, got %+v", m)
	}
}

func TestManagedSecret_EventConnectionUpdate(t *testing.T) {
	m := impliedMissing(eventConnection("update", "example-connection"), grantActions("events:*"), nil, false)
	if !hasActionOn(m, "secretsmanager:UpdateSecret", "aws_cloudwatch_event_connection", "example") {
		t.Errorf("expected secretsmanager:UpdateSecret missing, got %+v", m)
	}
}

func TestManagedSecret_EventConnectionDeleteNeedsNone(t *testing.T) {
	if m := impliedMissing(eventConnection("delete", "example-connection"), grantNothing(), nil, false); len(m) != 0 {
		t.Errorf("a delete needs no secret action, got %+v", m)
	}
}

func TestManagedSecret_EventConnectionGrantScopes(t *testing.T) {
	// The service-linked role the connection also needs is granted apart, so
	// only the secret's scope decides the outcome.
	const grant = `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"arn:aws:iam::123456789012:role/aws-service-role/apidestinations.events.amazonaws.com/*"},
		{"Effect":"Allow",
		"Action":["secretsmanager:CreateSecret","secretsmanager:GetSecretValue","secretsmanager:PutSecretValue"],
		"Resource":%q}]}`
	for name, c := range map[string]struct {
		resource string
		covered  bool
	}{
		"managed prefix":   {"arn:aws:secretsmanager:us-east-1:123456789012:secret:events!connection/*", true},
		"own connection":   {"arn:aws:secretsmanager:us-east-1:123456789012:secret:events!connection/example-connection/*", true},
		"other secrets":    {"arn:aws:secretsmanager:us-east-1:123456789012:secret:example-app-*", false},
		"other connection": {"arn:aws:secretsmanager:us-east-1:123456789012:secret:events!connection/example-other/*", false},
	} {
		doc := mustPolicy(t, fmt.Sprintf(grant, c.resource))
		m := impliedMissing(eventConnection("create", "example-connection"), doc, nil, false)
		if c.covered && len(m) != 0 {
			t.Errorf("%s: expected covered, got %+v", name, m)
		}
		if !c.covered && len(m) == 0 {
			t.Errorf("%s: expected missing", name)
		}
	}
}

func TestManagedSecret_EventConnectionUnknownNameNeedsPrefixGrant(t *testing.T) {
	// An unknown name cannot be tied to one connection's own secret, so the grant
	// an operator has to write is the managed prefix. Asserting only the missing
	// case would pass for any target ARN, because grantActions("events:*") allows
	// no secretsmanager action at all; so a covered case is pinned as well. The
	// service-linked role the connection also needs is granted apart, so only the
	// secret's scope decides the outcome.
	//
	// A grant scoped to a single connection's secret also reads as covered here,
	// because a need whose name is unknown is a wildcard pattern and coverage is
	// decided by overlap rather than containment. That is the permissive default
	// documented under "Strict resource scope"; --strict-resources does not
	// separate the two cases yet, so this test pins the prefix case and the
	// definite miss, not that limitation.
	const grant = `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"arn:aws:iam::123456789012:role/aws-service-role/apidestinations.events.amazonaws.com/*"},
		{"Effect":"Allow",
		"Action":["secretsmanager:CreateSecret","secretsmanager:GetSecretValue","secretsmanager:PutSecretValue"],
		"Resource":%q}]}`
	for name, c := range map[string]struct {
		resource string
		covered  bool
	}{
		"managed prefix":  {"arn:aws:secretsmanager:us-east-1:123456789012:secret:events!connection/*", true},
		"another service": {"arn:aws:secretsmanager:us-east-1:123456789012:secret:example-app-*", false},
	} {
		doc := mustPolicy(t, fmt.Sprintf(grant, c.resource))
		m := impliedMissing(eventConnection("create", ""), doc, nil, false)
		if c.covered && len(m) != 0 {
			t.Errorf("%s: expected covered, got %+v", name, m)
		}
		if !c.covered && !hasActionOn(m, "secretsmanager:CreateSecret", "aws_cloudwatch_event_connection", "example") {
			t.Errorf("%s: expected secretsmanager:CreateSecret missing, got %+v", name, m)
		}
	}
}
