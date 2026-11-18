package iam_test

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/permdata"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// Issue #208: after DeleteEventSourceMapping, the provider polls
// GetEventSourceMapping until Lambda reports the mapping gone. Once it is
// gone, IAM authorizes the poll on Resource "*", so a grant scoped to the
// mapping ARNs does not cover the delete. These tests use the embedded
// table, which lists GetEventSourceMapping under delete.

const mappingARNs = "arn:aws:lambda:*:*:event-source-mapping:*"

// mappingChange is an event source mapping change of op.
func mappingChange(op string) []*plan.ResourceChange {
	return []*plan.ResourceChange{{
		Type: "aws_lambda_event_source_mapping", Name: "events", Change: op,
		AttributeValues: map[string]string{
			"function_name": "arn:aws:lambda:us-east-1:111122223333:function:example-consumer",
		},
	}}
}

func parsePolicy(t *testing.T, doc string) *policy.Document {
	t.Helper()
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestValidate_MappingDeleteNeedsGetOnEveryResource is the issue's
// reproduction: Get, Delete and Update granted only on the mapping ARNs.
func TestValidate_MappingDeleteNeedsGetOnEveryResource(t *testing.T) {
	doc := parsePolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":["lambda:GetEventSourceMapping","lambda:DeleteEventSourceMapping","lambda:UpdateEventSourceMapping"],
		 "Resource":"`+mappingARNs+`"}]}`)

	missing, err := iam.Validate(mappingChange("delete"), doc, permdata.Embedded(), iam.DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].Action != "lambda:GetEventSourceMapping" {
		t.Fatalf("delete must need lambda:GetEventSourceMapping on every resource, got %+v", missing)
	}
	if got := missing[0].GrantedOn; len(got) != 1 || got[0] != mappingARNs {
		t.Errorf("the finding must name the scoped grant, got GrantedOn %v", got)
	}
}

// TestValidate_MappingDeleteCoveredByGetOnEveryResource is the issue's
// working policy: Get on "*" in its own statement, Delete and Update kept on
// the mapping ARNs.
func TestValidate_MappingDeleteCoveredByGetOnEveryResource(t *testing.T) {
	doc := parsePolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:GetEventSourceMapping","Resource":"*"},
		{"Effect":"Allow","Action":["lambda:DeleteEventSourceMapping","lambda:UpdateEventSourceMapping"],
		 "Resource":"`+mappingARNs+`"}]}`)

	missing, err := iam.Validate(mappingChange("delete"), doc, permdata.Embedded(), iam.DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("Get on every resource covers the delete waiter, got %+v", missing)
	}
}

// TestValidate_MappingCreateKeepsScopedGet is the control: the create waiter
// polls a mapping that exists, so IAM checks the mapping's ARN and a scoped
// grant still covers it.
func TestValidate_MappingCreateKeepsScopedGet(t *testing.T) {
	doc := parsePolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":["lambda:CreateEventSourceMapping","lambda:ListTags","lambda:TagResource"],"Resource":"*"},
		{"Effect":"Allow","Action":"lambda:GetEventSourceMapping","Resource":"`+mappingARNs+`"}]}`)

	missing, err := iam.Validate(mappingChange("create"), doc, permdata.Embedded(), iam.DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("a scoped Get covers the create waiter, got %+v", missing)
	}
}
