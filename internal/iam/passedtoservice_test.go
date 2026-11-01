package iam

import (
	"fmt"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

const exampleRoleARN = "arn:aws:iam::123456789012:role/example-role"

func passRoleGrant(t *testing.T, operator, service string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"iam:PassRole","Resource":"*",
		 "Condition":{%q:{"iam:PassedToService":%q}}}]}`, operator, service)
}

func TestPassedToService_PerResourceType(t *testing.T) {
	for typ, c := range map[string]struct{ attr, service string }{
		"aws_cloudwatch_event_target":  {"role_arn", "events.amazonaws.com"},
		"aws_lambda_function":          {"role", "lambda.amazonaws.com"},
		"aws_sfn_state_machine":        {"role_arn", "states.amazonaws.com"},
		"aws_codebuild_project":        {"service_role", "codebuild.amazonaws.com"},
		"aws_ecs_task_definition":      {"execution_role_arn", "ecs-tasks.amazonaws.com"},
		"aws_apigatewayv2_integration": {"credentials_arn", "apigateway.amazonaws.com"},
	} {
		rc := &plan.ResourceChange{
			Type: typ, Name: "example", Change: "create",
			AttributeValues: map[string]string{c.attr: exampleRoleARN},
		}
		// A grant limited to another service does not cover the pass.
		other := mustPolicy(t, passRoleGrant(t, "StringEquals", "example.amazonaws.com"))
		if m := impliedMissing(rc, other, newChangeSet([]*plan.ResourceChange{rc}), false); !hasAction(m, "iam:PassRole") {
			t.Errorf("%s: a grant limited to another service must report iam:PassRole, got %+v", typ, m)
		}
		// A grant limited to the resource's own service covers it.
		for _, op := range []string{"StringEquals", "StringLike"} {
			own := mustPolicy(t, passRoleGrant(t, op, c.service))
			if m := impliedMissing(rc, own, newChangeSet([]*plan.ResourceChange{rc}), false); len(m) != 0 {
				t.Errorf("%s: a %s grant for %s must cover, got %+v", typ, op, c.service, m)
			}
		}
	}
}

func TestPassedToService_EventTargetNotCoveredByLambdaGrant(t *testing.T) {
	rc := &plan.ResourceChange{
		Type: "aws_cloudwatch_event_target", Name: "example", Change: "create",
		AttributeValues: map[string]string{"role_arn": exampleRoleARN},
	}
	doc := mustPolicy(t, passRoleGrant(t, "StringEquals", "lambda.amazonaws.com"))
	if m := impliedMissing(rc, doc, newChangeSet([]*plan.ResourceChange{rc}), false); !hasAction(m, "iam:PassRole") {
		t.Fatalf("a PassRole grant limited to Lambda must not cover an event target, got %+v", m)
	}
}
