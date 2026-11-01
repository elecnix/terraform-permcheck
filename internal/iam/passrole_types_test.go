package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// passingTypes lists resource types that hand a role to a service, with the
// attribute that carries it and the principal that receives it.
var passingTypes = map[string]struct{ attr, service string }{
	"aws_scheduler_schedule":          {"target", "scheduler.amazonaws.com"},
	"aws_pipes_pipe":                  {"role_arn", "pipes.amazonaws.com"},
	"aws_glue_job":                    {"role_arn", "glue.amazonaws.com"},
	"aws_cloudtrail":                  {"cloud_watch_logs_role_arn", "cloudtrail.amazonaws.com"},
	"aws_flow_log":                    {"iam_role_arn", "vpc-flow-logs.amazonaws.com"},
	"aws_eks_cluster":                 {"role_arn", "eks.amazonaws.com"},
	"aws_api_gateway_integration":     {"credentials", "apigateway.amazonaws.com"},
	"aws_cloudwatch_event_rule":       {"role_arn", "events.amazonaws.com"},
	"aws_sagemaker_notebook_instance": {"role_arn", "sagemaker.amazonaws.com"},
	"aws_batch_compute_environment":   {"service_role", "batch.amazonaws.com"},
}

// A type whose role sits inside a nested block shows the block as set. The
// plan does not expose the nested value, so the role is unknown.
func passingChange(typ, attr string, literal bool) *plan.ResourceChange {
	rc := &plan.ResourceChange{
		Type: typ, Name: "example", Change: "create",
		Attributes: map[string]bool{attr: true}, AttributeValues: map[string]string{},
	}
	if literal {
		rc.AttributeValues[attr] = exampleRoleARN
	}
	return rc
}

func TestPassRole_MoreTypesNeedTheGrant(t *testing.T) {
	for typ, c := range passingTypes {
		rc := passingChange(typ, c.attr, c.attr != "target")
		if m := impliedMissing(rc, grantNothing(), newChangeSet([]*plan.ResourceChange{rc}), false); !hasAction(m, "iam:PassRole") {
			t.Errorf("%s: expected iam:PassRole missing, got %+v", typ, m)
		}
	}
}

func TestPassRole_MoreTypesCheckPassedToService(t *testing.T) {
	for typ, c := range passingTypes {
		rc := passingChange(typ, c.attr, c.attr != "target")
		set := newChangeSet([]*plan.ResourceChange{rc})
		other := mustPolicy(t, passRoleGrant(t, "StringEquals", "example.amazonaws.com"))
		if m := impliedMissing(rc, other, set, false); !hasAction(m, "iam:PassRole") {
			t.Errorf("%s: a grant limited to another service must report iam:PassRole, got %+v", typ, m)
		}
		own := mustPolicy(t, passRoleGrant(t, "StringEquals", c.service))
		if m := impliedMissing(rc, own, set, false); hasAction(m, "iam:PassRole") {
			t.Errorf("%s: a grant for %s must cover, got %+v", typ, c.service, m)
		}
	}
}

func TestPassRole_MoreTypesNeedNoneOnDelete(t *testing.T) {
	for typ, c := range passingTypes {
		rc := passingChange(typ, c.attr, true)
		rc.Change = "delete"
		if m := impliedMissing(rc, grantNothing(), newChangeSet([]*plan.ResourceChange{rc}), false); hasAction(m, "iam:PassRole") {
			t.Errorf("%s: a delete passes no role, got %+v", typ, m)
		}
	}
}

func TestPassRole_OptionalRoleUnsetNeedsNone(t *testing.T) {
	rc := &plan.ResourceChange{
		Type: "aws_cloudtrail", Name: "example", Change: "create",
		Attributes: map[string]bool{"name": true}, AttributeValues: map[string]string{},
	}
	if m := impliedMissing(rc, grantNothing(), newChangeSet([]*plan.ResourceChange{rc}), false); hasAction(m, "iam:PassRole") {
		t.Errorf("a trail with no logs role passes none, got %+v", m)
	}
}
