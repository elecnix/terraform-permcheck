package iam

import (
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// Resource-scoped coverage.
//
// A policy grants actions scoped to specific resources via each statement's
// Resource patterns. When the target resource's ARN is derivable at plan time,
// matching on the action name alone is sound but not complete: it reports a
// grant covered even when the statement's Resource can never apply to the
// target (e.g. `secretsmanager:PutSecretValue` on a different secret). This
// file cross-checks action coverage against the statements' Resource patterns
// and reports the action missing when the grant is provably scoped elsewhere.

// resourceTargets returns the targets a resource change acts on, derivable
// from plan-time values: one list of ARN patterns per resource. It returns nil
// when the target cannot be determined (unknown values, static HCL mode,
// unlisted resource types), in which case coverage falls back to action-only
// matching.
func resourceTargets(rc *plan.ResourceChange, set *changeSet) [][]string {
	targets := resourceRules[rc.Type].targets
	if targets == nil {
		return nil
	}
	return targets(rc, set)
}

// ownTarget returns a target rule for a resource that acts on itself: its one
// target has the ARN patterns arnPatterns builds from it, when they are known.
func ownTarget(arnPatterns func(*plan.ResourceChange) []string) func(*plan.ResourceChange, *changeSet) [][]string {
	return func(rc *plan.ResourceChange, _ *changeSet) [][]string {
		if forms := arnPatterns(rc); forms != nil {
			return [][]string{forms}
		}
		return nil
	}
}

// secretVersionTargetARNs derives the secrets a secret version applies to
// from its secret_id: either a literal ARN known at plan time, or a reference
// to managed secrets whose configured names are known.
func secretVersionTargetARNs(rc *plan.ResourceChange, set *changeSet) [][]string {
	return attributeTargets(rc, set, "secret_id", "aws_secretsmanager_secret", secretARNPatterns)
}

// logStreamTargetARNs derives the ARN patterns a CloudWatch Logs stream acts
// on: its group, in both log-group forms, and the stream itself.
func logStreamTargetARNs(rc *plan.ResourceChange, set *changeSet) [][]string {
	stream := rc.AttributeValues["name"]
	var groups []string
	if group := rc.AttributeValues["log_group_name"]; group != "" {
		groups = []string{group}
	} else {
		for _, c := range referencedChanges(rc, set, "log_group_name", "aws_cloudwatch_log_group") {
			if name := c.AttributeValues["name"]; name != "" {
				groups = append(groups, name)
			}
		}
	}
	var targets [][]string
	for _, group := range groups {
		forms := logGroupARNPatterns(group)
		if stream != "" {
			forms = append(forms, "arn:*:logs:*:*:log-group:"+group+":log-stream:"+stream)
		}
		targets = append(targets, forms)
	}
	return targets
}
