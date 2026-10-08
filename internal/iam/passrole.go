package iam

import "github.com/elecnix/terraform-permcheck/internal/plan"

// iam:PassRole.
//
// Resources that hand an IAM role to a service need iam:PassRole on that
// role's ARN. The terraform provider never calls iam:PassRole itself, so no
// schema lists it. The role is named by an attribute of the resource, and
// AWS rejects the call when the policy grants PassRole only on other roles.

// passRoleAttributes maps a terraform resource type to the attributes that
// carry the role it passes.
var passRoleAttributes = map[string][]string{
	"aws_lambda_function":          {"role"},
	"aws_sfn_state_machine":        {"role_arn"},
	"aws_codebuild_project":        {"service_role"},
	"aws_ecs_task_definition":      {"execution_role_arn", "task_role_arn"},
	"aws_cloudwatch_event_target":  {"role_arn"},
	"aws_apigatewayv2_integration": {"credentials_arn"},
}

// passRoleMissing returns iam:PassRole when the policy does not grant it on a
// role the resource passes. A role whose ARN is not derivable from plan values
// is skipped, so only provable non-coverage is reported. With strict set, such
// a role is reported unverified instead when the policy grants PassRole only
// on some roles.
func passRoleMissing(rc *plan.ResourceChange, policy AllowedProvider, all []*plan.ResourceChange, strict bool) []MissingAction {
	if rc.Change == "delete" {
		return nil
	}
	const action = "iam:PassRole"
	for _, attr := range passRoleAttributes[rc.Type] {
		targets := roleTargetARNs(rc, attr, all)
		unverified := false
		if len(targets) == 0 {
			if !strict || !passesRole(rc, attr) || !coversAction(policy, action) || !resourceScopeUnverified(policy, action) {
				continue
			}
			unverified = true
		} else if coversActionOnTargets(policy, action, targets) {
			continue
		}
		// One finding per resource, even when it passes two roles.
		return []MissingAction{{
			ResourceType:            rc.Type,
			ResourceName:            rc.Name,
			Change:                  rc.Change,
			Action:                  action,
			Service:                 "iam",
			Class:                   classTag(ClassManagement),
			ResourceScopeUnverified: unverified,
		}}
	}
	return nil
}

// passesRole reports whether the resource may set the role attribute attr:
// the attribute holds a value, references another object, or the plan does
// not say which attributes are set.
func passesRole(rc *plan.ResourceChange, attr string) bool {
	return rc.Attributes == nil || rc.Attributes[attr] || len(rc.References[attr]) > 0
}

// roleTargetARNs derives the role ARN pattern(s) held by attr: a literal ARN,
// or a reference to a managed aws_iam_role whose name is known.
func roleTargetARNs(rc *plan.ResourceChange, attr string, all []*plan.ResourceChange) []string {
	if v := rc.AttributeValues[attr]; v != "" {
		if isARN(v) {
			return []string{v}
		}
		return nil
	}
	var patterns []string
	for _, ref := range rc.References[attr] {
		resType, resName := targetFromReference(ref)
		if resType != "aws_iam_role" {
			continue
		}
		resName = stripResourceIndex(resName)
		for _, c := range all {
			if c.Type != resType || stripResourceIndex(c.Name) != resName {
				continue
			}
			// The leading * lets the pattern match a role under a path.
			if name := c.AttributeValues["name"]; name != "" {
				patterns = append(patterns, "arn:*:iam::*:role/*"+name)
			}
		}
	}
	return patterns
}

// coversActionOnTargets reports whether the policy grants action on a
// resource matching any target pattern. With no targets, or a policy that is
// not a *PolicyDocument, it checks the action alone.
func coversActionOnTargets(policy AllowedProvider, action string, targets []string) bool {
	if !coversAction(policy, action) {
		return false
	}
	doc, ok := policy.(*PolicyDocument)
	if !ok || len(targets) == 0 {
		return true
	}
	return doc.CoversTarget(action, targets)
}
