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
func passRoleMissing(rc *plan.ResourceChange, policy *PolicyDocument, set *changeSet, strict bool) []MissingAction {
	if rc.Change == "delete" {
		return nil
	}
	const action = "iam:PassRole"
	for _, attr := range passRoleAttributes[rc.Type] {
		targets := roleTargets(rc, attr, set)
		verdict := policy.worstVerdict(action, targets, strict)
		if verdict == Covered {
			continue
		}
		// With the role unknown, the resource may pass none, so only an
		// unverified grant on a role it may pass is reported.
		if len(targets) == 0 && (verdict != Unverified || !passesRole(rc, attr)) {
			continue
		}
		// One finding per resource, even when it passes two roles.
		return []MissingAction{{
			ModuleAddress:           rc.ModuleAddress,
			ResourceType:            rc.Type,
			ResourceName:            rc.InstanceName(),
			Change:                  rc.Change,
			Action:                  action,
			Service:                 "iam",
			Class:                   classTag(classManagement),
			ResourceScopeUnverified: verdict == Unverified,
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

// roleTargets derives the roles held by attr: a literal ARN, or a
// reference to managed aws_iam_role instances whose names are known. Each
// role is one target.
func roleTargets(rc *plan.ResourceChange, attr string, set *changeSet) [][]string {
	if v := rc.AttributeValues[attr]; v != "" {
		if isARN(v) {
			return [][]string{{v}}
		}
		return nil
	}
	var targets [][]string
	for _, c := range referencedChanges(rc, set, attr, "aws_iam_role") {
		if forms := roleARNPatterns(c); forms != nil {
			targets = append(targets, forms)
		}
	}
	return targets
}

// roleARNPatterns builds the ARN patterns of a planned role from its path and
// name: role/<path><name>, where the path starts and ends with a slash. When
// the path is unknown, the role may sit at the root or under any path. It
// returns nil when the name is unknown.
func roleARNPatterns(role *plan.ResourceChange) []string {
	name := role.AttributeValues["name"]
	if name == "" {
		return nil
	}
	const prefix = "arn:*:iam::*:role"
	if path := role.AttributeValues["path"]; path != "" {
		return []string{prefix + path + name}
	}
	return []string{prefix + "/" + name, prefix + "/*/" + name}
}
