package iam

import "github.com/elecnix/terraform-permcheck/internal/plan"

// iam:PassRole.
//
// Resources that hand an IAM role to a service need iam:PassRole on that
// role's ARN. The terraform provider never calls iam:PassRole itself, so no
// schema lists it. The role is named by an attribute of the resource, and
// AWS rejects the call when the policy grants PassRole only on other roles.

// passRoleRequirements returns iam:PassRole on each role the resource
// passes. A delete passes no role. A role the plan does not show is checked
// only when the resource may set its attribute, and then only a grant scoped
// to other roles under --strict-resources is reported (see
// knownTargetsOnly). Every requirement is ungated, so a resource that passes
// two roles has one finding.
func passRoleRequirements(rc *plan.ResourceChange, set *changeSet) []targeted {
	if rc.Change == "delete" {
		return nil
	}
	var reqs []targeted
	for _, attr := range resourceRules[rc.Type].passesRole {
		targets := roleTargets(rc, attr, set)
		if len(targets) == 0 && !passesRole(rc, attr) {
			continue
		}
		reqs = append(reqs, targeted{
			Requirement:      Requirement{Action: "iam:PassRole"},
			targets:          targets,
			knownTargetsOnly: true,
		})
	}
	return reqs
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
	return attributeTargets(rc, set, attr, "aws_iam_role", roleARNPatterns)
}
