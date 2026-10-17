package iam

import "github.com/elecnix/terraform-permcheck/internal/plan"

// Service-linked roles.
//
// Some resources make their service create a service-linked role in the
// caller's account the first time the service is used. AWS checks
// iam:CreateServiceLinkedRole against the caller, but the provider never
// calls it and no schema lists it. The role lives under
// role/aws-service-role/<service principal>/, so a grant scoped to that path
// covers it.
//
// AWS creates the role only when the account has none, so a policy that lacks
// the grant can pass for months and fail on the first apply in a fresh
// account. The requirement is therefore reported for every create.

// serviceLinkedRoleRequirements returns iam:CreateServiceLinkedRole for each
// service-linked role the resource may cause AWS to create. Only a create
// triggers it.
func serviceLinkedRoleRequirements(rc *plan.ResourceChange) []targeted {
	if rc.Change != "create" {
		return nil
	}
	var reqs []targeted
	for _, principal := range resourceRules[rc.Type].serviceLinkedRoles {
		reqs = append(reqs, targeted{
			Requirement: Requirement{Action: "iam:CreateServiceLinkedRole"},
			targets:     [][]string{{"arn:*:iam::*:role/aws-service-role/" + principal + "/*"}},
		})
	}
	return reqs
}
