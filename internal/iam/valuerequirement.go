package iam

import "github.com/elecnix/terraform-permcheck/internal/plan"

// Value-gated cross-service requirements.
//
// Some resource types make AWS check an action in a second service on the
// caller, though the provider never calls it and no schema lists it. The
// check applies only when an attribute holds a given value. Enabling enhanced
// scanning in an ECR registry is Inspector scanning, so AWS checks
// inspector2:ListAccountPermissions when scan_type is ENHANCED and does not
// when it is BASIC.

// valueRequirement is an action AWS checks on the caller when an attribute
// holds a value.
type valueRequirement struct {
	// action is the action AWS checks.
	action string
	// attribute is the top-level attribute that gates the action.
	attribute string
	// value is the value of attribute that makes AWS check the action.
	value string
}

// valueRequirements returns the requirements of resource change rc whose
// attribute holds the gating value. An attribute the plan does not show, such
// as one computed at apply time, may hold it, so the action stays required.
// Only a create or an update applies the value: a delete applies none.
func valueRequirements(rc *plan.ResourceChange) []targeted {
	if rc.Change != "create" && rc.Change != "update" {
		return nil
	}
	var reqs []targeted
	for _, v := range resourceRules[rc.Type].valueRequirements {
		if got := rc.AttributeValues[v.attribute]; got != "" && got != v.value {
			continue
		}
		reqs = append(reqs, targeted{Requirement: Requirement{Action: v.action}})
	}
	return reqs
}
