package iam

import (
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// Condition keys the plan can supply.
//
// A policy may grant an action only when a condition key holds a value the
// plan shows. The tool can then check the grant: when the key's value is
// derivable and the condition provably cannot match it, the grant does not
// apply and the action is missing. When the key is not derivable, the tool
// cannot check the grant, and --strict-resources reports it as unverified.
//
// The table is the sibling of resourceTargets (see resource_scope.go): both
// turn a resource change into facts a policy check can use.

// conditionKey is a condition key a resource change supplies.
type conditionKey struct {
	// name is the condition key as AWS names it, e.g. "lambda:FunctionArn".
	name string
	// attribute is the plan attribute holding the key's value.
	attribute string
	// arn reports whether the value is an ARN. A value that is not an ARN
	// cannot be compared with an ARN pattern, so the tool treats it as
	// unknown rather than as a mismatch.
	arn bool
}

// conditionKeyRule ties a condition key to the actions it gates.
type conditionKeyRule struct {
	// actions lists the actions the key gates. "*" stands for every action
	// of the resource type.
	actions []string
	// key is the condition key itself.
	key conditionKey
}

// gatesAction reports whether the rule's key gates an action.
func (r conditionKeyRule) gatesAction(action string) bool {
	for _, a := range r.actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

// conditionValues returns the condition key values the plan supplies for an
// action, keyed by condition key name. A key whose value the plan does not
// show is absent, so a condition on it stays unknown.
//
// The values come from the plan's attribute values, which hold only the
// concrete strings the plan shows: a value computed at apply time is
// absent, and so is a value that is not a string.
func conditionValues(rc *plan.ResourceChange, rule resourceRule, action string) policy.Conditions {
	if len(rule.conditionKeys) == 0 {
		return nil
	}
	var values policy.Conditions
	for _, ck := range rule.conditionKeys {
		if !ck.gatesAction(action) {
			continue
		}
		value := rc.AttributeValues[ck.key.attribute]
		if value == "" {
			continue
		}
		if ck.key.arn && !isARN(value) {
			// A bare function name, not an ARN: the tool cannot
			// compare it with an ARN pattern, so the key stays
			// unknown.
			continue
		}
		if values == nil {
			values = policy.Conditions{}
		}
		values[ck.key.name] = value
	}
	return values
}
