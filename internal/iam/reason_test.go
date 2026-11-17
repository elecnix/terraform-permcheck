package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// TestNewFinding_KeepsEveryUnverifiedReason checks that each reason the
// policy package reports marks the finding unverified. A reason the finding
// dropped would print the action as missing.
func TestNewFinding_KeepsEveryUnverifiedReason(t *testing.T) {
	cases := []struct {
		reason policy.UnverifiedReason
		marked func(MissingAction) bool
	}{
		{policy.ReasonResourceScope, func(m MissingAction) bool { return m.ResourceScopeUnverified }},
		{policy.ReasonCondition, func(m MissingAction) bool { return m.ConditionUnverified }},
		{policy.ReasonPolicyUnknown, func(m MissingAction) bool { return m.PolicyUnknownUnverified }},
		{policy.ReasonCrossAccount, func(m MissingAction) bool { return m.CrossAccountUnverified }},
	}
	for _, c := range cases {
		m := newFinding("ssm:GetParameter", ClassManagement, policy.Result{Verdict: policy.Unverified, Reason: c.reason})
		if !c.marked(m) {
			t.Errorf("%s: the finding does not carry the reason: %+v", c.reason.Value(), m)
		}
	}
}
