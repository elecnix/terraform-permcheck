package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// roleCreateWithInlinePolicyGate is the aws_iam_role create schema after the
// inline_policy correction: iam:GetRolePolicy runs only when the role has an
// inline policy, which iam:PutRolePolicy on the same path is already gated on.
var roleCreateWithInlinePolicyGate = fakeSchema{"create": {
	{Action: "iam:CreateRole"},
	{Action: "iam:PutRolePolicy", Gate: Gate{Attribute: "inline_policy", ValueGuarded: true}},
	{Action: "iam:GetRolePolicy", Gate: Gate{Attribute: "inline_policy", ValueGuarded: true}},
}}

// TestIAMRole_CreateWithoutInlinePolicy_DoesNotRequireGetRolePolicy checks
// that a role whose configuration writes no inline policy does not report
// iam:GetRolePolicy. The provider reads the policy once per name
// ListRolePolicies returned, and an inline-policy-free role returns none.
func TestIAMRole_CreateWithoutInlinePolicy_DoesNotRequireGetRolePolicy(t *testing.T) {
	role := &plan.ResourceChange{
		Type: "aws_iam_role", Name: "r", Change: "create",
		Attributes: map[string]bool{"name": true},
		Configured: map[string]bool{"name": true, "inline_policy": false},
	}
	resolver := typeKeyedResolver{"aws_iam_role": roleCreateWithInlinePolicyGate}
	missing, err := Validate([]*plan.ResourceChange{role}, grantNothing(), resolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "iam:GetRolePolicy") {
		t.Error("iam:GetRolePolicy must not be reported for a role with no inline policy")
	}
	if !hasAction(missing, "iam:CreateRole") {
		t.Error("iam:CreateRole must still be reported")
	}
}

// TestIAMRole_CreateWithInlinePolicy_RequiresGetRolePolicy checks that a role
// whose configuration writes an inline policy does report iam:GetRolePolicy,
// because the provider reads each policy it wrote.
func TestIAMRole_CreateWithInlinePolicy_RequiresGetRolePolicy(t *testing.T) {
	role := &plan.ResourceChange{
		Type: "aws_iam_role", Name: "r", Change: "create",
		Attributes: map[string]bool{"name": true, "inline_policy": true},
		Configured: map[string]bool{"name": true, "inline_policy": true},
	}
	resolver := typeKeyedResolver{"aws_iam_role": roleCreateWithInlinePolicyGate}
	missing, err := Validate([]*plan.ResourceChange{role}, grantNothing(), resolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "iam:GetRolePolicy") {
		t.Error("iam:GetRolePolicy must be reported for a role that writes an inline policy")
	}
}

// TestIAMRole_NoStateAtAll_KeepsGetRolePolicy checks that a change carrying
// neither state nor configuration keeps iam:GetRolePolicy. Presence is
// unknown there, and an unknown test counts as holding, so the permission
// stays reported rather than guessed away.
func TestIAMRole_NoStateAtAll_KeepsGetRolePolicy(t *testing.T) {
	role := &plan.ResourceChange{
		Type: "aws_iam_role", Name: "r", Change: "create",
	}
	resolver := typeKeyedResolver{"aws_iam_role": roleCreateWithInlinePolicyGate}
	missing, err := Validate([]*plan.ResourceChange{role}, grantNothing(), resolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "iam:GetRolePolicy") {
		t.Error("iam:GetRolePolicy must stay reported when the plan shows nothing either way")
	}
}
