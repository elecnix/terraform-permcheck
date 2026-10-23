package provideraws

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// roleCreateSchema is the part of the parsed aws_iam_role create schema the
// gate corrections act on: iam:PutRolePolicy already carries the inline_policy
// guard the parser found, and iam:GetRolePolicy carries none, because the
// provider reaches it from a loop over names ListRolePolicies returned.
func roleCreateSchema() *iam.Schema {
	return &iam.Schema{
		TypeName: "aws_iam_role",
		Ops: map[string][]iam.Requirement{
			"create": {
				{Action: "iam:CreateRole"},
				{Action: "iam:PutRolePolicy", Gate: iam.Gate{Attribute: "inline_policy", ValueGuarded: true}},
				{Action: "iam:GetRolePolicy"},
			},
			"delete": {
				{Action: "iam:DeleteRole"},
			},
		},
	}
}

// TestApplySchemaGates_GatesGetRolePolicyOnInlinePolicy checks that the
// aws_iam_role correction gives iam:GetRolePolicy the same inline_policy guard
// iam:PutRolePolicy already has. The provider reads GetRolePolicy once per
// name ListRolePolicies returned, and a role with no inline policy yields no
// name, so the call runs only when the author wrote an inline policy.
func TestApplySchemaGates_GatesGetRolePolicyOnInlinePolicy(t *testing.T) {
	schema := roleCreateSchema()
	applySchemaGates(schema)

	want := iam.Gate{Attribute: "inline_policy", ValueGuarded: true}
	gates := schema.Gates("create", "iam:GetRolePolicy")
	if len(gates) != 1 {
		t.Fatalf("create iam:GetRolePolicy has %d paths, want 1", len(gates))
	}
	if gates[0] != want {
		t.Errorf("create iam:GetRolePolicy gate = %+v, want %+v", gates[0], want)
	}
}

// TestApplySchemaGates_LeavesUngatedActionsAlone checks that the correction
// changes only the action it names. iam:CreateRole on the same operation keeps
// its ungated path, since the provider always creates the role.
func TestApplySchemaGates_LeavesUngatedActionsAlone(t *testing.T) {
	schema := roleCreateSchema()
	applySchemaGates(schema)

	for _, action := range []string{"iam:CreateRole", "iam:PutRolePolicy"} {
		before := roleCreateSchema().Gates("create", action)
		after := schema.Gates("create", action)
		if len(after) != len(before) {
			t.Fatalf("%s has %d paths after the correction, want %d", action, len(after), len(before))
		}
		for i := range before {
			if after[i] != before[i] {
				t.Errorf("%s path %d = %+v, want %+v", action, i, after[i], before[i])
			}
		}
	}
}

// TestApplySchemaGates_LeavesOtherOperationsAndTypesAlone checks that the
// correction is scoped to its operation, so a delete path that also reaches
// the action keeps its own gate.
func TestApplySchemaGates_LeavesOtherOperationsAndTypesAlone(t *testing.T) {
	schema := roleCreateSchema()
	schema.Ops["delete"] = append(schema.Ops["delete"], iam.Requirement{Action: "iam:GetRolePolicy"})
	applySchemaGates(schema)

	gates := schema.Gates("delete", "iam:GetRolePolicy")
	if len(gates) != 1 || !gates[0].Ungated() {
		t.Errorf("delete iam:GetRolePolicy gate = %+v, want an ungated path", gates)
	}

	other := &iam.Schema{
		TypeName: "aws_iam_user",
		Ops:      map[string][]iam.Requirement{"create": {{Action: "iam:GetRolePolicy"}}},
	}
	applySchemaGates(other)
	if gates := other.Gates("create", "iam:GetRolePolicy"); !gates[0].Ungated() {
		t.Errorf("aws_iam_user create iam:GetRolePolicy gate = %+v, want an ungated path", gates[0])
	}
}

// TestApplySchemaGates_EveryEntryNamesAKnownOperation checks that each
// correction names an operation the schema actually has, so a typo in the
// table cannot silently do nothing.
func TestApplySchemaGates_EveryEntryNamesAKnownOperation(t *testing.T) {
	for _, g := range schemaGates {
		if g.op == "" || g.action == "" || g.tfType == "" {
			t.Errorf("incomplete entry: %+v", g)
		}
		if g.gate.Ungated() && g.gate.Changed == "" {
			t.Errorf("%s %s %s: a gate the parser cannot derive must test something", g.tfType, g.op, g.action)
		}
	}
}
