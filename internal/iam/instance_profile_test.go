package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// desiredIAMRoleDeleteSchema is the desired aws_iam_role delete schema after
// the fix: iam:RemoveRoleFromInstanceProfile is removed from the static list
// because the provider only calls it when the role has instance profiles. The
// implied requirements logic adds it back when co-deleted instance profiles
// reference this role.
var desiredIAMRoleDeleteSchema = fakeSchema{"delete": {
	{Action: "iam:DeleteRole"},
	{Action: "iam:ListInstanceProfilesForRole"},
	{Action: "iam:ListAttachedRolePolicies"},
	{Action: "iam:DetachRolePolicy"},
	{Action: "iam:ListRolePolicies"},
	{Action: "iam:DeleteRolePolicy"},
}}

var minimalProfileSchema = fakeSchema{"delete": {
	{Action: "iam:DeleteInstanceProfile"},
}}

// TestIAMRole_DeleteAlone_DoesNotRequireRemoveFromInstanceProfile checks that
// deleting an aws_iam_role with no instance profiles in the plan does not
// report iam:RemoveRoleFromInstanceProfile. The provider calls it only after
// ListInstanceProfilesForRole returns non-empty; a role with no profiles
// attached never reaches that code path.
func TestIAMRole_DeleteAlone_DoesNotRequireRemoveFromInstanceProfile(t *testing.T) {
	role := &plan.ResourceChange{
		Type: "aws_iam_role", Name: "r", Change: "delete",
		AttributeValues: map[string]string{"name": "my-role", "id": "my-role"},
		Attributes:      map[string]bool{"name": true, "id": true},
	}
	set := newChangeSet([]*plan.ResourceChange{role})
	if m := impliedMissing(role, grantNothing(), set, false); hasAction(m, "iam:RemoveRoleFromInstanceProfile") {
		t.Error("iam:RemoveRoleFromInstanceProfile must not be implied for a role delete with no instance profiles in the plan")
	}
}

// TestIAMRole_DeleteWithCoDeletedProfile_RequiresDetach checks that deleting
// an aws_iam_role alongside an aws_iam_instance_profile whose role attribute
// names this role implies iam:RemoveRoleFromInstanceProfile. The provider calls
// RemoveRoleFromInstanceProfile for each profile ListInstanceProfilesForRole
// returns; a co-deleted profile is evidence the role has at least one.
func TestIAMRole_DeleteWithCoDeletedProfile_RequiresDetach(t *testing.T) {
	role := &plan.ResourceChange{
		Type: "aws_iam_role", Name: "r", Change: "delete",
		AttributeValues: map[string]string{"name": "my-role", "id": "my-role"},
		Attributes:      map[string]bool{"name": true, "id": true},
	}
	profile := &plan.ResourceChange{
		Type: "aws_iam_instance_profile", Name: "p", Change: "delete",
		AttributeValues: map[string]string{"role": "my-role"},
		Attributes:      map[string]bool{"role": true, "name": true},
	}
	set := newChangeSet([]*plan.ResourceChange{role, profile})
	m := impliedMissing(role, grantNothing(), set, false)
	if !hasAction(m, "iam:RemoveRoleFromInstanceProfile") {
		t.Error("iam:RemoveRoleFromInstanceProfile must be implied when a co-deleted instance profile references this role")
	}
}

// TestIAMRole_DeleteWithUnrelatedProfile_NotRequired checks that a co-deleted
// aws_iam_instance_profile whose role attribute names a different role does not
// imply iam:RemoveRoleFromInstanceProfile on this role.
func TestIAMRole_DeleteWithUnrelatedProfile_NotRequired(t *testing.T) {
	role := &plan.ResourceChange{
		Type: "aws_iam_role", Name: "r", Change: "delete",
		AttributeValues: map[string]string{"name": "my-role", "id": "my-role"},
		Attributes:      map[string]bool{"name": true, "id": true},
	}
	profile := &plan.ResourceChange{
		Type: "aws_iam_instance_profile", Name: "p", Change: "delete",
		AttributeValues: map[string]string{"role": "other-role"},
		Attributes:      map[string]bool{"role": true, "name": true},
	}
	set := newChangeSet([]*plan.ResourceChange{role, profile})
	if m := impliedMissing(role, grantNothing(), set, false); hasAction(m, "iam:RemoveRoleFromInstanceProfile") {
		t.Error("iam:RemoveRoleFromInstanceProfile must not be implied when the co-deleted profile belongs to a different role")
	}
}

// TestIAMRole_FullDelete_NoProfilesNoFalsePositive validates the full pipeline:
// a role delete with no co-deleted profiles must not report
// iam:RemoveRoleFromInstanceProfile under the desired schema (the fixed state).
func TestIAMRole_FullDelete_NoProfilesNoFalsePositive(t *testing.T) {
	role := &plan.ResourceChange{
		Type: "aws_iam_role", Name: "r", Change: "delete",
		AttributeValues: map[string]string{"name": "my-role", "id": "my-role"},
		Attributes:      map[string]bool{"name": true, "id": true},
	}
	resolver := typeKeyedResolver{"aws_iam_role": desiredIAMRoleDeleteSchema}
	missing, err := Validate([]*plan.ResourceChange{role}, grantNothing(), resolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "iam:RemoveRoleFromInstanceProfile") {
		t.Error("iam:RemoveRoleFromInstanceProfile must not appear in findings for a role delete with no instance profiles")
	}
}

// TestIAMRole_FullDelete_WithCoDeletedProfileIsRequired validates the full
// pipeline: a role delete alongside a co-deleted instance profile must report
// iam:RemoveRoleFromInstanceProfile under the desired schema.
func TestIAMRole_FullDelete_WithCoDeletedProfileIsRequired(t *testing.T) {
	role := &plan.ResourceChange{
		Type: "aws_iam_role", Name: "r", Change: "delete",
		AttributeValues: map[string]string{"name": "my-role", "id": "my-role"},
		Attributes:      map[string]bool{"name": true, "id": true},
	}
	profile := &plan.ResourceChange{
		Type: "aws_iam_instance_profile", Name: "p", Change: "delete",
		AttributeValues: map[string]string{"role": "my-role"},
		Attributes:      map[string]bool{"role": true, "name": true},
	}
	resolver := typeKeyedResolver{
		"aws_iam_role":             desiredIAMRoleDeleteSchema,
		"aws_iam_instance_profile": minimalProfileSchema,
	}
	missing, err := Validate([]*plan.ResourceChange{role, profile}, grantNothing(), resolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if !hasActionOn(missing, "iam:RemoveRoleFromInstanceProfile", "aws_iam_role", "r") {
		t.Error("iam:RemoveRoleFromInstanceProfile must appear in findings on the role when a co-deleted instance profile references it")
	}
}
