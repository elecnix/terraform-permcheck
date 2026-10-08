package provideraws

import (
	"reflect"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// TestParseResourceFileStructured_HasChangeCalls covers update-path SDK calls
// the provider makes only when an attribute changed. Such a call must be
// gated on a change of that attribute, so plan mode can suppress it when
// the plan shows no change to that attribute.
func TestParseResourceFileStructured_HasChangeCalls(t *testing.T) {
	src := `
package iam

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)

	_, err := conn.UpdateRole(ctx, &iam.UpdateRoleInput{})
	if err != nil { return nil }

	// Set a boundary only when the attribute changed.
	if d.HasChange("permissions_boundary") {
		_, err := conn.PutRolePermissionsBoundary(ctx, &iam.PutRolePermissionsBoundaryInput{})
		if err != nil { return nil }
	}

	// Remove a boundary only when the set value changed.
	if d.HasChange("permissions_boundary") {
		if v, ok := d.GetOk("permissions_boundary"); !ok {
			_ = v
			_, err := conn.DeleteRolePermissionsBoundary(ctx, &iam.DeleteRolePermissionsBoundaryInput{})
			if err != nil { return nil }
		}
	}

	// A negated guard runs its body when the attribute did NOT change, so it
	// is not a change gate: the call stays unconditional.
	if !d.HasChange("description") {
		_, err := conn.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{})
		if err != nil { return nil }
	}

	// The else branch runs when the attribute did NOT change, so it does not
	// inherit the gate of the if it negates.
	if d.HasChange("path") {
		_, err := conn.UpdateRoleDescription(ctx, &iam.UpdateRoleDescriptionInput{})
		if err != nil { return nil }
	} else {
		_, err := conn.TagRole(ctx, &iam.TagRoleInput{})
		if err != nil { return nil }
	}

	// A helper called inside a change guard inherits the gate.
	if d.HasChange("max_session_duration") {
		refreshRoleInlinePolicies(ctx, conn, d)
	}

	return nil
}

func refreshRoleInlinePolicies(ctx context.Context, conn *iam.Client, d *schema.ResourceData) {
	_, err := conn.PutRolePolicy(ctx, &iam.PutRolePolicyInput{})
	_ = err
}
`

	actions, err := ParseResourceFileStructured(src, "aws_iam_role", "Role")
	if err != nil {
		t.Fatalf("ParseResourceFileStructured failed: %v", err)
	}

	checkGates(t, withoutErrorHandling(actions), "update", []gateCase{
		// Unconditional update call stays unconditional.
		{"iam:UpdateRole", always},
		// Change-gated calls carry the attribute as a change gate.
		{"iam:PutRolePermissionsBoundary", []iam.Gate{changed("permissions_boundary")}},
		{"iam:UpdateRoleDescription", []iam.Gate{changed("path")}},
		// A presence guard nested inside a change guard keeps the outer
		// gate, which is the stricter of the two.
		{"iam:DeleteRolePermissionsBoundary", []iam.Gate{changed("permissions_boundary")}},
		// A negated guard and an else branch are not change gates.
		{"iam:DeleteRolePolicy", always},
		{"iam:TagRole", always},
		// Helper calls inherit the call-site gate.
		{"iam:PutRolePolicy", []iam.Gate{changed("max_session_duration")}},
	})
}

// TestBranchGuards covers each guard form the parser reads, the gate it puts
// on the body and the gate it puts on the else branch, including the
// d.HasChange forms and the methods that are not gates.
func TestBranchGuards(t *testing.T) {
	pres := func(a string) []condGuard { return []condGuard{{Attribute: a}} }
	chg := func(a string) []condGuard { return []condGuard{{Attribute: a, Change: true}} }
	tests := []struct {
		src       string
		then, els []condGuard
	}{
		{`if v, ok := d.GetOk("kms_key_arn"); ok { foo() }`, pres("kms_key_arn"), nil},
		{`if d.Get("force_destroy").(bool) { foo() }`, pres("force_destroy"), nil},
		{`if d.HasChange("permissions_boundary") { foo() }`, chg("permissions_boundary"), nil},
		// A negated guard runs its body when the guard is false, and its
		// else branch when the guard holds.
		{`if !d.HasChange("permissions_boundary") { foo() }`, nil, chg("permissions_boundary")},
		{`if !d.Get("force_destroy").(bool) { foo() }`, nil, pres("force_destroy")},
		{`if _, ok := d.GetOk("x"); !ok { foo() }`, nil, pres("x")},
		{`if (d.HasChange("permissions_boundary")) { foo() }`, chg("permissions_boundary"), nil},
		// A guard bound in the init statement gates the branch whose
		// outcome implies it.
		{`if changed := d.HasChange("x"); changed { foo() }`, chg("x"), nil},
		{`if changed := d.HasChange("x"); !changed { foo() }`, nil, chg("x")},
		{`if changed := d.HasChange("x"); changed && other { foo() }`, chg("x"), nil},
		{`if changed := d.HasChange("x"); changed || other { foo() }`, nil, nil},
		{`if changed := d.HasChange("x"); other { foo() }`, nil, nil},
		{`if v, ok := d.GetOk("x"); v.(int) < 5 { foo() }`, nil, nil},
		// d.HasChanges gates on a change to any of its attributes.
		{`if d.HasChanges("a", "b") { foo() }`, append(chg("a"), chg("b")...), nil},
		{`if d.HasChange("a") || d.HasChange("b") { foo() }`, append(chg("a"), chg("b")...), nil},
		{`if err != nil { foo() }`, nil, nil},
		{`if d.HasChangesExcept("tags") { foo() }`, nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			ifStmt := firstIfStmt(t, "func f() {\n"+tt.src+"\n}")
			then, els := branchGuards(ifStmt, initGuardVars(ifStmt.Init, nil), &walkContext{})
			if !reflect.DeepEqual(then, tt.then) || !reflect.DeepEqual(els, tt.els) {
				t.Errorf("branchGuards = (%+v, %+v), want (%+v, %+v)", then, els, tt.then, tt.els)
			}
		})
	}
}

// TestParseResourceFileStructured_ElseIfChangeChain checks that an else-if
// chain does not carry the first guard into a later guard's gate: each branch
// takes only the gate of the guard that controls it.
func TestParseResourceFileStructured_ElseIfChangeChain(t *testing.T) {
	src := `
package iam

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)

	if d.HasChange("path") {
		conn.UpdateRoleDescription(ctx, &iam.UpdateRoleDescriptionInput{})
	} else if d.HasChange("description") {
		conn.PutRolePolicy(ctx, &iam.PutRolePolicyInput{})
	} else {
		conn.TagRole(ctx, &iam.TagRoleInput{})
	}
	return nil
}
`
	actions, err := ParseResourceFileStructured(src, "aws_iam_role", "Role")
	if err != nil {
		t.Fatal(err)
	}
	checkGates(t, withoutErrorHandling(actions), "update", []gateCase{
		{"iam:UpdateRoleDescription", []iam.Gate{changed("path")}},
		{"iam:PutRolePolicy", []iam.Gate{changed("description")}},
		{"iam:TagRole", always},
	})
}

// TestParseResourceFileStructured_UnconditionalFirstKeepsNoKind covers an action
// called both unconditionally and under a change guard: the one surviving
// requirement is ungated, whichever call comes first.
func TestParseResourceFileStructured_UnconditionalFirstKeepsNoKind(t *testing.T) {
	for name, body := range map[string]string{
		"unconditional first": `conn.PutRolePolicy(ctx, &iam.PutRolePolicyInput{})
	if d.HasChange("description") {
		conn.PutRolePolicy(ctx, &iam.PutRolePolicyInput{})
	}`,
		"gated first": `if d.HasChange("description") {
		conn.PutRolePolicy(ctx, &iam.PutRolePolicyInput{})
	}
	conn.PutRolePolicy(ctx, &iam.PutRolePolicyInput{})`,
	} {
		t.Run(name, func(t *testing.T) {
			src := "package iam\nfunc resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {\n\tconn := meta.(*conns.AWSClient).IAMClient(ctx)\n\t" + body + "\n\treturn nil\n}\n"
			actions, err := ParseResourceFileStructured(src, "aws_iam_role", "Role")
			if err != nil {
				t.Fatal(err)
			}
			want := []iam.Requirement{{Action: "iam:PutRolePolicy"}}
			if got := ignoreErrorHandling(actions["update"]); !reflect.DeepEqual(got, want) {
				t.Errorf("update = %+v, want the single ungated %+v", got, want)
			}
		})
	}
}

// TestParseResourceFileStructured_InitFormChangeGuard covers a change guard
// bound in the init statement: the body is gated, the else branch is not, and a
// negated condition gates nothing.
func TestParseResourceFileStructured_InitFormChangeGuard(t *testing.T) {
	src := `
package iam

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)

	if changed := d.HasChange("path"); changed {
		conn.UpdateRoleDescription(ctx, &iam.UpdateRoleDescriptionInput{})
	} else {
		conn.TagRole(ctx, &iam.TagRoleInput{})
	}

	if changed := d.HasChange("description"); !changed {
		conn.PutRolePolicy(ctx, &iam.PutRolePolicyInput{})
	}
	return nil
}
`
	actions, err := ParseResourceFileStructured(src, "aws_iam_role", "Role")
	if err != nil {
		t.Fatal(err)
	}
	checkGates(t, withoutErrorHandling(actions), "update", []gateCase{
		{"iam:UpdateRoleDescription", []iam.Gate{changed("path")}},
		{"iam:TagRole", always},
		{"iam:PutRolePolicy", always},
	})
}
