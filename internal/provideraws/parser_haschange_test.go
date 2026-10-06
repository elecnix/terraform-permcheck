package provideraws

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestParseResourceFileStructured_HasChangeCalls covers update-path SDK calls
// the provider makes only when an attribute changed. Such a call must be
// marked conditional with the change kind, so plan mode can suppress it when
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

	updateActions := actions["update"]

	byAction := make(map[string]ExtractedAction, len(updateActions))
	for _, ea := range updateActions {
		byAction[ea.Action] = ea
	}

	// Unconditional update call stays unconditional.
	if ea, ok := byAction["iam:UpdateRole"]; !ok {
		t.Error("expected iam:UpdateRole in update actions")
	} else if ea.Conditional {
		t.Errorf("iam:UpdateRole should be unconditional, got condition %q", ea.Condition)
	}

	// Change-gated calls carry the attribute and the change kind.
	for _, action := range []string{
		"iam:PutRolePermissionsBoundary",
		"iam:DeleteRolePermissionsBoundary",
		"iam:UpdateRoleDescription",
	} {
		ea, ok := byAction[action]
		if !ok {
			t.Errorf("expected %s in update actions, got %v", action, updateActions)
			continue
		}
		if !ea.Conditional {
			t.Errorf("%s should be conditional", action)
		}
		if ea.ConditionKind != ConditionChange {
			t.Errorf("%s condition kind = %q, want %q", action, ea.ConditionKind, ConditionChange)
		}
	}

	if ea := byAction["iam:PutRolePermissionsBoundary"]; ea.Condition != "permissions_boundary" {
		t.Errorf("PutRolePermissionsBoundary condition = %q, want permissions_boundary", ea.Condition)
	}
	if ea := byAction["iam:UpdateRoleDescription"]; ea.Condition != "path" {
		t.Errorf("UpdateRoleDescription condition = %q, want path", ea.Condition)
	}

	// A negated guard and an else branch are not change gates.
	for _, action := range []string{"iam:DeleteRolePolicy", "iam:TagRole"} {
		ea, ok := byAction[action]
		if !ok {
			t.Errorf("expected %s in update actions, got %v", action, updateActions)
			continue
		}
		if ea.Conditional || ea.Condition != "" || ea.ConditionKind != "" {
			t.Errorf("%s should be unconditional, got (%v, %q, %q)",
				action, ea.Conditional, ea.Condition, ea.ConditionKind)
		}
	}

	// A presence guard nested inside a change guard keeps the outer gate, which
	// is the stricter of the two.
	if ea := byAction["iam:DeleteRolePermissionsBoundary"]; ea.ConditionKind != ConditionChange || ea.Condition != "permissions_boundary" {
		t.Errorf("DeleteRolePermissionsBoundary gate = (%q, %q), want (%q, permissions_boundary)",
			ea.ConditionKind, ea.Condition, ConditionChange)
	}

	// Helper calls inherit the call-site gate.
	ea, ok := byAction["iam:PutRolePolicy"]
	if !ok {
		t.Errorf("expected iam:PutRolePolicy from the helper call, got %v", updateActions)
	} else {
		if !ea.Conditional || ea.ConditionKind != ConditionChange || ea.Condition != "max_session_duration" {
			t.Errorf("iam:PutRolePolicy gate = (%v, %q, %q), want (true, %q, max_session_duration)",
				ea.Conditional, ea.ConditionKind, ea.Condition, ConditionChange)
		}
	}
}

// TestExtractConditionGuard covers each guard form the parser reads, including
// the d.HasChange forms and the methods that are not gates.
func TestExtractConditionGuard(t *testing.T) {
	tests := []struct {
		src      string
		wantAttr string
		wantKind ConditionKind
	}{
		{`if v, ok := d.GetOk("kms_key_arn"); ok { foo() }`, "kms_key_arn", ConditionPresence},
		{`if d.Get("force_destroy").(bool) { foo() }`, "force_destroy", ConditionPresence},
		{`if d.HasChange("permissions_boundary") { foo() }`, "permissions_boundary", ConditionChange},
		// A negated guard runs its body when the guard is false, so it gates
		// nothing the validator can evaluate.
		{`if !d.HasChange("permissions_boundary") { foo() }`, "", ""},
		{`if !d.Get("force_destroy").(bool) { foo() }`, "", ""},
		{`if (d.HasChange("permissions_boundary")) { foo() }`, "permissions_boundary", ConditionChange},
		// Only the single-attribute form is a gate: d.HasChanges spans several
		// attributes, and recording just one of them would mis-gate the call.
		{`if d.HasChanges("a", "b") { foo() }`, "", ""},
		{`if err != nil { foo() }`, "", ""},
		{`if d.HasChangesExcept("tags") { foo() }`, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			src := "package x\nfunc f() {\n" + tt.src + "\n}"
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			var gotAttr string
			var gotKind ConditionKind
			ast.Inspect(f, func(n ast.Node) bool {
				if ifStmt, ok := n.(*ast.IfStmt); ok {
					guard := extractConditionGuard(ifStmt)
					gotAttr, gotKind = guard.Attribute, guard.Kind
					return false
				}
				return true
			})

			if gotAttr != tt.wantAttr || gotKind != tt.wantKind {
				t.Errorf("extractConditionGuard = (%q, %q), want (%q, %q)",
					gotAttr, gotKind, tt.wantAttr, tt.wantKind)
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
	got := map[string]ExtractedAction{}
	for _, ea := range actions["update"] {
		got[ea.Action] = ea
	}
	want := map[string]string{
		"iam:UpdateRoleDescription": "path",
		"iam:PutRolePolicy":         "description",
		"iam:TagRole":               "",
	}
	for action, attr := range want {
		ea, ok := got[action]
		if !ok {
			t.Errorf("expected %s, got %v", action, actions["update"])
			continue
		}
		if ea.Condition != attr {
			t.Errorf("%s condition = %q, want %q", action, ea.Condition, attr)
		}
		if attr == "" && (ea.Conditional || ea.ConditionKind != "") {
			t.Errorf("%s should be unconditional, got (%v, %q)", action, ea.Conditional, ea.ConditionKind)
		}
	}
}

// TestParseResourceFileStructured_UnconditionalFirstKeepsNoKind covers an action
// called both unconditionally and under a change guard: the surviving entry is
// unconditional and carries no gate kind, whichever call comes first.
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
			if len(actions["update"]) != 1 {
				t.Fatalf("expected one deduplicated action, got %v", actions["update"])
			}
			ea := actions["update"][0]
			if ea.Conditional || ea.Condition != "" || ea.ConditionKind != "" {
				t.Errorf("got (%v, %q, %q), want an unconditional entry with no kind",
					ea.Conditional, ea.Condition, ea.ConditionKind)
			}
		})
	}
}
