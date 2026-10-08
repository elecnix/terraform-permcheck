package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// TestValidate_AnyGateHolds covers an action the provider reaches on two
// paths with different gates: dynamodb:TagResource runs when tags are set,
// and again for replicas when a replica is configured. The action is needed
// when either gate holds.
func TestValidate_AnyGateHolds(t *testing.T) {
	schema := fakeSchema{"create": {
		{Action: "dynamodb:TagResource", Gate: Gate{Attribute: "tags"}},
		{Action: "dynamodb:TagResource", Gate: Gate{Attribute: "replica", ValueGuarded: true}},
	}}
	cases := []struct {
		name       string
		attrs      map[string]bool
		configured map[string]bool
		want       string // ConditionAttribute, or "-" for no finding
	}{
		{"neither gate holds", map[string]bool{"name": true, "replica": true}, map[string]bool{"name": true}, "-"},
		{"tags set", map[string]bool{"tags": true}, map[string]bool{"tags": true}, "tags"},
		{"replica configured", map[string]bool{"replica": true}, map[string]bool{"replica": true}, "replica"},
		{"both hold", map[string]bool{"tags": true, "replica": true}, map[string]bool{"tags": true, "replica": true}, "tags|replica"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			changes := []*plan.ResourceChange{{
				Type: "aws_dynamodb_table", Name: "items", Change: "create",
				Attributes: c.attrs, Configured: c.configured,
			}}
			missing, err := Validate(changes, denyAll{}, fakeResolver{schema}, FilterConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if c.want == "-" {
				if len(missing) != 0 {
					t.Errorf("expected no finding, got %+v", missing)
				}
				return
			}
			if len(missing) != 1 || missing[0].ConditionAttribute != c.want {
				t.Errorf("expected one finding gated on %q, got %+v", c.want, missing)
			}
		})
	}
}

// TestValidate_AnyGateUngatedPath covers an action that one path reaches with
// no gate: it is required whatever the other gates say.
func TestValidate_AnyGateUngatedPath(t *testing.T) {
	schema := fakeSchema{"create": {
		{Action: "apigateway:POST", Gate: Gate{Attribute: "tags"}},
		{Action: "apigateway:POST"},
	}}
	changes := []*plan.ResourceChange{{Type: "aws_apigatewayv2_domain_name", Name: "api", Change: "create", Attributes: map[string]bool{}}}
	missing, err := Validate(changes, denyAll{}, fakeResolver{schema}, FilterConfig{ExcludeConditional: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].ConditionAttribute != "" || missing[0].Class != "[required]" {
		t.Errorf("expected one ungated [required] finding, got %+v", missing)
	}
}

// TestValidate_AnyGateRequiredPathDecidesTag covers an action that a
// best-effort path always reaches and a checked path reaches when an
// attribute is set. With the attribute set, the action is required and the
// tag names that attribute.
func TestValidate_AnyGateRequiredPathDecidesTag(t *testing.T) {
	schema := fakeSchema{"create": {
		{Action: "widget:PutWidgetNote", Gate: Gate{BestEffort: true}},
		{Action: "widget:PutWidgetNote", Gate: Gate{Attribute: "note"}},
	}}
	for _, c := range []struct {
		attrs     map[string]bool
		wantClass string
		wantAttr  string
	}{
		{map[string]bool{"note": true}, "[required]", "note"},
		{map[string]bool{}, "[optional]", ""},
	} {
		changes := []*plan.ResourceChange{{Type: "aws_widget", Name: "w", Change: "create", Attributes: c.attrs}}
		missing, err := Validate(changes, denyAll{}, fakeResolver{schema}, FilterConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != 1 || missing[0].Class != c.wantClass || missing[0].ConditionAttribute != c.wantAttr {
			t.Errorf("attrs %v: got %+v, want one %s finding tagged %q", c.attrs, missing, c.wantClass, c.wantAttr)
		}
	}
}

// TestValidate_AnyGateChangeAndBestEffort covers a change gate and a
// best-effort path. The action is optional when only best-effort paths hold,
// and required when a path whose failure counts holds.
func TestValidate_AnyGateChangeAndBestEffort(t *testing.T) {
	schema := fakeSchema{"update": {
		{Action: "iam:UpdateRolePolicy", Gate: Gate{Changed: "policy"}},
		{Action: "iam:UpdateRolePolicy", Gate: Gate{Attribute: "tags", BestEffort: true}},
	}}
	cases := []struct {
		name    string
		changed map[string]bool
		want    string // Class, or "-" for no finding
	}{
		{"policy changed", map[string]bool{"policy": true}, "[required]"},
		{"only the best-effort path holds", map[string]bool{"policy": false}, "[optional]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			changes := []*plan.ResourceChange{{
				Type: "aws_iam_role", Name: "r", Change: "update",
				Attributes: map[string]bool{"tags": true}, ChangedAttributes: c.changed,
			}}
			missing, err := Validate(changes, denyAll{}, fakeResolver{schema}, FilterConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if len(missing) != 1 || missing[0].Class != c.want {
				t.Errorf("expected one %s finding, got %+v", c.want, missing)
			}
		})
	}

	// Neither gate holds.
	changes := []*plan.ResourceChange{{
		Type: "aws_iam_role", Name: "r", Change: "update",
		Attributes: map[string]bool{}, ChangedAttributes: map[string]bool{"policy": false},
	}}
	missing, err := Validate(changes, denyAll{}, fakeResolver{schema}, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("expected no finding, got %+v", missing)
	}
}
