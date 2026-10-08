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
			missing, err := Validate(changes, grantNothing(), fakeResolver{schema}, FilterConfig{})
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
	missing, err := Validate(changes, grantNothing(), fakeResolver{schema}, FilterConfig{ExcludeConditional: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].ConditionAttribute != "" || missing[0].Class != ClassManagement {
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
		wantClass Class
		wantAttr  string
	}{
		{map[string]bool{"note": true}, ClassManagement, "note"},
		{map[string]bool{}, ClassOptional, ""},
	} {
		changes := []*plan.ResourceChange{{Type: "aws_widget", Name: "w", Change: "create", Attributes: c.attrs}}
		missing, err := Validate(changes, grantNothing(), fakeResolver{schema}, FilterConfig{})
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
		want    Class
	}{
		{"policy changed", map[string]bool{"policy": true}, ClassManagement},
		{"only the best-effort path holds", map[string]bool{"policy": false}, ClassOptional},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			changes := []*plan.ResourceChange{{
				Type: "aws_iam_role", Name: "r", Change: "update",
				Attributes: map[string]bool{"tags": true}, ChangedAttributes: c.changed,
			}}
			missing, err := Validate(changes, grantNothing(), fakeResolver{schema}, FilterConfig{})
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
	missing, err := Validate(changes, grantNothing(), fakeResolver{schema}, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("expected no finding, got %+v", missing)
	}
}

// TestValidate_NestedGatePaths covers gates on a nested attribute path such
// as ttl.0.enabled. The plan's nested value decides them, not the top-level
// attribute name, which never matches the path.
func TestValidate_NestedGatePaths(t *testing.T) {
	schema := fakeSchema{
		"create": {
			{Action: "dynamodb:CreateTable"},
			{Action: "dynamodb:UpdateTimeToLive", Gate: Gate{Attribute: "ttl.0.enabled"}},
			{Action: "dynamodb:UpdateContinuousBackups", Gate: Gate{Attribute: "point_in_time_recovery.0.enabled"}},
		},
		"update": {
			{Action: "kinesis:UpdateStreamMode", Gate: Gate{Changed: "stream_mode_details.0.stream_mode"}},
			{Action: "kinesis:IncreaseStreamRetentionPeriod", Gate: Gate{Changed: "retention_period"}},
		},
	}
	changes, err := plan.Parse([]byte(`{"resource_changes":[
{"type":"aws_dynamodb_table","name":"t","change":{"actions":["create"],"before":null,
 "after":{"ttl":[{"enabled":true,"attribute_name":"exp"}],"point_in_time_recovery":[{"enabled":false}]},"after_unknown":{}}},
{"type":"aws_kinesis_stream","name":"s","change":{"actions":["update"],
 "before":{"stream_mode_details":[{"stream_mode":"PROVISIONED"}],"retention_period":24},
 "after":{"stream_mode_details":[{"stream_mode":"ON_DEMAND"}],"retention_period":24},"after_unknown":{}}}
]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	missing, err := Validate(changes, grantActions("dynamodb:CreateTable"), fakeResolver{schema}, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, m := range missing {
		got[m.Action] = m.ConditionAttribute
	}
	if got["dynamodb:UpdateTimeToLive"] != "ttl.0.enabled" {
		t.Errorf("UpdateTimeToLive not reported gated on ttl.0.enabled: %+v", missing)
	}
	if _, ok := got["dynamodb:UpdateContinuousBackups"]; ok {
		t.Errorf("UpdateContinuousBackups reported with recovery disabled: %+v", missing)
	}
	if got["kinesis:UpdateStreamMode"] != "stream_mode_details.0.stream_mode" {
		t.Errorf("UpdateStreamMode not reported for a mode change: %+v", missing)
	}
	if _, ok := got["kinesis:IncreaseStreamRetentionPeriod"]; ok {
		t.Errorf("retention call reported with retention unchanged: %+v", missing)
	}
}

// TestValidate_NestedGateWithoutState covers a resource change that carries
// only top-level maps, as tests and static HCL build them. The first segment
// of the path decides.
func TestValidate_NestedGateWithoutState(t *testing.T) {
	schema := fakeSchema{"create": {{Action: "dynamodb:UpdateTimeToLive", Gate: Gate{Attribute: "ttl.0.enabled"}}}}
	for _, c := range []struct {
		attrs map[string]bool
		want  int
	}{{map[string]bool{"ttl": true}, 1}, {map[string]bool{"ttl": false}, 0}, {nil, 1}} {
		changes := []*plan.ResourceChange{{Type: "aws_dynamodb_table", Name: "t", Change: "create", Attributes: c.attrs}}
		missing, err := Validate(changes, grantNothing(), fakeResolver{schema}, FilterConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != c.want {
			t.Errorf("attrs %v: got %d findings, want %d", c.attrs, len(missing), c.want)
		}
	}
}
