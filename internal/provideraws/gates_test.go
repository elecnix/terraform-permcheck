package provideraws

import (
	"reflect"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// TestDedupActions_AnyPathGate covers an action reached on two paths with
// different gates. It is needed when either gate holds, so both gates stay.
func TestDedupActions_AnyPathGate(t *testing.T) {
	tags := ExtractedAction{Action: "x:A", Conditional: true, Condition: "tags", ConditionKind: ConditionPresence}
	replica := ExtractedAction{Action: "x:A", Conditional: true, Condition: "replica", ConditionKind: ConditionPresence, ValueGuarded: true}
	changed := ExtractedAction{Action: "x:A", Conditional: true, Condition: "policy", ConditionKind: ConditionChange}
	cleanup := ExtractedAction{Action: "x:A", BestEffort: true}

	got := dedupActions([]ExtractedAction{tags, replica, changed, cleanup})
	want := []iam.Gate{
		{Attribute: "tags"},
		{Attribute: "replica", ValueGuarded: true},
		{Changed: "policy"},
		{BestEffort: true},
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Gates, want) {
		t.Fatalf("dedupActions = %+v, want one action with gates %+v", got, want)
	}

	// A path with no gate whose failure counts makes the action required.
	got = dedupActions([]ExtractedAction{tags, {Action: "x:A"}, replica})
	if len(got) != 1 || got[0].Conditional || got[0].Gates != nil || got[0].BestEffort {
		t.Errorf("ungated path = %+v, want ungated", got)
	}

	// A path with no gate subsumes the gated paths that are as best-effort.
	got = dedupActions([]ExtractedAction{{Action: "x:A", BestEffort: true}, {Action: "x:A", BestEffort: true, Conditional: true, Condition: "policy", ConditionKind: ConditionChange}})
	if len(got) != 1 || got[0].Conditional || !got[0].BestEffort {
		t.Errorf("best-effort ungated path = %+v, want ungated and best-effort", got)
	}

	// The same gate twice is one path.
	got = dedupActions([]ExtractedAction{tags, tags})
	if len(got) != 1 || got[0].Gates != nil || got[0].Condition != "tags" {
		t.Errorf("same gate twice = %+v, want the single tags gate", got)
	}
}

// TestResolve_CallSiteGateOnEachPath covers a helper that reaches an action
// on two gated paths, called under a guard of its own. Each path that has no
// gate of its own takes the call site's gate.
func TestResolve_CallSiteGateOnEachPath(t *testing.T) {
	src := `
package svc

// @SDKResource("aws_svc_thing", name="Thing")
func resourceThingCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).SvcClient(ctx)
	if v, ok := d.GetOk("tags"); ok {
		if _, err := conn.TagResource(ctx, nil); err != nil {
			return diag.FromErr(err)
		}
	}
	if v, ok := d.GetOk("replica"); ok {
		if err := tagReplicas(ctx, conn); err != nil {
			return diag.FromErr(err)
		}
	}
	return nil
}

func tagReplicas(ctx context.Context, conn *svc.Client) error {
	_, err := conn.TagResource(ctx, nil)
	return err
}
`
	actions, err := ParseResourceFileStructured(src, "aws_svc_thing", "Thing")
	if err != nil {
		t.Fatal(err)
	}
	want := []iam.Gate{{Attribute: "tags"}, {Attribute: "replica"}}
	for _, ea := range actions["create"] {
		if ea.Action == "svc:TagResource" {
			if !reflect.DeepEqual(ea.Gates, want) {
				t.Errorf("svc:TagResource gates = %+v, want %+v", ea.Gates, want)
			}
			return
		}
	}
	t.Errorf("svc:TagResource not found in %+v", actions["create"])
}
