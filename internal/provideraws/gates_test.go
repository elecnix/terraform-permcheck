package provideraws

import (
	"reflect"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// TestMergeRequirements_AnyPathGate covers an action reached on two paths
// with different gates. It is needed when either gate holds, so both gates
// stay.
func TestMergeRequirements_AnyPathGate(t *testing.T) {
	req := func(g iam.Gate) iam.Requirement { return iam.Requirement{Action: "x:A", Gate: g} }
	tags := req(iam.Gate{Attribute: "tags"})
	replica := req(iam.Gate{Attribute: "replica", ValueGuarded: true})
	changed := req(iam.Gate{Changed: "policy"})
	cleanup := req(iam.Gate{BestEffort: true})

	got := mergeRequirements([]iam.Requirement{tags, replica, changed, cleanup})
	want := []iam.Requirement{tags, replica, changed, cleanup}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeRequirements = %+v, want %+v", got, want)
	}

	// A path with no gate whose failure counts makes the action required.
	got = mergeRequirements([]iam.Requirement{tags, req(iam.Gate{}), replica})
	if want := []iam.Requirement{req(iam.Gate{})}; !reflect.DeepEqual(got, want) {
		t.Errorf("ungated path = %+v, want %+v", got, want)
	}

	// A path with no gate subsumes the gated paths that are as best-effort.
	got = mergeRequirements([]iam.Requirement{cleanup, req(iam.Gate{Changed: "policy", BestEffort: true})})
	if want := []iam.Requirement{cleanup}; !reflect.DeepEqual(got, want) {
		t.Errorf("best-effort ungated path = %+v, want %+v", got, want)
	}

	// The same gate twice is one path.
	got = mergeRequirements([]iam.Requirement{tags, tags})
	if want := []iam.Requirement{tags}; !reflect.DeepEqual(got, want) {
		t.Errorf("same gate twice = %+v, want %+v", got, want)
	}

	// Each action keeps its place: the order in which it first appears.
	other := iam.Requirement{Action: "x:B"}
	got = mergeRequirements([]iam.Requirement{tags, other, replica})
	if want := []iam.Requirement{tags, replica, other}; !reflect.DeepEqual(got, want) {
		t.Errorf("two actions = %+v, want %+v", got, want)
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
	if got := gatesOf(actions["create"], "svc:TagResource"); !reflect.DeepEqual(got, want) {
		t.Errorf("svc:TagResource gates = %+v, want %+v in %+v", got, want, actions["create"])
	}
}
