package check

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

// fakeResolver resolves terraform resource types from a fixed table of
// schemas, so the tests need no provider clone and no network.
type fakeResolver map[string]*iam.Schema

func (r fakeResolver) Resolve(tfType string) (*iam.Schema, error) {
	s, ok := r[tfType]
	if !ok {
		return nil, errors.New("unknown type " + tfType)
	}
	return s, nil
}

// failingResolver fails every lookup as a registry outage would.
type failingResolver struct{}

func (failingResolver) Resolve(tfType string) (*iam.Schema, error) {
	return nil, fmt.Errorf("fetch %s: HTTP 503: %w", tfType, iam.ErrLookupFailed)
}

// countingResolver counts the lookups of each type it passes on.
type countingResolver struct {
	iam.Resolver
	calls map[string]int
}

func (r countingResolver) Resolve(tfType string) (*iam.Schema, error) {
	r.calls[tfType]++
	return r.Resolver.Resolve(tfType)
}

// addresses collapses findings to "type.name" for assertions.
func addresses(findings []iam.MissingAction) []string {
	out := make([]string, 0, len(findings))
	for _, m := range findings {
		out = append(out, m.ResourceType+"."+m.ResourceName)
	}
	return out
}

// allowing returns a policy loader for a policy that allows exactly actions.
func allowing(actions ...string) func() ([]byte, error) {
	quoted := make([]string, len(actions))
	for i, a := range actions {
		quoted[i] = `"` + a + `"`
	}
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[` +
		strings.Join(quoted, ",") + `],"Resource":"*"}]}`
	return func() ([]byte, error) { return []byte(doc), nil }
}

// noPolicy is a policy loader that fails the test when it is called.
func noPolicy(t *testing.T) func() ([]byte, error) {
	return func() ([]byte, error) {
		t.Fatal("policy loaded for an input with nothing to check")
		return nil, nil
	}
}

// actions collapses missing actions to "type.change:action" for assertions.
func actions(missing []iam.MissingAction) []string {
	out := make([]string, 0, len(missing))
	for _, m := range missing {
		out = append(out, m.ResourceType+"."+m.Change+":"+m.Action)
	}
	return out
}

var kmsKey = &iam.Schema{
	TypeName: "aws_kms_key",
	Ops: map[string][]iam.Requirement{
		"create": {
			{Action: "kms:CreateKey"},
			{Action: "kms:TagResource", Gate: iam.Gate{Attribute: "tags"}},
			{Action: "kms:Decrypt"},
		},
		"read":   iam.Unconditional("kms:DescribeKey"),
		"update": iam.Unconditional("kms:CreateKey", "kms:EnableKeyRotation"),
		"delete": iam.Unconditional("kms:ScheduleKeyDeletion"),
	},
}

func TestRun_PlanReportsMissingActions(t *testing.T) {
	in := FromPlan([]*plan.ResourceChange{
		{Type: "aws_kms_key", Name: "a", Change: "create", Attributes: map[string]bool{"tags": true}},
		{Type: "aws_unknown_thing", Name: "b", Change: "create"},
	})

	res, err := Run(in, allowing("kms:CreateKey"), Options{Resolver: fakeResolver{"aws_kms_key": kmsKey}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// kms:Decrypt is data-plane and dropped by the default filter.
	want := []string{"aws_kms_key.create:kms:TagResource"}
	if got := actions(res.Missing); !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}
	if res.Missing[0].ConditionAttribute != "tags" {
		t.Errorf("ConditionAttribute = %q, want tags", res.Missing[0].ConditionAttribute)
	}
	if got, want := addresses(res.Unresolved), []string{"aws_unknown_thing.b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("unresolved = %v, want %v", got, want)
	}
	if !res.HasGaps() {
		t.Error("HasGaps = false with an unresolved type")
	}
	// An unresolved change is not checked, as in static mode.
	if res.Checked != 1 || res.Label != "resource changes" {
		t.Errorf("Checked, Label = %d, %q; want 1, \"resource changes\"", res.Checked, res.Label)
	}
}

func TestRun_StaticChecksEachTypeOnce(t *testing.T) {
	in := FromHCL([]hcl.ResourceBlock{
		{Type: "aws_kms_key", Name: "a"},
		{Type: "aws_kms_key", Name: "b"},
		{Type: "aws_unknown_thing", Name: "c"},
	})

	res, err := Run(in, allowing("kms:CreateKey", "kms:TagResource"), Options{Resolver: fakeResolver{"aws_kms_key": kmsKey}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Static mode checks every block of a type, for every operation that
	// adds an action create does not cover, but counts the type once.
	want := []string{
		"aws_kms_key.update:kms:EnableKeyRotation",
		"aws_kms_key.delete:kms:ScheduleKeyDeletion",
		"aws_kms_key.update:kms:EnableKeyRotation",
		"aws_kms_key.delete:kms:ScheduleKeyDeletion",
	}
	if got := actions(res.Missing); !reflect.DeepEqual(got, want) {
		t.Errorf("missing = %v, want %v", got, want)
	}
	if got, want := addresses(res.Missing), []string{"aws_kms_key.a", "aws_kms_key.a", "aws_kms_key.b", "aws_kms_key.b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("missing on %v, want %v", got, want)
	}
	if res.Checked != 1 || res.Label != "resource types (static HCL mode)" {
		t.Errorf("Checked, Label = %d, %q; want 1, static label", res.Checked, res.Label)
	}
	if got, want := addresses(res.Unresolved), []string{"aws_unknown_thing.c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("unresolved = %v, want %v", got, want)
	}
}

func TestRun_EmptyInputSkipsPolicy(t *testing.T) {
	for _, tc := range []struct {
		in    Input
		label string
	}{
		{FromPlan(nil), "resource changes"},
		{FromHCL(nil), "resource types (static HCL mode)"},
	} {
		res, err := Run(tc.in, noPolicy(t), Options{Resolver: fakeResolver{}})
		if err != nil {
			t.Fatalf("Run(%s): %v", tc.label, err)
		}
		if res.Checked != 0 || res.Label != tc.label || len(res.Missing) != 0 {
			t.Errorf("Run(%s) = %+v, want an empty result", tc.label, res)
		}
	}
}

func TestRun_PolicyErrors(t *testing.T) {
	in := FromPlan([]*plan.ResourceChange{{Type: "aws_kms_key", Name: "a", Change: "create"}})
	opts := Options{Resolver: fakeResolver{"aws_kms_key": kmsKey}}

	loadErr := errors.New("read policy: boom")
	_, err := Run(in, func() ([]byte, error) { return nil, loadErr }, opts)
	if !errors.Is(err, loadErr) || err.Error() != "read policy: boom" {
		t.Errorf("load error = %v, want it returned unchanged", err)
	}

	_, err = Run(in, func() ([]byte, error) { return []byte("{not json"), nil }, opts)
	if err == nil || !strings.HasPrefix(err.Error(), "parse policy: ") {
		t.Errorf("parse error = %v, want a \"parse policy: \" prefix", err)
	}
}

func TestFilter_Config(t *testing.T) {
	onlyRequired := iam.DefaultFilter()
	onlyRequired.ExcludeConditional = true
	strict := iam.DefaultFilter()
	strict.StrictResources = true

	for _, tc := range []struct {
		name   string
		filter Filter
		want   iam.FilterConfig
	}{
		{"default", Filter{}, iam.DefaultFilter()},
		{"no-filter", Filter{NoFilter: true}, iam.FilterConfig{}},
		{"only-required", Filter{OnlyRequired: true}, onlyRequired},
		// --no-filter --only-required still drops conditional actions.
		{"both", Filter{NoFilter: true, OnlyRequired: true}, iam.FilterConfig{ExcludeConditional: true}},
		{"strict-resources", Filter{StrictResources: true}, strict},
		{"no-filter strict-resources", Filter{NoFilter: true, StrictResources: true}, iam.FilterConfig{StrictResources: true}},
	} {
		if got := tc.filter.config(); got != tc.want {
			t.Errorf("%s: config() = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestRun_FilterFlags(t *testing.T) {
	in := FromPlan([]*plan.ResourceChange{{Type: "aws_kms_key", Name: "a", Change: "create"}})
	resolver := fakeResolver{"aws_kms_key": kmsKey}

	for _, tc := range []struct {
		name   string
		filter Filter
		want   []string
	}{
		{"default", Filter{}, []string{"aws_kms_key.create:kms:TagResource"}},
		{"no-filter", Filter{NoFilter: true}, []string{"aws_kms_key.create:kms:TagResource", "aws_kms_key.create:kms:Decrypt"}},
		{"only-required", Filter{OnlyRequired: true}, []string{}},
		{"both", Filter{NoFilter: true, OnlyRequired: true}, []string{"aws_kms_key.create:kms:Decrypt"}},
	} {
		res, err := Run(in, allowing("kms:CreateKey"), Options{Filter: tc.filter, Resolver: resolver})
		if err != nil {
			t.Fatalf("%s: Run: %v", tc.name, err)
		}
		if got := actions(res.Missing); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: missing = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRun_Exclusions(t *testing.T) {
	in := FromPlan([]*plan.ResourceChange{{Type: "aws_kms_key", Name: "a", Change: "create"}})
	opts := Options{
		Filter:     Filter{NoFilter: true},
		Exclusions: []iam.Exclusion{{Permission: "kms:Decrypt", Reason: "granted by key policy"}},
		Resolver:   fakeResolver{"aws_kms_key": kmsKey},
	}

	res, err := Run(in, allowing("kms:CreateKey"), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got, want := actions(res.Missing), []string{"aws_kms_key.create:kms:TagResource"}; !reflect.DeepEqual(got, want) {
		t.Errorf("missing = %v, want %v", got, want)
	}
	if len(res.Excluded) != 1 || res.Excluded[0].Action != "kms:Decrypt" || res.Excluded[0].Reason != "granted by key policy" {
		t.Errorf("excluded = %+v, want kms:Decrypt with its reason", res.Excluded)
	}
}

// TestRun_ProviderSourceOutput feeds the real producer, the provider-source
// parser, into iam.Validate. The fixture is a trimmed provider resource file,
// so the test exercises the producer's real output shape (permissions,
// presence gates, transparent tagging) without the provider clone.
func TestRun_ProviderSourceOutput(t *testing.T) {
	resolver := cloud.NewChainProvider(provideraws.NewSourceProviderWithPath("testdata/provider"))
	allowed := allowing("backup:CreateBackupVault", "backup:DescribeBackupVault", "backup:DeleteBackupVault")

	for _, tc := range []struct {
		name  string
		attrs map[string]bool
		want  []string
	}{
		{
			name:  "no gating attributes set",
			attrs: map[string]bool{"name": true},
			want:  []string{"aws_backup_vault.create:backup:ListTags"},
		},
		{
			name:  "kms_key_arn and tags set",
			attrs: map[string]bool{"name": true, "kms_key_arn": true, "tags": true},
			want: []string{
				"aws_backup_vault.create:kms:CreateGrant",
				"aws_backup_vault.create:backup:ListTags",
				"aws_backup_vault.create:backup:TagResource",
			},
		},
	} {
		in := FromPlan([]*plan.ResourceChange{
			{Type: "aws_backup_vault", Name: "this", Change: "create", Attributes: tc.attrs},
		})
		res, err := Run(in, allowed, Options{Resolver: resolver})
		if err != nil {
			t.Fatalf("%s: Run: %v", tc.name, err)
		}
		if got := actions(res.Missing); !sameSet(got, tc.want) {
			t.Errorf("%s: missing = %v, want %v", tc.name, got, tc.want)
		}
		for _, m := range res.Missing {
			if m.Class != iam.ClassManagement {
				t.Errorf("%s: %s class = %q, want [required]", tc.name, m.Action, m.Class)
			}
		}
	}
}

// sameSet reports whether a and b hold the same strings, in any order.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// TestResolverFor_SharedPerProcess verifies that every caller gets the
// same embedded resolver, so the table is decoded once per process rather
// than once per check.
func TestResolverFor_SharedPerProcess(t *testing.T) {
	if ResolverFor(SourceEmbedded) != ResolverFor(SourceEmbedded) {
		t.Error("ResolverFor(SourceEmbedded) built a new resolver on the second call")
	}
}

func TestRun_UnresolvedTypes(t *testing.T) {
	changes := []*plan.ResourceChange{
		{Type: "aws_kms_key", Name: "a", Change: "create"},
		{Type: "aws_new_thing", Name: "x", Change: "create"},
		{Type: "aws_new_thing", Name: "y", Change: "update"},
	}
	resolver := fakeResolver{"aws_kms_key": kmsKey}
	all := allowing("kms:*")

	t.Run("fail by default", func(t *testing.T) {
		res, err := Run(FromPlan(changes), all, Options{Resolver: resolver})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Missing) != 0 {
			t.Errorf("missing = %v, want none", actions(res.Missing))
		}
		if got, want := addresses(res.Unresolved), []string{"aws_new_thing.x", "aws_new_thing.y"}; !reflect.DeepEqual(got, want) {
			t.Errorf("unresolved = %v, want %v", got, want)
		}
		if res.UnresolvedAllowed || !res.HasGaps() {
			t.Errorf("UnresolvedAllowed, HasGaps = %v, %v; want false, true", res.UnresolvedAllowed, res.HasGaps())
		}
	})

	t.Run("allowed", func(t *testing.T) {
		res, err := Run(FromPlan(changes), all, Options{Resolver: resolver, AllowUnresolvedTypes: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Unresolved) != 2 || !res.UnresolvedAllowed || res.HasGaps() {
			t.Errorf("unresolved = %v, allowed = %v, HasGaps = %v; want 2, true, false", addresses(res.Unresolved), res.UnresolvedAllowed, res.HasGaps())
		}
	})

	t.Run("excluded by type", func(t *testing.T) {
		ex := []iam.Exclusion{{Permission: "*", Resource: "aws_new_thing", Reason: "checked by hand"}}
		res, err := Run(FromPlan(changes), all, Options{Resolver: resolver, Exclusions: ex})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Unresolved) != 0 || res.HasGaps() {
			t.Errorf("unresolved = %v, HasGaps = %v; want none, false", addresses(res.Unresolved), res.HasGaps())
		}
		if len(res.Excluded) != 2 || !res.Excluded[0].Unresolved || res.Excluded[0].Reason != "checked by hand" {
			t.Errorf("excluded = %+v, want both unresolved changes with the reason", res.Excluded)
		}
	})

	t.Run("resolved once per type", func(t *testing.T) {
		counting := countingResolver{Resolver: resolver, calls: map[string]int{}}
		if _, err := Run(FromPlan(changes), all, Options{Resolver: counting}); err != nil {
			t.Fatal(err)
		}
		if counting.calls["aws_new_thing"] != 1 {
			t.Errorf("aws_new_thing resolved %d times, want 1", counting.calls["aws_new_thing"])
		}
	})
}

func TestRun_LookupFailure(t *testing.T) {
	for _, in := range []Input{
		FromPlan([]*plan.ResourceChange{{Type: "aws_kms_key", Name: "a", Change: "create"}}),
		FromHCL([]hcl.ResourceBlock{{Type: "aws_kms_key", Name: "a"}}),
	} {
		_, err := Run(in, allowing("kms:*"), Options{Resolver: failingResolver{}})
		if !errors.Is(err, iam.ErrLookupFailed) {
			t.Errorf("Run(%s) err = %v, want ErrLookupFailed", in.label(), err)
		}
	}
}

// TestRun_PlanCountsResources verifies that the checked count counts
// resources: a replace, checked as a delete and a create, counts once, and a
// no-op kept for reference resolution does not count. A resource of an
// unresolved type is not checked and does not count either.
func TestRun_PlanCountsResources(t *testing.T) {
	in := FromPlan([]*plan.ResourceChange{
		{Address: "aws_kms_key.a", Type: "aws_kms_key", Name: "a", Change: "delete"},
		{Address: "aws_kms_key.a", Type: "aws_kms_key", Name: "a", Change: "create"},
		{Address: "aws_unknown_thing.u", Type: "aws_unknown_thing", Name: "u", Change: "delete"},
		{Address: "aws_unknown_thing.u", Type: "aws_unknown_thing", Name: "u", Change: "create"},
		{Address: "aws_kms_key.b", Type: "aws_kms_key", Name: "b", Change: plan.NoOp},
		{Address: "module.m.aws_kms_key.a", ModuleAddress: "module.m", Type: "aws_kms_key", Name: "a", Change: "create"},
	})
	res, err := Run(in, allowing("kms:*"), Options{Resolver: fakeResolver{"aws_kms_key": kmsKey}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Checked != 2 {
		t.Errorf("Checked = %d, want 2 (aws_kms_key.a and module.m.aws_kms_key.a)", res.Checked)
	}
}

// TestRun_PlanOnlyNoOpSkipsPolicy verifies that a plan whose every change
// is a no-op has nothing to check.
func TestRun_PlanOnlyNoOpSkipsPolicy(t *testing.T) {
	in := FromPlan([]*plan.ResourceChange{{Type: "aws_kms_key", Name: "b", Change: plan.NoOp}})
	res, err := Run(in, noPolicy(t), Options{Resolver: fakeResolver{"aws_kms_key": kmsKey}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Checked != 0 {
		t.Errorf("Checked = %d, want 0", res.Checked)
	}
}
