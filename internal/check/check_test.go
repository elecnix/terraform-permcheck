package check

import (
	"errors"
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
type fakeResolver map[string]*cloud.Schema

func (r fakeResolver) Resolve(tfType string) (iam.SchemaLike, error) {
	s, ok := r[tfType]
	if !ok {
		return nil, errors.New("unknown type " + tfType)
	}
	return s, nil
}

// policy returns a policy loader for a policy that allows exactly actions.
func policy(actions ...string) func() ([]byte, error) {
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

var kmsKey = &cloud.Schema{
	TypeName: "aws_kms_key",
	Permissions: map[string][]string{
		"create": {"kms:CreateKey", "kms:TagResource", "kms:Decrypt"},
		"read":   {"kms:DescribeKey"},
		"update": {"kms:CreateKey", "kms:EnableKeyRotation"},
		"delete": {"kms:ScheduleKeyDeletion"},
	},
	Conditional: map[string]map[string]string{
		"create": {"kms:TagResource": "tags"},
	},
}

func TestRun_PlanReportsMissingActions(t *testing.T) {
	in := FromPlan([]*plan.ResourceChange{
		{Type: "aws_kms_key", Name: "a", Change: "create", Attributes: map[string]bool{"tags": true}},
		{Type: "aws_unknown_thing", Name: "b", Change: "create"},
	})

	res, err := Run(in, policy("kms:CreateKey"), Options{Resolver: fakeResolver{"aws_kms_key": kmsKey}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// kms:Decrypt is data-plane and dropped by the default filter.
	want := []string{"aws_kms_key.create:kms:TagResource"}
	if got := actions(res.Missing); !reflect.DeepEqual(got, want) {
		t.Errorf("missing = %v, want %v", got, want)
	}
	if res.Missing[0].ConditionAttribute != "tags" {
		t.Errorf("ConditionAttribute = %q, want tags", res.Missing[0].ConditionAttribute)
	}
	// Plan mode counts every resource change, resolvable or not.
	if res.Checked != 2 || res.Label != "resource changes" {
		t.Errorf("Checked, Label = %d, %q; want 2, \"resource changes\"", res.Checked, res.Label)
	}
}

func TestRun_StaticChecksEachTypeOnce(t *testing.T) {
	in := FromHCL([]hcl.ResourceBlock{
		{Type: "aws_kms_key", Name: "a"},
		{Type: "aws_kms_key", Name: "b"},
		{Type: "aws_unknown_thing", Name: "c"},
	})

	res, err := Run(in, policy("kms:CreateKey", "kms:TagResource"), Options{Resolver: fakeResolver{"aws_kms_key": kmsKey}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Static mode checks the first block of each type, for every operation
	// that adds an action create does not cover.
	want := []string{
		"aws_kms_key.update:kms:EnableKeyRotation",
		"aws_kms_key.delete:kms:ScheduleKeyDeletion",
	}
	if got := actions(res.Missing); !reflect.DeepEqual(got, want) {
		t.Errorf("missing = %v, want %v", got, want)
	}
	if res.Checked != 1 || res.Label != "resource types (static HCL mode)" {
		t.Errorf("Checked, Label = %d, %q; want 1, static label", res.Checked, res.Label)
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
		if got := tc.filter.Config(); got != tc.want {
			t.Errorf("%s: Config() = %+v, want %+v", tc.name, got, tc.want)
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
		res, err := Run(in, policy("kms:CreateKey"), Options{Filter: tc.filter, Resolver: resolver})
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

	res, err := Run(in, policy("kms:CreateKey"), opts)
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
	resolver := FromProvider(provideraws.NewSourceProviderWithPath("testdata/provider"))
	allowed := policy("backup:CreateBackupVault", "backup:DescribeBackupVault", "backup:DeleteBackupVault")

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
			if m.Class != "[required]" {
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
