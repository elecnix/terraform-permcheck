package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// countFixture spans several actions, classes, conditions and an unverified
// finding, with two findings that share a group.
func countFixture() []iam.MissingAction {
	return []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "a", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "b[0]", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "a", Change: "create", Action: "s3:CreateBucket", Class: "[optional]"},
		{ResourceType: "aws_kms_key", ResourceName: "k", Change: "create", Action: "kms:CreateGrant", Class: "[required]", ConditionAttribute: "policy"},
		{ResourceType: "aws_sqs_queue", ResourceName: "q", Change: "create", Action: "sqs:CreateQueue", Class: "[required]", ResourceScopeUnverified: true},
	}
}

// TestReport_CountsMatchRenderers checks that every count a report prints
// is the number of groups it lists.
func TestReport_CountsMatchRenderers(t *testing.T) {
	r := New(check.Result{Missing: countFixture(), Checked: 4, Label: "resource changes"}, nil, false)
	if len(r.groups) != 4 || len(r.missing) != 3 || len(r.unverified) != 1 {
		t.Fatalf("groups %d, missing %d, unverified %d; want 4, 3, 1", len(r.groups), len(r.missing), len(r.unverified))
	}
	text := r.text()
	if !strings.Contains(text, "Missing IAM permissions (3):\n") || !strings.Contains(text, "Unverified IAM permissions (1),") {
		t.Errorf("text headers do not match the groups:\n%s", text)
	}
	if got := strings.Count(r.annotations(), "::warning "); got != len(r.groups) {
		t.Errorf("%d ::warning lines, want %d", got, len(r.groups))
	}
	if want := "4 resource changes checked, 3 distinct missing permissions found, 1 unverified (resource scope)."; r.summary() != want {
		t.Errorf("summary = %q, want %q", r.summary(), want)
	}
}

// TestReport_JSONStaysFlat checks that the json report lists findings, not
// groups: CI consumers count its entries.
func TestReport_JSONStaysFlat(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "a", Action: "s3:CreateBucket"},
		{ResourceType: "aws_s3_bucket", ResourceName: "b", Action: "s3:CreateBucket"},
		{ResourceType: "aws_s3_bucket", ResourceName: "c", Action: "s3:CreateBucket"},
		{ResourceType: "aws_kms_key", ResourceName: "a", Action: "kms:CreateKey"},
		{ResourceType: "aws_kms_key", ResourceName: "b", Action: "kms:CreateKey"},
	}
	r := New(check.Result{Missing: missing}, nil, false)
	var res JSONResult
	if err := json.Unmarshal([]byte(r.json()), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Missing) != 5 || len(r.groups) != 2 {
		t.Errorf("json lists %d findings and the report has %d groups; want 5 and 2", len(res.Missing), len(r.groups))
	}
}

// TestGroupBy_KeepsFirstSeenOrder guards against sorting the groups. The
// order is plan order, and annotations in a pull request follow it.
func TestGroupBy_KeepsFirstSeenOrder(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_kms_key", ResourceName: "a", Action: "kms:DescribeKey"},
		{ResourceType: "aws_s3_bucket", ResourceName: "b", Action: "s3:GetBucketAcl"},
		{ResourceType: "aws_kms_key", ResourceName: "c", Action: "kms:CreateGrant"},
		{ResourceType: "aws_kms_key", ResourceName: "d", Action: "kms:DescribeKey"},
	}
	r := New(check.Result{Missing: missing}, nil, false)
	var got []string
	for _, g := range r.groups {
		var names []string
		for _, f := range g.items {
			names = append(names, f.ResourceName)
		}
		got = append(got, g.key.action+fmt.Sprint(names))
	}
	want := []string{"kms:DescribeKey[a d]", "s3:GetBucketAcl[b]", "kms:CreateGrant[c]"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("groups = %v, want %v", got, want)
	}
}

// TestNew_ResolvesLocationsOnce checks that a finding gets its location from
// its index-free key, and a need finding gets none.
func TestNew_ResolvesLocationsOnce(t *testing.T) {
	locations := iam.Locations{
		"aws_s3_bucket.a": {Path: "a.tf", Line: 1},
		"aws_s3_bucket.b": {Path: "b.tf", Line: 2},
	}
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "a[0]", Action: "s3:CreateBucket"},
		{ResourceType: "aws_s3_bucket", ResourceName: `b["us-east-1"]`, Action: "s3:CreateBucket"},
		{ResourceType: "aws_s3_bucket", ResourceName: "c", Action: "s3:CreateBucket"},
		{Need: "aws_s3_bucket.a", Action: "s3:CreateBucket"},
	}
	r := New(check.Result{Missing: missing}, locations, false)
	want := []string{"a.tf:1", "b.tf:2", "", ""}
	for i, f := range r.findings {
		got := ""
		if f.loc != nil {
			got = fmt.Sprintf("%s:%d", f.loc.Path, f.loc.Line)
		}
		if got != want[i] {
			t.Errorf("finding %d location = %q, want %q", i, got, want[i])
		}
	}
}

func TestSource(t *testing.T) {
	tests := []struct {
		m    iam.MissingAction
		want string
	}{
		{iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a[0]", Change: "create"}, "aws_s3_bucket.a[0] (create)"},
		{iam.MissingAction{Need: "Push"}, `needs "Push"`},
		{iam.MissingAction{Need: "Push", NeedResource: repoA}, `needs "Push" on ` + repoA},
	}
	for _, tt := range tests {
		if got := source(tt.m); got != tt.want {
			t.Errorf("source(%+v) = %q, want %q", tt.m, got, tt.want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"text", "github-annotations", "json"} {
		if f, err := ParseFormat(s); err != nil || string(f) != s {
			t.Errorf("ParseFormat(%q) = %q, %v", s, f, err)
		}
	}
	if _, err := ParseFormat("sarif"); err == nil || err.Error() != `unsupported format "sarif" (supported: text, github-annotations, json)` {
		t.Errorf("ParseFormat(sarif) error = %v", err)
	}
}

// TestReport_UnresolvedNeverAllClear checks that no format prints the
// all-clear line or an ok-without-count json result when a resource type
// was not resolved, whether the run fails on it, allows it or excludes it.
func TestReport_UnresolvedNeverAllClear(t *testing.T) {
	u := iam.MissingAction{ResourceType: "aws_new_thing", ResourceName: "a", Change: "create", Unresolved: true}
	cases := []struct {
		name      string
		res       check.Result
		wantGaps  bool
		wantInSum string
	}{
		{"failing", check.Result{Unresolved: []iam.MissingAction{u}}, true, "1 resource type unresolved."},
		{"allowed", check.Result{Unresolved: []iam.MissingAction{u}, UnresolvedAllowed: true}, false, "1 resource type unresolved (allowed)."},
		{"excluded", check.Result{Excluded: []iam.ExcludedAction{{MissingAction: u}}}, false, "1 resource type unresolved (allowed)."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.res.Checked, tc.res.Label = 1, "resource changes"
			r := New(tc.res, nil, false)
			for _, f := range []Format{Text, GitHubAnnotations} {
				var out, errOut strings.Builder
				r.Write(f, &out, &errOut)
				all := out.String() + errOut.String()
				if strings.Contains(all, "All required permissions covered") {
					t.Errorf("%s: all-clear printed:\n%s", f, all)
				}
				if !strings.Contains(all, tc.wantInSum) {
					t.Errorf("%s: summary lacks %q:\n%s", f, tc.wantInSum, all)
				}
			}
			var res JSONResult
			if err := json.Unmarshal([]byte(r.json()), &res); err != nil {
				t.Fatal(err)
			}
			if got := res.Status == "gaps_found"; got != tc.wantGaps {
				t.Errorf("json status = %q, want gaps %v", res.Status, tc.wantGaps)
			}
			if !tc.wantGaps && res.UnresolvedAllowed != 1 {
				t.Errorf("json unresolved_allowed = %d, want 1", res.UnresolvedAllowed)
			}
		})
	}
}
