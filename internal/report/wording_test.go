package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/iam"
)

func TestAllClear_NothingChecked(t *testing.T) {
	for _, label := range []string{"resource changes", "resource types (static HCL mode)"} {
		r := New(check.Result{Label: label}, nil, false)
		if got, want := r.allClear(), "No resources to check."; got != want {
			t.Errorf("%s: allClear = %q, want %q", label, got, want)
		}
	}
	r := New(check.Result{Label: "resource changes", Needs: 1}, nil, false)
	if got, want := r.allClear(), "All required permissions covered (0 resource changes, 1 declared need checked)."; got != want {
		t.Errorf("needs only: allClear = %q, want %q", got, want)
	}
}

func TestSummary_Singular(t *testing.T) {
	one := []iam.MissingAction{{ResourceType: "aws_s3_bucket", ResourceName: "a", Change: "create", Action: "s3:CreateBucket", Class: iam.ClassManagement}}
	cases := []struct {
		res  check.Result
		want string
	}{
		{check.Result{Missing: one, Checked: 1, Label: "resource changes"}, "1 resource change checked, 1 distinct missing permission found."},
		{check.Result{Missing: one, Checked: 1, Label: "resource types (static HCL mode)"}, "1 resource type (static HCL mode) checked, 1 distinct missing permission found."},
		{check.Result{Missing: one, Checked: 1, Label: "resource changes", Needs: 2}, "1 resource change, 2 declared needs checked, 1 distinct missing permission found."},
		{check.Result{Missing: one, Checked: 2, Label: "resource changes"}, "2 resource changes checked, 1 distinct missing permission found."},
	}
	for _, c := range cases {
		if got := New(c.res, nil, false).summary(); got != c.want {
			t.Errorf("summary = %q, want %q", got, c.want)
		}
	}
	if got, want := New(check.Result{Checked: 1, Label: "resource changes"}, nil, false).allClear(), "All required permissions covered (1 resource change checked)."; got != want {
		t.Errorf("allClear = %q, want %q", got, want)
	}
}

// An unresolved type a config exclusion covers is excluded, not allowed.
func TestSummary_ExcludedUnresolved(t *testing.T) {
	u := iam.MissingAction{ResourceType: "aws_new_thing", ResourceName: "a", Change: "create", Unresolved: true}
	res := check.Result{Checked: 2, Label: "resource changes", Excluded: []iam.ExcludedAction{{MissingAction: u, Reason: "by hand"}}}
	if got, want := New(res, nil, false).summary(), "2 resource changes checked, 0 distinct missing permissions found, 1 resource type unresolved (excluded)."; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
	res.UnresolvedAllowed = true
	res.Unresolved = []iam.MissingAction{{ResourceType: "aws_other", ResourceName: "b", Change: "create", Unresolved: true}}
	if got, want := New(res, nil, false).summary(), "2 resource changes checked, 0 distinct missing permissions found, 1 resource type unresolved (allowed), 1 resource type unresolved (excluded)."; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
	if j := New(res, nil, true).json(); strings.Contains(j, `"excluded_action"`) {
		t.Errorf("an excluded unresolved type has no action, so the json must omit excluded_action:\n%s", j)
	}
}

// The text report puts one blank line between the findings and the summary.
func TestWrite_TextSpacing(t *testing.T) {
	one := []iam.MissingAction{{ResourceType: "aws_s3_bucket", ResourceName: "a", Change: "create", Action: "s3:CreateBucket", Class: iam.ClassManagement}}
	var stdout, stderr bytes.Buffer
	New(check.Result{Missing: one, Checked: 1, Label: "resource changes"}, nil, false).Write(Text, &stdout, &stderr)
	if strings.Contains(stderr.String(), "\n\n\n") {
		t.Errorf("two blank lines before the summary:\n%q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "(create)\n\n1 resource change") {
		t.Errorf("want one blank line before the summary:\n%q", stderr.String())
	}
}
