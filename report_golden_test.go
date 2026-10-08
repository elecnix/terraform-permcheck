package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/report"
)

// updateGolden rewrites testdata/report/*.golden from the current output.
var updateGolden = flag.Bool("update", false, "rewrite testdata/report/*.golden")

// goldenCase is one report input. Each case is rendered in every format, and
// each rendering is compared byte for byte with its golden file.
type goldenCase struct {
	name         string
	res          check.Result
	locations    report.Locations
	showExcluded bool
}

func goldenCases() []goldenCase {
	bucketA := iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a[0]", Change: "create", Action: "s3:PutBucketTagging", Class: iam.ClassManagement}
	bucketB := iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: `b["x"]`, Change: "create", Action: "s3:PutBucketTagging", Class: iam.ClassManagement}
	bucketC := iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "c", Change: "update", Action: "s3:PutBucketTagging", Class: iam.ClassManagement}
	kmsOptional := iam.MissingAction{ResourceType: "aws_kms_key", ResourceName: "main", Change: "create", Action: "kms:DescribeKey", Class: iam.ClassOptional}
	dataPlane := iam.MissingAction{ResourceType: "aws_backup_vault", ResourceName: "v", Change: "delete", Action: "backup-storage:MountCapsule", Class: iam.ClassDataPlane}
	conditional := iam.MissingAction{ResourceType: "aws_backup_vault", ResourceName: "v", Change: "delete", Action: "kms:CreateGrant", Class: iam.ClassManagement, ConditionAttribute: "kms_key_arn"}
	conditional2 := iam.MissingAction{ResourceType: "aws_sns_topic", ResourceName: "t[1]", Change: "create", Action: "kms:CreateGrant", Class: iam.ClassManagement, ConditionAttribute: "kms_key_arn"}
	unverified := iam.MissingAction{ResourceType: "aws_sqs_queue", ResourceName: "q", Change: "create", Action: "sqs:CreateQueue", Class: iam.ClassManagement, ResourceScopeUnverified: true}
	unverified2 := iam.MissingAction{ResourceType: "aws_sqs_queue", ResourceName: `r["k"]`, Change: "create", Action: "sqs:CreateQueue", Class: iam.ClassManagement, ResourceScopeUnverified: true}
	needOn := iam.MissingAction{Need: "EcrImageVerification", NeedResource: "arn:aws:ecr:us-east-1:111122223333:repository/a", Action: "ecr:DescribeImages", Class: iam.ClassManagement}
	needAny := iam.MissingAction{Need: "Logs", Action: "logs:CreateLogGroup", Class: iam.ClassManagement}
	needUnverified := iam.MissingAction{Need: "Logs", Action: "logs:PutLogEvents", Class: iam.ClassManagement, ResourceScopeUnverified: true}

	newA := iam.MissingAction{ResourceType: "aws_new_thing", ResourceName: "a", Change: "create", Unresolved: true}
	newB := iam.MissingAction{ResourceType: "aws_new_thing", ResourceName: `b["k"]`, Change: "update", Unresolved: true}
	otherNew := iam.MissingAction{ResourceType: "aws_other_new", ResourceName: "x", Change: "delete", Unresolved: true}

	locations := report.Locations{
		"aws_s3_bucket.a":    {Path: "s3.tf", Line: 3},
		"aws_s3_bucket.b":    {Path: "s3.tf", Line: 12},
		"aws_backup_vault.v": {Path: "modules/backup/main.tf", Line: 40},
		"aws_sqs_queue.r":    {Path: "sqs.tf", Line: 7},
		"aws_new_thing.b":    {Path: "new.tf", Line: 9},
	}

	excluded := []iam.ExcludedAction{
		{MissingAction: iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a[0]", Change: "delete", Action: "s3:DeleteBucket", Class: iam.ClassManagement}, Reason: "bucket is retained"},
		{MissingAction: iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: `b["x"]`, Change: "delete", Action: "s3:DeleteBucket", Class: iam.ClassManagement}, Reason: "bucket is retained"},
		{MissingAction: iam.MissingAction{ResourceType: "aws_kms_key", ResourceName: "main", Change: "create", Action: "kms:TagResource", Class: iam.ClassManagement}},
		{MissingAction: iam.MissingAction{Need: "Logs", Action: "logs:DeleteLogGroup", Class: iam.ClassManagement}, Reason: "logs are kept"},
	}

	// A replace is checked as a delete and a create, so its findings carry
	// both changes. A finding in a module names the module.
	replaceDelete := iam.MissingAction{ResourceType: "aws_sqs_queue", ResourceName: "q", Change: "delete", Action: "sqs:DeleteQueue", Class: iam.ClassManagement}
	replaceCreate := iam.MissingAction{ResourceType: "aws_sqs_queue", ResourceName: "q", Change: "create", Action: "sqs:CreateQueue", Class: iam.ClassManagement}
	moduleDelete := iam.MissingAction{ModuleAddress: "module.prod", ResourceType: "aws_sqs_queue", ResourceName: "q", Change: "delete", Action: "sqs:DeleteQueue", Class: iam.ClassManagement}
	moduleNew := iam.MissingAction{ModuleAddress: `module.app["eu"]`, ResourceType: "aws_new_thing", ResourceName: "a[0]", Change: "create", Unresolved: true}
	moduleExcluded := iam.ExcludedAction{MissingAction: iam.MissingAction{ModuleAddress: "module.legacy", ResourceType: "aws_sqs_queue", ResourceName: "q", Change: "delete", Action: "sqs:DeleteQueue", Class: iam.ClassManagement}, Reason: "deleted by hand"}

	planLabel := "resource changes"
	return []goldenCase{
		{
			name: "empty",
			res:  check.Result{Checked: 4, Label: planLabel},
		},
		{
			name: "empty_static",
			res:  check.Result{Checked: 0, Label: "resource types (static HCL)"},
		},
		{
			name: "grouped_with_locations",
			res: check.Result{
				Missing: []iam.MissingAction{bucketA, kmsOptional, bucketB, dataPlane, bucketC, conditional, conditional2},
				Checked: 6, Label: planLabel,
			},
			locations: locations,
		},
		{
			name: "grouped_without_locations",
			res: check.Result{
				Missing: []iam.MissingAction{bucketA, kmsOptional, bucketB, dataPlane, bucketC, conditional, conditional2},
				Checked: 6, Label: planLabel,
			},
		},
		{
			name: "unverified_mixed",
			res: check.Result{
				Missing: []iam.MissingAction{unverified, bucketA, unverified2, conditional},
				Checked: 3, Label: planLabel,
			},
			locations: locations,
		},
		{
			name: "unverified_only",
			res: check.Result{
				Missing: []iam.MissingAction{unverified, unverified2},
				Checked: 2, Label: planLabel,
			},
			locations: locations,
		},
		{
			name: "needs",
			res: check.Result{
				Missing: []iam.MissingAction{needOn, bucketA, needAny, needUnverified},
				Checked: 1, Label: planLabel, Needs: 2,
			},
			locations: locations,
		},
		{
			name: "needs_only_one",
			res: check.Result{
				Missing: []iam.MissingAction{needAny},
				Checked: 0, Label: planLabel, Needs: 1,
			},
		},
		{
			name: "excluded_hidden",
			res: check.Result{
				Missing:  []iam.MissingAction{bucketA},
				Excluded: excluded,
				Checked:  3, Label: planLabel,
			},
			locations: locations,
		},
		{
			name: "excluded_shown",
			res: check.Result{
				Missing:  []iam.MissingAction{bucketA},
				Excluded: excluded,
				Checked:  3, Label: planLabel, Needs: 1,
			},
			locations:    locations,
			showExcluded: true,
		},
		{
			name: "unresolved_mixed",
			res: check.Result{
				Missing:    []iam.MissingAction{bucketA, unverified2},
				Unresolved: []iam.MissingAction{newA, otherNew, newB},
				Checked:    5, Label: planLabel,
			},
			locations: locations,
		},
		{
			name: "unresolved_only",
			res: check.Result{
				Unresolved: []iam.MissingAction{newA, newB},
				Checked:    2, Label: planLabel,
			},
			locations: locations,
		},
		{
			name: "unresolved_allowed",
			res: check.Result{
				Unresolved:        []iam.MissingAction{newA, newB, otherNew},
				UnresolvedAllowed: true,
				Checked:           3, Label: planLabel,
			},
			locations: locations,
		},
		{
			name: "unresolved_excluded",
			res: check.Result{
				Excluded: []iam.ExcludedAction{
					{MissingAction: newA, Reason: "checked by hand"},
					{MissingAction: newB, Reason: "checked by hand"},
				},
				Checked: 2, Label: planLabel,
			},
			showExcluded: true,
		},
		{
			name: "unresolved_excluded_hidden",
			res: check.Result{
				Excluded: []iam.ExcludedAction{{MissingAction: newA, Reason: "checked by hand"}},
				Checked:  1, Label: planLabel,
			},
		},
		{
			name: "module_and_replace",
			res: check.Result{
				Missing:    []iam.MissingAction{replaceDelete, moduleDelete, replaceCreate},
				Unresolved: []iam.MissingAction{moduleNew},
				Excluded:   []iam.ExcludedAction{moduleExcluded},
				Checked:    4, Label: planLabel,
			},
			showExcluded: true,
		},
		{
			name: "excluded_shown_all_clear",
			res: check.Result{
				Excluded: excluded,
				Checked:  3, Label: planLabel,
			},
			showExcluded: true,
		},
	}
}

// TestReportGolden pins the report output, both streams, for every format.
// Run with -update to rewrite the golden files after an intended change.
func TestReportGolden(t *testing.T) {
	for _, c := range goldenCases() {
		for _, format := range []report.Format{report.Text, report.GitHubAnnotations, report.JSON} {
			c, format := c, format
			t.Run(c.name+"/"+string(format), func(t *testing.T) {
				stdout, stderr := renderReport(t, c, format)
				got := "--- stdout ---\n" + stdout + "--- stderr ---\n" + stderr
				path := filepath.Join("testdata", "report", c.name+"."+string(format)+".golden")
				if *updateGolden {
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
					return
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read golden (run with -update to create it): %v", err)
				}
				if got != string(want) {
					t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
				}
			})
		}
	}
}

// renderReport prints the case's report and returns what went to stdout and
// to stderr.
func renderReport(t *testing.T, c goldenCase, format report.Format) (stdout, stderr string) {
	t.Helper()
	return captureStreams(t, func() {
		printReport(c.res, format, c.locations, c.showExcluded)
	})
}

// captureStreams runs fn with os.Stdout and os.Stderr redirected to pipes.
func captureStreams(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	read := func(r *os.File, into *bytes.Buffer, done chan<- struct{}) {
		_, _ = io.Copy(into, r)
		close(done)
	}
	// The deferred closes run on every return, t.Fatal included. Closing a
	// write end twice returns an error that nothing reads.
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer errR.Close()
	defer errW.Close()
	var outBuf, errBuf bytes.Buffer
	outDone, errDone := make(chan struct{}), make(chan struct{})
	go read(outR, &outBuf, outDone)
	go read(errR, &errBuf, errDone)

	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()
	fn()
	outW.Close()
	errW.Close()
	<-outDone
	<-errDone
	return outBuf.String(), errBuf.String()
}

// captureStreams closes both ends of its pipes, so repeated calls do not hold
// file descriptors until the next garbage collection.
func TestCaptureStreams_ClosesPipes(t *testing.T) {
	openFDs := func() int {
		entries, err := os.ReadDir("/dev/fd")
		if err != nil {
			t.Skipf("cannot list open file descriptors: %v", err)
		}
		return len(entries)
	}
	// With the collector off, a pipe left open stays open for the count.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	before := openFDs()
	for i := 0; i < 20; i++ {
		captureStreams(t, func() {})
	}
	if after := openFDs(); after > before {
		t.Errorf("open file descriptors went from %d to %d after 20 calls", before, after)
	}
}
