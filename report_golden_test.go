package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// updateGolden rewrites testdata/report/*.golden from the current output.
var updateGolden = flag.Bool("update", false, "rewrite testdata/report/*.golden")

// goldenCase is one report input. Each case is rendered in every format, and
// each rendering is compared byte for byte with its golden file.
type goldenCase struct {
	name         string
	res          check.Result
	locations    map[string]iam.FileLocation
	showExcluded bool
}

func goldenCases() []goldenCase {
	bucketA := iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a[0]", Change: "create", Action: "s3:PutBucketTagging", Class: "[required]"}
	bucketB := iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: `b["x"]`, Change: "create", Action: "s3:PutBucketTagging", Class: "[required]"}
	bucketC := iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "c", Change: "update", Action: "s3:PutBucketTagging", Class: "[required]"}
	kmsOptional := iam.MissingAction{ResourceType: "aws_kms_key", ResourceName: "main", Change: "create", Action: "kms:DescribeKey", Class: "[optional]"}
	dataPlane := iam.MissingAction{ResourceType: "aws_backup_vault", ResourceName: "v", Change: "delete", Action: "backup-storage:MountCapsule", Class: "[data-plane]"}
	conditional := iam.MissingAction{ResourceType: "aws_backup_vault", ResourceName: "v", Change: "delete", Action: "kms:CreateGrant", Class: "[required]", ConditionAttribute: "kms_key_arn"}
	conditional2 := iam.MissingAction{ResourceType: "aws_sns_topic", ResourceName: "t[1]", Change: "create", Action: "kms:CreateGrant", Class: "[required]", ConditionAttribute: "kms_key_arn"}
	unverified := iam.MissingAction{ResourceType: "aws_sqs_queue", ResourceName: "q", Change: "create", Action: "sqs:CreateQueue", Class: "[required]", ResourceScopeUnverified: true}
	unverified2 := iam.MissingAction{ResourceType: "aws_sqs_queue", ResourceName: `r["k"]`, Change: "create", Action: "sqs:CreateQueue", Class: "[required]", ResourceScopeUnverified: true}
	needOn := iam.MissingAction{Need: "EcrImageVerification", NeedResource: "arn:aws:ecr:us-east-1:111122223333:repository/a", Action: "ecr:DescribeImages", Class: "[required]"}
	needAny := iam.MissingAction{Need: "Logs", Action: "logs:CreateLogGroup", Class: "[required]"}
	needUnverified := iam.MissingAction{Need: "Logs", Action: "logs:PutLogEvents", Class: "[required]", ResourceScopeUnverified: true}

	locations := map[string]iam.FileLocation{
		"aws_s3_bucket.a":    {Path: "s3.tf", Line: 3},
		"aws_s3_bucket.b":    {Path: "s3.tf", Line: 12},
		"aws_backup_vault.v": {Path: "modules/backup/main.tf", Line: 40},
		"aws_sqs_queue.r":    {Path: "sqs.tf", Line: 7},
	}

	excluded := []iam.ExcludedAction{
		{MissingAction: iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a[0]", Change: "delete", Action: "s3:DeleteBucket", Class: "[required]"}, Reason: "bucket is retained"},
		{MissingAction: iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: `b["x"]`, Change: "delete", Action: "s3:DeleteBucket", Class: "[required]"}, Reason: "bucket is retained"},
		{MissingAction: iam.MissingAction{ResourceType: "aws_kms_key", ResourceName: "main", Change: "create", Action: "kms:TagResource", Class: "[required]"}},
		{MissingAction: iam.MissingAction{Need: "Logs", Action: "logs:DeleteLogGroup", Class: "[required]"}, Reason: "logs are kept"},
	}

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
		for _, format := range []string{"text", "github-annotations", "json"} {
			c, format := c, format
			t.Run(c.name+"/"+format, func(t *testing.T) {
				stdout, stderr := renderReport(t, c, format)
				got := "--- stdout ---\n" + stdout + "--- stderr ---\n" + stderr
				path := filepath.Join("testdata", "report", c.name+"."+format+".golden")
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
func renderReport(t *testing.T, c goldenCase, format string) (stdout, stderr string) {
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
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
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
