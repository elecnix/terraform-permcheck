package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// The helpers below render one part of a report, so each test can look at
// the part it is about.

func formatMissing(missing []iam.MissingAction, locations iam.Locations) string {
	return New(check.Result{Missing: missing}, locations, false).text()
}

func formatGitHubAnnotations(missing []iam.MissingAction, locations iam.Locations) string {
	return New(check.Result{Missing: missing}, locations, false).annotations()
}

func formatJSON(missing []iam.MissingAction, excluded []iam.ExcludedAction, checked int, label string, locations iam.Locations) string {
	res := check.Result{Missing: missing, Excluded: excluded, Checked: checked, Label: label}
	return New(res, locations, excluded != nil).json()
}

func formatExcluded(excluded []iam.ExcludedAction) string {
	return New(check.Result{Excluded: excluded}, nil, true).excludedText()
}

func formatExcludedAnnotations(excluded []iam.ExcludedAction) string {
	return New(check.Result{Excluded: excluded}, nil, true).excludedAnnotations()
}

func distinctCount(missing []iam.MissingAction) int {
	return len(New(check.Result{Missing: missing}, nil, false).groups)
}

func unverifiedCount(missing []iam.MissingAction) int {
	return len(New(check.Result{Missing: missing}, nil, false).unverified)
}

const repoA = "arn:aws:ecr:us-east-1:111111111111:repository/app-a"

func TestFormatMissing_Grouped(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "data", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "logs_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "data_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_cloudwatch_log_group", ResourceName: "api", Change: "delete", Action: "cloudwatchlogs:TagResource", Class: "[required]"},
	}

	got := formatMissing(missing, nil)

	// Header: count should be distinct actions (3), not total items (5)
	if !strings.Contains(got, "Missing IAM permissions (3):") {
		t.Errorf("header should show distinct count 3, got:\n%s", got)
	}

	// Each distinct action should appear exactly once as a group header
	if !strings.Contains(got, "s3:HeadBucket [required]\n") {
		t.Error("expected s3:HeadBucket [required] group header")
	}
	if !strings.Contains(got, "s3:DeletePublicAccessBlock [required]\n") {
		t.Error("expected s3:DeletePublicAccessBlock [required] group header")
	}
	if !strings.Contains(got, "cloudwatchlogs:TagResource [required]\n") {
		t.Error("expected cloudwatchlogs:TagResource [required] group header")
	}

	// Each resource should appear under its action group
	if !strings.Contains(got, "  → aws_s3_bucket.logs (delete)\n") {
		t.Error("expected → aws_s3_bucket.logs (delete)")
	}
	if !strings.Contains(got, "  → aws_s3_bucket.data (delete)\n") {
		t.Error("expected → aws_s3_bucket.data (delete)")
	}
	if !strings.Contains(got, "  → aws_s3_bucket_public_access_block.logs_block (delete)\n") {
		t.Error("expected → aws_s3_bucket_public_access_block.logs_block (delete)")
	}
	if !strings.Contains(got, "  → aws_s3_bucket_public_access_block.data_block (delete)\n") {
		t.Error("expected → aws_s3_bucket_public_access_block.data_block (delete)")
	}
	if !strings.Contains(got, "  → aws_cloudwatch_log_group.api (delete)\n") {
		t.Error("expected → aws_cloudwatch_log_group.api (delete)")
	}

	// Should not contain old format
	if strings.Contains(got, " needs ") {
		t.Error("output should not use old 'needs' format")
	}
}

func TestFormatMissing_SingleResource(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_iam_role", ResourceName: "deploy", Change: "delete", Action: "iam:RemoveRoleFromInstanceProfile", Class: "[required]"},
	}

	got := formatMissing(missing, nil)

	if !strings.Contains(got, "Missing IAM permissions (1):") {
		t.Errorf("header should show count 1, got:\n%s", got)
	}
	if !strings.Contains(got, "iam:RemoveRoleFromInstanceProfile [required]\n") {
		t.Error("expected iam:RemoveRoleFromInstanceProfile group header")
	}
	if !strings.Contains(got, "  → aws_iam_role.deploy (delete)\n") {
		t.Error("expected → aws_iam_role.deploy (delete)")
	}
}

func TestFormatMissing_Empty(t *testing.T) {
	got := formatMissing(nil, nil)
	if got != "" {
		t.Errorf("expected empty string for nil, got %q", got)
	}

	got = formatMissing([]iam.MissingAction{}, nil)
	if got != "" {
		t.Errorf("expected empty string for empty slice, got %q", got)
	}
}

func TestDistinctCount(t *testing.T) {
	missing := []iam.MissingAction{
		{Action: "s3:HeadBucket", Class: "[required]"},
		{Action: "s3:HeadBucket", Class: "[required]"},
		{Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{Action: "cloudwatchlogs:TagResource", Class: "[required]"},
		{Action: "backup:CreateBackupVault", Class: "[optional]"},
	}

	got := distinctCount(missing)
	if got != 4 {
		t.Errorf("DistinctCount = %d, want 4", got)
	}

	// Different class = different group
	missing2 := []iam.MissingAction{
		{Action: "s3:HeadBucket", Class: "[required]"},
		{Action: "s3:HeadBucket", Class: "[optional]"},
	}
	if distinctCount(missing2) != 2 {
		t.Error("same action with different classes should be distinct")
	}

	// Empty
	if distinctCount(nil) != 0 {
		t.Error("empty should return 0")
	}
}

func TestFormatGitHubAnnotations_Grouped(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "data", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "logs_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "data_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_cloudwatch_log_group", ResourceName: "api", Change: "delete", Action: "cloudwatchlogs:TagResource", Class: "[required]"},
	}

	got := formatGitHubAnnotations(missing, nil)

	// Each distinct action should emit a single ::warning:: line
	s3HeadCount := strings.Count(got, "::warning ")
	if s3HeadCount != 3 {
		t.Errorf("expected 3 ::warning lines (one per distinct action), got %d:\n%s", s3HeadCount, got)
	}

	// Verify the ::warning format: ::warning title=...::message
	if !strings.Contains(got, "::warning title=Missing IAM permission::") {
		t.Error("expected ::warning title=Missing IAM permission:: prefix")
	}

	// Should list affected resource types
	if !strings.Contains(got, "aws_s3_bucket") {
		t.Error("expected aws_s3_bucket in annotations")
	}
	if !strings.Contains(got, "aws_cloudwatch_log_group") {
		t.Error("expected aws_cloudwatch_log_group in annotations")
	}

	// Each warning should include the action name
	if !strings.Contains(got, "cloudwatchlogs:TagResource") {
		t.Error("expected cloudwatchlogs:TagResource in annotations")
	}
}

func TestFormatGitHubAnnotations_Empty(t *testing.T) {
	got := formatGitHubAnnotations(nil, nil)
	if got != "" {
		t.Errorf("expected empty string for nil, got %q", got)
	}

	got = formatGitHubAnnotations([]iam.MissingAction{}, nil)
	if got != "" {
		t.Errorf("expected empty string for empty slice, got %q", got)
	}
}

func TestFormatGitHubAnnotations_Conditional(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_backup_vault", ResourceName: "main", Change: "create", Action: "kms:CreateGrant", Class: "[required]", ConditionAttribute: "kms_key_arn"},
	}

	got := formatGitHubAnnotations(missing, nil)

	if !strings.Contains(got, "::warning title=Missing IAM permission::") {
		t.Error("expected ::warning prefix")
	}
	// Should mention both the action and the attribute
	if !strings.Contains(got, "kms:CreateGrant") {
		t.Error("expected kms:CreateGrant in annotation")
	}
	if !strings.Contains(got, "kms_key_arn") {
		t.Error("expected conditional attribute kms_key_arn in annotation")
	}
}

func TestFormatMissing_ConditionalAttribute(t *testing.T) {
	// Conditional permissions should show [conditional: <attr>]
	missing := []iam.MissingAction{
		{ResourceType: "aws_backup_vault", ResourceName: "main", Change: "create", Action: "kms:CreateGrant", Class: "[required]", ConditionAttribute: "kms_key_arn"},
		{ResourceType: "aws_backup_vault", ResourceName: "main", Change: "create", Action: "kms:CreateKey", Class: "[required]", ConditionAttribute: ""},
	}
	got := formatMissing(missing, nil)
	if !strings.Contains(got, "kms:CreateGrant [conditional: kms_key_arn]") {
		t.Errorf("expected conditional tag, got:\n%s", got)
	}
	if !strings.Contains(got, "kms:CreateKey [required]") {
		t.Errorf("expected [required] tag for unconditional action, got:\n%s", got)
	}
}

func TestFormatGitHubAnnotations_WithFileLocation(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "cloudtrail", Change: "create", Action: "s3:PutPublicAccessBlock", Class: "[required]"},
	}

	locations := iam.Locations{
		"aws_s3_bucket.cloudtrail":                     {Path: "modules/datadog-cloudtrail/main.tf", Line: 10},
		"aws_s3_bucket_public_access_block.cloudtrail": {Path: "modules/datadog-cloudtrail/main.tf", Line: 82},
	}

	got := formatGitHubAnnotations(missing, locations)

	// First action (s3:CreateBucket) should have file=...line=10
	if !strings.Contains(got, "::warning file=modules/datadog-cloudtrail/main.tf,line=10,title=Missing IAM permission::") {
		t.Errorf("expected file= and line=10 in output, got:\n%s", got)
	}

	// Second action (s3:PutPublicAccessBlock) should have file=...line=82
	if !strings.Contains(got, "::warning file=modules/datadog-cloudtrail/main.tf,line=82,title=Missing IAM permission::") {
		t.Errorf("expected file= and line=82 in output, got:\n%s", got)
	}
}

func TestFormatGitHubAnnotations_PartialFileLocation(t *testing.T) {
	// Some resources have locations, some don't.
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "unknown_bucket", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
	}

	locations := iam.Locations{
		"aws_s3_bucket.cloudtrail": {Path: "main.tf", Line: 5},
	}

	got := formatGitHubAnnotations(missing, locations)

	// The group contains cloudtrail (has location) and unknown_bucket (no location).
	// First resource with a location wins → should have file=...
	if !strings.Contains(got, "::warning file=main.tf,line=5,title=Missing IAM permission::") {
		t.Errorf("expected file= for group with partial locations, got:\n%s", got)
	}
}

func TestFormatGitHubAnnotations_NoLocations(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
	}

	// nil map → behavior unchanged
	got := formatGitHubAnnotations(missing, nil)

	if !strings.Contains(got, "::warning title=Missing IAM permission::") {
		t.Error("expected ::warning without file= when locations is nil")
	}
	if strings.Contains(got, "file=") {
		t.Error("should not include file= when locations is nil")
	}

	// Empty map → same behavior
	got = formatGitHubAnnotations(missing, iam.Locations{})

	if !strings.Contains(got, "::warning title=Missing IAM permission::") {
		t.Error("expected ::warning without file= when locations is empty")
	}
	if strings.Contains(got, "file=") {
		t.Error("should not include file= when locations is empty")
	}
}

func TestFormatGitHubAnnotations_StripIndexForLookup(t *testing.T) {
	// Resource names with count/for_each indices should be stripped before lookup.
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail[0]", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: `config["us-east-1"]`, Change: "create", Action: "s3:PutBucketPolicy", Class: "[required]"},
	}

	locations := iam.Locations{
		"aws_s3_bucket.cloudtrail": {Path: "main.tf", Line: 10},
		"aws_s3_bucket.config":     {Path: "config.tf", Line: 42},
	}

	got := formatGitHubAnnotations(missing, locations)

	if !strings.Contains(got, "::warning file=main.tf,line=10,title=Missing IAM permission::") {
		t.Errorf("expected file=main.tf,line=10 for cloudtrail[0], got:\n%s", got)
	}
	if !strings.Contains(got, "::warning file=config.tf,line=42,title=Missing IAM permission::") {
		t.Errorf("expected file=config.tf,line=42 for config[\"us-east-1\"], got:\n%s", got)
	}
}

func TestFormatMissing_WithFileLocation(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
	}

	locations := iam.Locations{
		"aws_s3_bucket.cloudtrail": {Path: "main.tf", Line: 10},
		// logs has NO location
	}

	got := formatMissing(missing, locations)

	// cloudtrail should have the file location appended
	if !strings.Contains(got, "    → aws_s3_bucket.cloudtrail (create) [main.tf:10]\n") {
		t.Errorf("expected file location for cloudtrail, got:\n%s", got)
	}

	// logs should NOT have a file location
	if !strings.Contains(got, "    → aws_s3_bucket.logs (delete)\n") {
		t.Errorf("expected no file location for logs, got:\n%s", got)
	}
	if strings.Contains(got, "aws_s3_bucket.logs (delete) [") {
		t.Error("logs should not have file location")
	}
}

func TestFormatMissing_StripIndexForLookup(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail[0]", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
	}

	locations := iam.Locations{
		"aws_s3_bucket.cloudtrail": {Path: "main.tf", Line: 10},
	}

	got := formatMissing(missing, locations)

	if !strings.Contains(got, "    → aws_s3_bucket.cloudtrail[0] (create) [main.tf:10]\n") {
		t.Errorf("expected stripped index lookup with file location, got:\n%s", got)
	}
}

func TestFormatMissing_WithClassification(t *testing.T) {
	missing := []iam.MissingAction{
		{
			ResourceType: "aws_backup_vault",
			ResourceName: "this",
			Change:       "create",
			Action:       "backup:CreateBackupVault",
			Service:      "backup",
			Class:        "[required]",
		},
		{
			ResourceType: "aws_backup_vault",
			ResourceName: "this",
			Change:       "create",
			Action:       "backup:PutBackupVaultAccessPolicy",
			Service:      "backup",
			Class:        "[optional]",
		},
		{
			ResourceType: "aws_backup_vault",
			ResourceName: "this",
			Change:       "create",
			Action:       "kms:CreateGrant",
			Service:      "kms",
			Class:        "[required]",
		},
	}

	output := formatMissing(missing, nil)

	// Check header — shows distinct action count
	if !strings.Contains(output, "Missing IAM permissions (3)") {
		t.Errorf("expected header with count, got: %s", output)
	}

	// Check grouped action lines with tags
	checks := []string{
		"backup:CreateBackupVault [required]\n",
		"backup:PutBackupVaultAccessPolicy [optional]\n",
		"kms:CreateGrant [required]\n",
	}
	for _, want := range checks {
		if !strings.Contains(output, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, output)
		}
	}

	// Check resource references under each action
	resourceChecks := []string{
		"    → aws_backup_vault.this (create)\n",
	}
	for _, want := range resourceChecks {
		if !strings.Contains(output, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}

func TestFormatMissing_NoClass(t *testing.T) {
	missing := []iam.MissingAction{
		{
			ResourceType: "aws_backup_vault",
			ResourceName: "this",
			Change:       "create",
			Action:       "backup:CreateBackupVault",
			Service:      "backup",
			Class:        "",
		},
	}

	output := formatMissing(missing, nil)

	// Action line should have no class tag, followed by resource
	if !strings.Contains(output, "  backup:CreateBackupVault\n") {
		t.Errorf("expected action line without class tag, got:\n%s", output)
	}
	if !strings.Contains(output, "    → aws_backup_vault.this (create)\n") {
		t.Errorf("expected resource line, got:\n%s", output)
	}
}

func TestFormatMissing_UnverifiedSection(t *testing.T) {
	missing := []iam.MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "b", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_lambda_function", ResourceName: "fn", Change: "create", Action: "lambda:CreateFunction", Class: "[required]", ResourceScopeUnverified: true},
	}
	out := formatMissing(missing, nil)
	if !strings.Contains(out, "Missing IAM permissions (1):\n  s3:CreateBucket [required]\n") {
		t.Errorf("missing section wrong:\n%s", out)
	}
	if !strings.Contains(out, "Unverified IAM permissions (1)") ||
		!strings.Contains(out, "  lambda:CreateFunction [required] [unverified: resource scope]\n    → aws_lambda_function.fn (create)") {
		t.Errorf("unverified section wrong:\n%s", out)
	}
	if got := unverifiedCount(missing); got != 1 {
		t.Errorf("UnverifiedCount = %d, want 1", got)
	}
	if got := distinctCount(missing); got != 2 {
		t.Errorf("DistinctCount = %d, want 2", got)
	}

	only := formatMissing(missing[1:], nil)
	if strings.Contains(only, "Missing IAM permissions") {
		t.Errorf("no missing section expected when every finding is unverified:\n%s", only)
	}
}

func TestFormatGitHubAnnotations_Unverified(t *testing.T) {
	out := formatGitHubAnnotations([]iam.MissingAction{
		{ResourceType: "aws_lambda_function", ResourceName: "fn", Change: "create", Action: "lambda:CreateFunction", Class: "[required]", ResourceScopeUnverified: true},
	}, nil)
	want := "::warning title=Unverified IAM permission::lambda:CreateFunction [unverified: resource scope] needed by: aws_lambda_function.fn (create)\n"
	if out != want {
		t.Errorf("got  %q\nwant %q", out, want)
	}
}

func TestFormatJSON_Unverified(t *testing.T) {
	out := formatJSON([]iam.MissingAction{
		{ResourceType: "aws_lambda_function", ResourceName: "fn", Change: "create", Action: "lambda:CreateFunction", Class: "[required]", ResourceScopeUnverified: true},
		{ResourceType: "aws_s3_bucket", ResourceName: "b", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
	}, nil, 2, "resource changes", nil)
	var res struct {
		Status  string                   `json:"status"`
		Missing []map[string]interface{} `json:"missing"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "gaps_found" {
		t.Errorf("status = %q, want gaps_found", res.Status)
	}
	if res.Missing[0]["unverified"] != "resource_scope" {
		t.Errorf("unverified = %v, want resource_scope", res.Missing[0]["unverified"])
	}
	if _, ok := res.Missing[1]["unverified"]; ok {
		t.Errorf("a plain gap must omit unverified, got %v", res.Missing[1])
	}
}

// TestFormatExcluded groups by (action, reason) and includes the reason line.
func TestFormatExcluded(t *testing.T) {
	excluded := []iam.ExcludedAction{
		{MissingAction: iam.MissingAction{ResourceType: "aws_cloudtrail", ResourceName: "audit", Change: "create", Action: "s3:DeleteBucketPublicAccessBlock"}, Reason: "audit role"},
	}
	got := formatExcluded(excluded)
	for _, want := range []string{"Excluded (per config) (1):", "s3:DeleteBucketPublicAccessBlock", "reason: audit role", "→ aws_cloudtrail.audit (create)"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatExcluded missing %q\ngot:\n%s", want, got)
		}
	}
	if formatExcluded(nil) != "" {
		t.Error("formatExcluded(nil) should be empty")
	}
}

// TestFormatExcludedAnnotations emits a ::notice:: per group.
func TestFormatExcludedAnnotations(t *testing.T) {
	excluded := []iam.ExcludedAction{
		{MissingAction: iam.MissingAction{ResourceType: "aws_cloudtrail", ResourceName: "audit", Change: "create", Action: "s3:DeleteBucketPublicAccessBlock"}, Reason: "audit role"},
	}
	got := formatExcludedAnnotations(excluded)
	if !strings.Contains(got, "::notice title=Excluded IAM permission::") {
		t.Errorf("missing ::notice:: line\ngot: %s", got)
	}
	if !strings.Contains(got, "audit role") {
		t.Errorf("missing reason\ngot: %s", got)
	}
}

// TestFormatExcluded_Operations names the operation in the report line.
func TestFormatExcluded_Operations(t *testing.T) {
	excluded := []iam.ExcludedAction{
		{MissingAction: iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "locked", Change: "delete", Action: "s3:PutBucketEncryption"}, Reason: "no delete by design"},
	}
	got := formatExcluded(excluded)
	if !strings.Contains(got, "→ aws_s3_bucket.locked (delete)") {
		t.Errorf("missing operation in line\ngot:\n%s", got)
	}
}

// TestFormat_NeedSource verifies every format names the need as the source.
func TestFormat_NeedSource(t *testing.T) {
	missing := []iam.MissingAction{{Action: "ecr:DescribeImages", Service: "ecr", Class: "[required]", Need: "EcrImageVerification", NeedResource: repoA}}

	if got := formatMissing(missing, nil); !strings.Contains(got, `→ needs "EcrImageVerification" on `+repoA) {
		t.Errorf("FormatMissing:\n%s", got)
	}
	if got := formatGitHubAnnotations(missing, nil); !strings.Contains(got, `ecr:DescribeImages needed by: needs "EcrImageVerification" on `+repoA) {
		t.Errorf("FormatGitHubAnnotations:\n%s", got)
	}
	got := formatJSON(missing, nil, 0, "resource changes", nil)
	for _, want := range []string{`"need": "EcrImageVerification"`, `"need_resource": "` + repoA + `"`} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatJSON missing %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"resource_type"`) {
		t.Errorf("FormatJSON should omit the empty resource fields of a need:\n%s", got)
	}
	excluded := []iam.ExcludedAction{{MissingAction: missing[0], Reason: "later"}}
	if got := formatExcluded(excluded); !strings.Contains(got, `→ needs "EcrImageVerification"`) {
		t.Errorf("FormatExcluded:\n%s", got)
	}
	if got := formatExcludedAnnotations(excluded); !strings.Contains(got, `for: needs "EcrImageVerification"`) {
		t.Errorf("FormatExcludedAnnotations:\n%s", got)
	}
}
