package iam

import (
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

func TestFilterS3Subresources(t *testing.T) {
	changes := []*plan.ResourceChange{
		{Type: "aws_s3_bucket", Name: "logs", Change: "create"},
		{Type: "aws_s3_bucket_server_side_encryption_configuration", Name: "logs_enc", Change: "create"},
	}
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:CreateBucket", Service: "s3"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:PutBucketEncryption", Service: "s3"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:PutBucketVersioning", Service: "s3"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:DeleteBucket", Service: "s3"},
	}

	result := filterS3Subresources(missing, changes)

	if len(result) != 3 {
		t.Fatalf("expected 3 missing after filtering, got %d: %v", len(result), result)
	}

	// s3:CreateBucket should remain (not absorbed)
	if !hasAction(result, "s3:CreateBucket") {
		t.Error("expected s3:CreateBucket to remain")
	}
	// s3:PutBucketEncryption should be absorbed by the SSE config sub-resource
	if hasAction(result, "s3:PutBucketEncryption") {
		t.Error("expected s3:PutBucketEncryption to be filtered (absorbed by sub-resource)")
	}
	// s3:PutBucketVersioning should remain (no versioning sub-resource present)
	if !hasAction(result, "s3:PutBucketVersioning") {
		t.Error("expected s3:PutBucketVersioning to remain (no versioning sub-resource in plan)")
	}
	// s3:DeleteBucket should remain (not absorbed)
	if !hasAction(result, "s3:DeleteBucket") {
		t.Error("expected s3:DeleteBucket to remain")
	}
}

func TestFilterS3Subresources_NoSubs(t *testing.T) {
	// When no S3 sub-resources are present, nothing should be filtered
	changes := []*plan.ResourceChange{
		{Type: "aws_s3_bucket", Name: "logs", Change: "create"},
		{Type: "aws_dynamodb_table", Name: "data", Change: "create"},
	}
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:PutBucketEncryption", Service: "s3"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:CreateBucket", Service: "s3"},
	}

	result := filterS3Subresources(missing, changes)

	if len(result) != 2 {
		t.Fatalf("expected 2 missing (no subs present), got %d", len(result))
	}
}

func TestFilterS3Subresources_MultipleSubs(t *testing.T) {
	// Multiple sub-resources: each absorbs its own permissions
	changes := []*plan.ResourceChange{
		{Type: "aws_s3_bucket", Name: "logs", Change: "create"},
		{Type: "aws_s3_bucket_server_side_encryption_configuration", Name: "logs_enc", Change: "create"},
		{Type: "aws_s3_bucket_versioning", Name: "logs_ver", Change: "create"},
		{Type: "aws_s3_bucket_logging", Name: "logs_log", Change: "create"},
	}
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:CreateBucket", Service: "s3"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:PutBucketEncryption", Service: "s3"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:PutBucketVersioning", Service: "s3"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:PutBucketLogging", Service: "s3"},
	}

	result := filterS3Subresources(missing, changes)

	if len(result) != 1 {
		t.Fatalf("expected 1 missing after filtering all subs, got %d: %v", len(result), result)
	}
	if result[0].Action != "s3:CreateBucket" {
		t.Errorf("expected only s3:CreateBucket to remain, got %s", result[0].Action)
	}
}

func TestFilterS3Subresources_OnlyParent(t *testing.T) {
	// When only aws_s3_bucket exists (no sub-resources), all its permissions should remain
	changes := []*plan.ResourceChange{
		{Type: "aws_s3_bucket", Name: "logs", Change: "create"},
	}
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:CreateBucket", Service: "s3"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:PutBucketEncryption", Service: "s3"},
	}

	result := filterS3Subresources(missing, changes)

	if len(result) != 2 {
		t.Fatalf("expected 2 missing (only parent, no subs), got %d", len(result))
	}
}

func TestFilterS3Subresources_NonS3Unaffected(t *testing.T) {
	// Non-S3 resources should not be affected by S3 sub-resource filtering
	changes := []*plan.ResourceChange{
		{Type: "aws_s3_bucket", Name: "logs", Change: "create"},
		{Type: "aws_s3_bucket_server_side_encryption_configuration", Name: "logs_enc", Change: "create"},
		{Type: "aws_backup_vault", Name: "main", Change: "create"},
	}
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "create", Action: "s3:PutBucketEncryption", Service: "s3"},
		{ResourceType: "aws_backup_vault", ResourceName: "main", Change: "create", Action: "backup:CreateBackupVault", Service: "backup"},
	}

	result := filterS3Subresources(missing, changes)

	if len(result) != 1 {
		t.Fatalf("expected 1 missing (s3 encryption absorbed, backup vault remains), got %d", len(result))
	}
	if result[0].Action != "backup:CreateBackupVault" {
		t.Errorf("expected backup:CreateBackupVault to remain, got %s", result[0].Action)
	}
}

func TestS3SubresourceAbsorbed(t *testing.T) {
	// SSE config absorbs PutBucketEncryption
	absorbed := s3SubresourceAbsorbed("aws_s3_bucket_server_side_encryption_configuration")
	if len(absorbed) != 1 || !absorbed["s3:PutBucketEncryption"] {
		t.Errorf("expected {s3:PutBucketEncryption}, got %v", absorbed)
	}

	// Unknown type returns nil
	absorbed = s3SubresourceAbsorbed("aws_nonexistent")
	if absorbed != nil {
		t.Errorf("expected nil for unknown type, got %v", absorbed)
	}
}

// fakeSchema is a test SchemaLike with conditional metadata.
type fakeSchema struct {
	perms map[string][]string
	cond  map[string]map[string]string
}

func (f fakeSchema) GetPermissions() map[string][]string          { return f.perms }
func (f fakeSchema) GetConditional() map[string]map[string]string { return f.cond }

type fakeResolver struct{ s SchemaLike }

func (r fakeResolver) Resolve(string) (SchemaLike, error) { return r.s, nil }

// denyAll covers no actions.
type denyAll struct{}

func (denyAll) Covers(string) bool { return false }

func TestValidate_ConditionalGatedOnAttribute(t *testing.T) {
	schema := fakeSchema{
		perms: map[string][]string{
			"create": {"kms:CreateKey", "kms:TagResource"},
		},
		cond: map[string]map[string]string{
			"create": {"kms:TagResource": "tags"},
		},
	}
	resolver := fakeResolver{schema}

	// Case 1: tags present → kms:TagResource is required (reported missing).
	withTags := []*plan.ResourceChange{
		{Type: "aws_kms_key", Name: "k", Change: "create", Attributes: map[string]bool{"tags": true}},
	}
	missing, err := Validate(withTags, denyAll{}, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "kms:TagResource") {
		t.Error("expected kms:TagResource to be required when tags are present")
	}
	if !hasAction(missing, "kms:CreateKey") {
		t.Error("expected kms:CreateKey to always be required")
	}

	// Case 2: attributes parsed but tags absent → kms:TagResource gated out.
	noTags := []*plan.ResourceChange{
		{Type: "aws_kms_key", Name: "k", Change: "create", Attributes: map[string]bool{"description": true}},
	}
	missing, err = Validate(noTags, denyAll{}, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "kms:TagResource") {
		t.Error("expected kms:TagResource to be gated out when tags absent")
	}
	if !hasAction(missing, "kms:CreateKey") {
		t.Error("expected kms:CreateKey to remain required")
	}

	// Case 3: no attribute info (nil) → conditional kept (cannot prove absence).
	unknown := []*plan.ResourceChange{
		{Type: "aws_kms_key", Name: "k", Change: "create"},
	}
	missing, err = Validate(unknown, denyAll{}, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "kms:TagResource") {
		t.Error("expected kms:TagResource to be kept when attribute info is unknown")
	}
}

func TestValidate_ConditionalGatedOnAttribute_Delete(t *testing.T) {
	// A conditional permission on a delete change must be evaluated against
	// prior state (change.before), not treated as unknown.
	schema := fakeSchema{
		perms: map[string][]string{
			"delete": {"secretsmanager:DeleteSecret", "secretsmanager:UpdateSecretVersionStage"},
		},
		cond: map[string]map[string]string{
			"delete": {"secretsmanager:UpdateSecretVersionStage": "version_stages"},
		},
	}
	resolver := fakeResolver{schema}

	// Case 1: before-state has version_stages set → permission still required.
	withStages := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret_version", Name: "v", Change: "delete", Attributes: map[string]bool{"version_stages": true}},
	}
	missing, err := Validate(withStages, denyAll{}, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "secretsmanager:UpdateSecretVersionStage") {
		t.Error("expected UpdateSecretVersionStage to be required when before-state has version_stages set")
	}

	// Case 2: before-state has version_stages unset → permission suppressed.
	withoutStages := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret_version", Name: "v", Change: "delete", Attributes: map[string]bool{"secret_id": true}},
	}
	missing, err = Validate(withoutStages, denyAll{}, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "secretsmanager:UpdateSecretVersionStage") {
		t.Error("expected UpdateSecretVersionStage to be suppressed when before-state has version_stages unset")
	}
	if !hasAction(missing, "secretsmanager:DeleteSecret") {
		t.Error("expected unconditional DeleteSecret to remain required")
	}
}

func TestFormatMissing_Grouped(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "data", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "logs_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "data_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_cloudwatch_log_group", ResourceName: "api", Change: "delete", Action: "cloudwatchlogs:TagResource", Class: "[required]"},
	}

	got := FormatMissing(missing, nil)

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
	missing := []MissingAction{
		{ResourceType: "aws_iam_role", ResourceName: "deploy", Change: "delete", Action: "iam:RemoveRoleFromInstanceProfile", Class: "[required]"},
	}

	got := FormatMissing(missing, nil)

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
	got := FormatMissing(nil, nil)
	if got != "" {
		t.Errorf("expected empty string for nil, got %q", got)
	}

	got = FormatMissing([]MissingAction{}, nil)
	if got != "" {
		t.Errorf("expected empty string for empty slice, got %q", got)
	}
}

func TestDistinctCount(t *testing.T) {
	missing := []MissingAction{
		{Action: "s3:HeadBucket", Class: "[required]"},
		{Action: "s3:HeadBucket", Class: "[required]"},
		{Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{Action: "cloudwatchlogs:TagResource", Class: "[required]"},
		{Action: "backup:CreateBackupVault", Class: "[optional]"},
	}

	got := DistinctCount(missing)
	if got != 4 {
		t.Errorf("DistinctCount = %d, want 4", got)
	}

	// Different class = different group
	missing2 := []MissingAction{
		{Action: "s3:HeadBucket", Class: "[required]"},
		{Action: "s3:HeadBucket", Class: "[optional]"},
	}
	if DistinctCount(missing2) != 2 {
		t.Error("same action with different classes should be distinct")
	}

	// Empty
	if DistinctCount(nil) != 0 {
		t.Error("empty should return 0")
	}
}

func TestFormatGitHubAnnotations_Grouped(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "data", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "logs_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "data_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_cloudwatch_log_group", ResourceName: "api", Change: "delete", Action: "cloudwatchlogs:TagResource", Class: "[required]"},
	}

	got := FormatGitHubAnnotations(missing, nil)

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
	got := FormatGitHubAnnotations(nil, nil)
	if got != "" {
		t.Errorf("expected empty string for nil, got %q", got)
	}

	got = FormatGitHubAnnotations([]MissingAction{}, nil)
	if got != "" {
		t.Errorf("expected empty string for empty slice, got %q", got)
	}
}

func TestFormatGitHubAnnotations_Conditional(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_backup_vault", ResourceName: "main", Change: "create", Action: "kms:CreateGrant", Class: "[required]", ConditionAttribute: "kms_key_arn"},
	}

	got := FormatGitHubAnnotations(missing, nil)

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

func hasAction(missing []MissingAction, action string) bool {
	for _, m := range missing {
		if m.Action == action {
			return true
		}
	}
	return false
}

func TestFormatMissing_ConditionalAttribute(t *testing.T) {
	// Conditional permissions should show [conditional: <attr>]
	missing := []MissingAction{
		{ResourceType: "aws_backup_vault", ResourceName: "main", Change: "create", Action: "kms:CreateGrant", Class: "[required]", ConditionAttribute: "kms_key_arn"},
		{ResourceType: "aws_backup_vault", ResourceName: "main", Change: "create", Action: "kms:CreateKey", Class: "[required]", ConditionAttribute: ""},
	}
	got := FormatMissing(missing, nil)
	if !strings.Contains(got, "kms:CreateGrant [conditional: kms_key_arn]") {
		t.Errorf("expected conditional tag, got:\n%s", got)
	}
	if !strings.Contains(got, "kms:CreateKey [required]") {
		t.Errorf("expected [required] tag for unconditional action, got:\n%s", got)
	}
}

func TestValidate_ExcludeConditional(t *testing.T) {
	schema := fakeSchema{
		perms: map[string][]string{
			"create": {"kms:CreateKey", "kms:CreateGrant"},
		},
		cond: map[string]map[string]string{
			"create": {"kms:CreateGrant": "kms_key_arn"},
		},
	}
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{Type: "aws_backup_vault", Name: "v", Change: "create"},
	}

	// With ExcludeConditional: kms:CreateGrant should be filtered out
	filter := FilterConfig{ExcludeConditional: true}
	missing, err := Validate(changes, denyAll{}, resolver, filter)
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "kms:CreateGrant") {
		t.Error("kms:CreateGrant should be excluded when ExcludeConditional is true")
	}
	if !hasAction(missing, "kms:CreateKey") {
		t.Error("kms:CreateKey should remain (unconditional)")
	}
}

func TestStripResourceIndex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no index", "cloudtrail", "cloudtrail"},
		{"count index", "cloudtrail[0]", "cloudtrail"},
		{"large count", "cloudtrail[123]", "cloudtrail"},
		{"for_each string key", `config["us-east-1"]`, "config"},
		{"for_each with dots", `foo["bar.baz"]`, "foo"},
		{"already clean", "my_bucket", "my_bucket"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripResourceIndex(tt.input)
			if got != tt.expected {
				t.Errorf("stripResourceIndex(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestFormatGitHubAnnotations_WithFileLocation(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "cloudtrail", Change: "create", Action: "s3:PutPublicAccessBlock", Class: "[required]"},
	}

	locations := map[string]FileLocation{
		"aws_s3_bucket.cloudtrail":                     {Path: "modules/datadog-cloudtrail/main.tf", Line: 10},
		"aws_s3_bucket_public_access_block.cloudtrail": {Path: "modules/datadog-cloudtrail/main.tf", Line: 82},
	}

	got := FormatGitHubAnnotations(missing, locations)

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
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "unknown_bucket", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
	}

	locations := map[string]FileLocation{
		"aws_s3_bucket.cloudtrail": {Path: "main.tf", Line: 5},
	}

	got := FormatGitHubAnnotations(missing, locations)

	// The group contains cloudtrail (has location) and unknown_bucket (no location).
	// First resource with a location wins → should have file=...
	if !strings.Contains(got, "::warning file=main.tf,line=5,title=Missing IAM permission::") {
		t.Errorf("expected file= for group with partial locations, got:\n%s", got)
	}
}

func TestFormatGitHubAnnotations_NoLocations(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
	}

	// nil map → behavior unchanged
	got := FormatGitHubAnnotations(missing, nil)

	if !strings.Contains(got, "::warning title=Missing IAM permission::") {
		t.Error("expected ::warning without file= when locations is nil")
	}
	if strings.Contains(got, "file=") {
		t.Error("should not include file= when locations is nil")
	}

	// Empty map → same behavior
	got = FormatGitHubAnnotations(missing, map[string]FileLocation{})

	if !strings.Contains(got, "::warning title=Missing IAM permission::") {
		t.Error("expected ::warning without file= when locations is empty")
	}
	if strings.Contains(got, "file=") {
		t.Error("should not include file= when locations is empty")
	}
}

func TestFormatGitHubAnnotations_StripIndexForLookup(t *testing.T) {
	// Resource names with count/for_each indices should be stripped before lookup.
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail[0]", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: `config["us-east-1"]`, Change: "create", Action: "s3:PutBucketPolicy", Class: "[required]"},
	}

	locations := map[string]FileLocation{
		"aws_s3_bucket.cloudtrail": {Path: "main.tf", Line: 10},
		"aws_s3_bucket.config":     {Path: "config.tf", Line: 42},
	}

	got := FormatGitHubAnnotations(missing, locations)

	if !strings.Contains(got, "::warning file=main.tf,line=10,title=Missing IAM permission::") {
		t.Errorf("expected file=main.tf,line=10 for cloudtrail[0], got:\n%s", got)
	}
	if !strings.Contains(got, "::warning file=config.tf,line=42,title=Missing IAM permission::") {
		t.Errorf("expected file=config.tf,line=42 for config[\"us-east-1\"], got:\n%s", got)
	}
}

func TestFormatMissing_WithFileLocation(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
	}

	locations := map[string]FileLocation{
		"aws_s3_bucket.cloudtrail": {Path: "main.tf", Line: 10},
		// logs has NO location
	}

	got := FormatMissing(missing, locations)

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
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "cloudtrail[0]", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
	}

	locations := map[string]FileLocation{
		"aws_s3_bucket.cloudtrail": {Path: "main.tf", Line: 10},
	}

	got := FormatMissing(missing, locations)

	if !strings.Contains(got, "    → aws_s3_bucket.cloudtrail[0] (create) [main.tf:10]\n") {
		t.Errorf("expected stripped index lookup with file location, got:\n%s", got)
	}
}
