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

func TestFormatMissing_Grouped(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "logs", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket", ResourceName: "data", Change: "delete", Action: "s3:HeadBucket", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "logs_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_s3_bucket_public_access_block", ResourceName: "data_block", Change: "delete", Action: "s3:DeletePublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_cloudwatch_log_group", ResourceName: "api", Change: "delete", Action: "cloudwatchlogs:TagResource", Class: "[required]"},
	}

	got := FormatMissing(missing)

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

	got := FormatMissing(missing)

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
	got := FormatMissing(nil)
	if got != "" {
		t.Errorf("expected empty string for nil, got %q", got)
	}

	got = FormatMissing([]MissingAction{})
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
	got := FormatMissing(missing)
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
