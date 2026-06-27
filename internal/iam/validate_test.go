package iam

import (
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

func hasAction(missing []MissingAction, action string) bool {
	for _, m := range missing {
		if m.Action == action {
			return true
		}
	}
	return false
}
