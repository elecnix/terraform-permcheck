package iam

import (
	"testing"
)

// deleteAndCreateFixture mixes a create gap and a delete gap on the same
// permission, which is what an operations list has to separate.
func deleteAndCreateFixture() []MissingAction {
	return []MissingAction{
		{ResourceType: "aws_s3_bucket_server_side_encryption_configuration", ResourceName: "locked", Change: "create", Action: "s3:PutBucketEncryption", Class: ClassManagement},
		{ResourceType: "aws_s3_bucket_server_side_encryption_configuration", ResourceName: "locked", Change: "delete", Action: "s3:PutBucketEncryption", Class: ClassManagement},
	}
}

// TestApplyExclusions_OperationsLimitsToOneOperation keeps the delete gap when
// the exclusion names delete only.
func TestApplyExclusions_OperationsLimitsToOneOperation(t *testing.T) {
	excl := []Exclusion{{
		Permission: "s3:PutBucketEncryption",
		Resource:   "aws_s3_bucket_server_side_encryption_configuration.*",
		Operations: []string{"delete"},
		Reason:     "role intentionally cannot delete",
	}}

	kept, excluded := ApplyExclusions(deleteAndCreateFixture(), excl)

	if len(excluded) != 1 || excluded[0].Change != "delete" {
		t.Fatalf("excluded = %+v, want only the delete change", excluded)
	}
	if len(kept) != 1 || kept[0].Change != "create" {
		t.Fatalf("kept = %+v, want only the create change", kept)
	}
}

// TestApplyExclusions_NoOperationsKeepsEveryOperation pins today's meaning: an
// entry without operations suppresses the permission on every change.
func TestApplyExclusions_NoOperationsKeepsEveryOperation(t *testing.T) {
	excl := []Exclusion{{Permission: "s3:PutBucketEncryption"}}

	kept, excluded := ApplyExclusions(deleteAndCreateFixture(), excl)

	if len(kept) != 0 {
		t.Fatalf("kept = %+v, want none", kept)
	}
	if len(excluded) != 2 {
		t.Fatalf("excluded = %d, want 2: %+v", len(excluded), excluded)
	}
}

// TestApplyExclusions_OperationsMultiple accepts a list of operations.
func TestApplyExclusions_OperationsMultiple(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "b", Change: "create", Action: "s3:PutBucketEncryption"},
		{ResourceType: "aws_s3_bucket", ResourceName: "b", Change: "update", Action: "s3:PutBucketEncryption"},
		{ResourceType: "aws_s3_bucket", ResourceName: "b", Change: "delete", Action: "s3:PutBucketEncryption"},
	}
	excl := []Exclusion{{Permission: "s3:*", Operations: []string{"update", "delete"}}}

	kept, excluded := ApplyExclusions(missing, excl)

	if len(excluded) != 2 {
		t.Fatalf("excluded = %d, want 2: %+v", len(excluded), excluded)
	}
	if len(kept) != 1 || kept[0].Change != "create" {
		t.Fatalf("kept = %+v, want only the create change", kept)
	}
}

// TestApplyExclusions_OperationsNeverMatches reports a real gap when the entry's
// operations don't cover the change at all.
func TestApplyExclusions_OperationsNeverMatches(t *testing.T) {
	excl := []Exclusion{{Permission: "s3:*", Operations: []string{"delete"}}}

	kept, excluded := ApplyExclusions(deleteAndCreateFixture()[:1], excl)

	if len(excluded) != 0 {
		t.Fatalf("excluded = %+v, want none", excluded)
	}
	if len(kept) != 1 {
		t.Fatalf("kept = %d, want 1", len(kept))
	}
}

// TestApplyExclusions_OperationsAndResource combines both scopes.
func TestApplyExclusions_OperationsAndResource(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "locked", Change: "delete", Action: "s3:PutBucketEncryption"},
		{ResourceType: "aws_cloudtrail", ResourceName: "audit", Change: "delete", Action: "s3:PutBucketEncryption"},
	}
	excl := []Exclusion{{
		Permission: "s3:PutBucketEncryption",
		Resource:   "aws_s3_bucket.*",
		Operations: []string{"delete"},
	}}

	kept, excluded := ApplyExclusions(missing, excl)

	if len(excluded) != 1 || excluded[0].ResourceType != "aws_s3_bucket" {
		t.Fatalf("excluded = %+v, want only the bucket", excluded)
	}
	if len(kept) != 1 || kept[0].ResourceType != "aws_cloudtrail" {
		t.Fatalf("kept = %+v, want only the trail", kept)
	}
}
