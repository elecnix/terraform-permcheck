package iam

import (
	"testing"
)

func missingFixture() []MissingAction {
	return []MissingAction{
		{ResourceType: "aws_cloudtrail", ResourceName: "audit", Change: "create", Action: "s3:DeleteBucketPublicAccessBlock", Class: ClassManagement},
		{ResourceType: "aws_secretsmanager_secret", ResourceName: "forwarder", Change: "create", Action: "secretsmanager:UpdateSecretVersionStage", Class: ClassManagement},
		{ResourceType: "aws_dynamodb_table", ResourceName: "items", Change: "create", Action: "dynamodb:CreateTable", Class: ClassManagement},
	}
}

// TestApplyExclusions_ByPermission suppresses a single action regardless of resource.
func TestApplyExclusions_ByPermission(t *testing.T) {
	excl := []Exclusion{{Permission: "s3:DeleteBucketPublicAccessBlock", Reason: "CloudTrail bucket managed by audit role"}}
	kept, excluded := ApplyExclusions(missingFixture(), excl)

	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2: %+v", len(kept), kept)
	}
	if len(excluded) != 1 {
		t.Fatalf("excluded = %d, want 1: %+v", len(excluded), excluded)
	}
	if excluded[0].Action != "s3:DeleteBucketPublicAccessBlock" {
		t.Errorf("excluded action = %q", excluded[0].Action)
	}
	if excluded[0].Reason != "CloudTrail bucket managed by audit role" {
		t.Errorf("excluded reason = %q", excluded[0].Reason)
	}
}

// TestApplyExclusions_ResourceScope only suppresses when the resource pattern matches.
func TestApplyExclusions_ResourceScope(t *testing.T) {
	// Same permission on a non-matching resource type is NOT excluded.
	excl := []Exclusion{{Permission: "dynamodb:CreateTable", Resource: "aws_secretsmanager_*"}}
	kept, excluded := ApplyExclusions(missingFixture(), excl)
	if len(excluded) != 0 {
		t.Fatalf("expected no exclusions (resource scope mismatch), got %+v", excluded)
	}
	if len(kept) != 3 {
		t.Fatalf("kept = %d, want 3", len(kept))
	}

	// Wildcard resource type scope that DOES match.
	excl = []Exclusion{{Permission: "secretsmanager:*", Resource: "aws_secretsmanager_*"}}
	kept, excluded = ApplyExclusions(missingFixture(), excl)
	if len(excluded) != 1 || excluded[0].Action != "secretsmanager:UpdateSecretVersionStage" {
		t.Fatalf("expected secretsmanager exclusion, got %+v", excluded)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %d, want 2", len(kept))
	}
}

// TestApplyExclusions_ResourceAddress scopes by the full type.name address.
func TestApplyExclusions_ResourceAddress(t *testing.T) {
	excl := []Exclusion{{Permission: "s3:*", Resource: "aws_cloudtrail.audit"}}
	_, excluded := ApplyExclusions(missingFixture(), excl)
	if len(excluded) != 1 || excluded[0].ResourceName != "audit" {
		t.Fatalf("expected address-scoped exclusion, got %+v", excluded)
	}

	// A different instance name must not match.
	excl = []Exclusion{{Permission: "s3:*", Resource: "aws_cloudtrail.other"}}
	_, excluded = ApplyExclusions(missingFixture(), excl)
	if len(excluded) != 0 {
		t.Fatalf("expected no exclusion for non-matching address, got %+v", excluded)
	}
}

// TestApplyExclusions_IndexedAddress strips count/for_each index before matching.
func TestApplyExclusions_IndexedAddress(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_cloudtrail", ResourceName: "audit[0]", Change: "create", Action: "s3:DeleteBucketPublicAccessBlock"},
	}
	excl := []Exclusion{{Permission: "s3:*", Resource: "aws_cloudtrail.audit"}}
	_, excluded := ApplyExclusions(missing, excl)
	if len(excluded) != 1 {
		t.Fatalf("expected indexed address to match after stripping index, got %+v", excluded)
	}
}

// TestApplyExclusions_NoExclusions keeps everything.
func TestApplyExclusions_NoExclusions(t *testing.T) {
	kept, excluded := ApplyExclusions(missingFixture(), nil)
	if len(kept) != 3 || len(excluded) != 0 {
		t.Fatalf("kept=%d excluded=%d, want 3/0", len(kept), len(excluded))
	}
}
