package iam

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// TestParseConfig_Operations parses the optional list.
func TestParseConfig_Operations(t *testing.T) {
	cfg, err := parseConfig([]byte(`{"exclude":[
		{"permission":"s3:DeleteBucketEncryption","operations":["delete"],"reason":"locked bucket"},
		{"permission":"s3:*"}
	]}`))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if len(cfg.Exclude[0].Operations) != 1 || cfg.Exclude[0].Operations[0] != "delete" {
		t.Errorf("operations = %+v, want [delete]", cfg.Exclude[0].Operations)
	}
	if cfg.Exclude[1].Operations != nil {
		t.Errorf("absent operations = %+v, want nil", cfg.Exclude[1].Operations)
	}
}

// TestParseConfig_OperationsNormalized pins that the trimmed, lowercased
// operation names land in the returned config, so a caller reading
// Config.Exclude[i].Operations never sees "Delete" or " delete ".
func TestParseConfig_OperationsNormalized(t *testing.T) {
	cfg, err := parseConfig([]byte(`{"exclude":[{"permission":"s3:*","operations":["Delete"," UPDATE "]}]}`))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	want := []string{"delete", "update"}
	if !slices.Equal(cfg.Exclude[0].Operations, want) {
		t.Fatalf("operations = %q, want %q", cfg.Exclude[0].Operations, want)
	}
}

// TestParseConfig_UnknownOperation rejects a name the plan never emits.
func TestParseConfig_UnknownOperation(t *testing.T) {
	_, err := parseConfig([]byte(`{"exclude":[{"permission":"s3:*","operations":["destroy"]}]}`))
	if err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("expected 'unknown operation' error, got %v", err)
	}
}

// TestLoadConfig_OperationsFile reads an operations list from disk.
func TestLoadConfig_OperationsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	body := `{"exclude":[{"permission":"s3:DeleteBucketEncryption","resource":"aws_s3_bucket_server_side_encryption_configuration.*","operations":["delete"],"reason":"role intentionally cannot delete"}]}`
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	e := cfg.Exclude[0]
	if len(e.Operations) != 1 || e.Operations[0] != "delete" {
		t.Fatalf("operations = %+v, want [delete]", e.Operations)
	}
}
