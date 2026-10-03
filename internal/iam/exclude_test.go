package iam

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func missingFixture() []MissingAction {
	return []MissingAction{
		{ResourceType: "aws_cloudtrail", ResourceName: "audit", Change: "create", Action: "s3:DeleteBucketPublicAccessBlock", Class: "[required]"},
		{ResourceType: "aws_secretsmanager_secret", ResourceName: "forwarder", Change: "create", Action: "secretsmanager:UpdateSecretVersionStage", Class: "[required]"},
		{ResourceType: "aws_dynamodb_table", ResourceName: "items", Change: "create", Action: "dynamodb:CreateTable", Class: "[required]"},
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

// TestLoadConfig_Valid parses a well-formed config file.
func TestLoadConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	body := `{
  "exclude": [
    { "permission": "s3:DeleteBucketPublicAccessBlock", "reason": "audit role" },
    { "permission": "secretsmanager:*", "resource": "aws_secretsmanager_*" }
  ]
}`
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Exclude) != 2 {
		t.Fatalf("got %d exclusions, want 2", len(cfg.Exclude))
	}
	if cfg.Exclude[0].Reason != "audit role" || cfg.Exclude[1].Resource != "aws_secretsmanager_*" {
		t.Errorf("unexpected parse: %+v", cfg.Exclude)
	}
}

// TestLoadConfig_MissingPermission rejects an exclusion without a permission.
func TestLoadConfig_MissingPermission(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	if err := os.WriteFile(p, []byte(`{"exclude":[{"reason":"no permission"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(p)
	if err == nil || !strings.Contains(err.Error(), "permission is required") {
		t.Fatalf("expected 'permission is required' error, got %v", err)
	}
}

// TestLoadConfig_BadJSON reports a parse error.
func TestLoadConfig_BadJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	if err := os.WriteFile(p, []byte(`{not json`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

// TestLoadConfig_BadPattern rejects an invalid glob pattern.
func TestLoadConfig_BadPattern(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	if err := os.WriteFile(p, []byte(`{"exclude":[{"permission":"s3:[bad"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("expected invalid pattern error, got nil")
	}
}

// TestFormatExcluded groups by (action, reason) and includes the reason line.
func TestFormatExcluded(t *testing.T) {
	excluded := []ExcludedAction{
		{MissingAction: MissingAction{ResourceType: "aws_cloudtrail", ResourceName: "audit", Change: "create", Action: "s3:DeleteBucketPublicAccessBlock"}, Reason: "audit role"},
	}
	got := FormatExcluded(excluded)
	for _, want := range []string{"Excluded (per config) (1):", "s3:DeleteBucketPublicAccessBlock", "reason: audit role", "→ aws_cloudtrail.audit (create)"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatExcluded missing %q\ngot:\n%s", want, got)
		}
	}
	if FormatExcluded(nil) != "" {
		t.Error("FormatExcluded(nil) should be empty")
	}
}

// TestFormatExcludedAnnotations emits a ::notice:: per group.
func TestFormatExcludedAnnotations(t *testing.T) {
	excluded := []ExcludedAction{
		{MissingAction: MissingAction{ResourceType: "aws_cloudtrail", ResourceName: "audit", Change: "create", Action: "s3:DeleteBucketPublicAccessBlock"}, Reason: "audit role"},
	}
	got := FormatExcludedAnnotations(excluded)
	if !strings.Contains(got, "::notice title=Excluded IAM permission::") {
		t.Errorf("missing ::notice:: line\ngot: %s", got)
	}
	if !strings.Contains(got, "audit role") {
		t.Errorf("missing reason\ngot: %s", got)
	}
}
