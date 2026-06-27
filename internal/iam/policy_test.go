package iam

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/policy_full.json")
	if err != nil {
		t.Fatal(err)
	}

	doc, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}

	if doc.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %s", doc.Version)
	}
	if len(doc.Statements) != 4 {
		t.Errorf("expected 4 statements, got %d", len(doc.Statements))
	}
}

func TestPolicyCovers(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/policy_full.json")
	if err != nil {
		t.Fatal(err)
	}

	doc, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Exact match
	if !doc.Covers("backup:CreateBackupVault") {
		t.Error("expected policy to cover backup:CreateBackupVault (exact match)")
	}

	if !doc.Covers("kms:CreateGrant") {
		t.Error("expected policy to cover kms:CreateGrant (single action string)")
	}

	// Wildcard match via iam:*
	if !doc.Covers("iam:CreateRole") {
		t.Error("expected policy to cover iam:CreateRole via iam:* wildcard")
	}

	// Not covered
	if doc.Covers("s3:PutObject") {
		t.Error("policy should NOT cover s3:PutObject (not declared)")
	}
}

func TestPolicyCoversPartial(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/policy_partial.json")
	if err != nil {
		t.Fatal(err)
	}

	doc, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}

	// backup:* wildcard should cover any backup action
	if !doc.Covers("backup:CreateBackupVault") {
		t.Error("expected backup:* to cover backup:CreateBackupVault")
	}

	if !doc.Covers("backup:DeleteBackupVault") {
		t.Error("expected backup:* to cover backup:DeleteBackupVault")
	}

	// Should not cover non-backup actions
	if doc.Covers("kms:CreateGrant") {
		t.Error("partial policy should NOT cover kms:CreateGrant")
	}
}

func TestWildcardMatching(t *testing.T) {
	tests := []struct {
		pattern string
		action  string
		match   bool
	}{
		{"*", "backup:CreateBackupVault", true},
		{"*", "anything", true},
		{"backup:*", "backup:CreateBackupVault", true},
		{"backup:*", "backup:DeleteBackupVault", true},
		{"backup:*", "kms:CreateGrant", false},
		{"backup:*", "backupstorage:Mount", false},
		{"backup:CreateBackupVault", "backup:CreateBackupVault", true},
		{"backup:CreateBackupVault", "backup:DeleteBackupVault", false},
	}

	for _, tt := range tests {
		got := matchesWildcard(tt.pattern, tt.action)
		if got != tt.match {
			t.Errorf("matchesWildcard(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.match)
		}
	}
}

func TestParsePolicyInvalidJSON(t *testing.T) {
	_, err := ParsePolicy([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestActionFieldSingleString(t *testing.T) {
	input := []byte(`{"Action": "s3:GetObject"}`)
	var s struct {
		Action actionField `json:"Action"`
	}
	if err := newJSONDecoder(input).Decode(&s); err != nil {
		t.Fatal(err)
	}
	if len(s.Action) != 1 || s.Action[0] != "s3:GetObject" {
		t.Errorf("expected [s3:GetObject], got %v", s.Action)
	}
}

func TestActionFieldStringSlice(t *testing.T) {
	input := []byte(`{"Action": ["s3:GetObject", "s3:PutObject"]}`)
	var s struct {
		Action actionField `json:"Action"`
	}
	if err := newJSONDecoder(input).Decode(&s); err != nil {
		t.Fatal(err)
	}
	if len(s.Action) != 2 {
		t.Errorf("expected 2 actions, got %d", len(s.Action))
	}
}

// newJSONDecoder creates a JSON decoder from a byte slice.
func newJSONDecoder(data []byte) *json.Decoder {
	return json.NewDecoder(bytes.NewReader(data))
}

func TestClassifyPermission(t *testing.T) {
	tests := []struct {
		action string
		class  PermissionClass
	}{
		// Management-plane
		{"backup:CreateBackupVault", ClassManagement},
		{"backup:DeleteBackupVault", ClassManagement},
		{"dynamodb:CreateTable", ClassManagement},
		{"dynamodb:DescribeTable", ClassManagement},
		{"dynamodb:UpdateTable", ClassManagement},
		{"kms:CreateGrant", ClassManagement},
		{"kms:DescribeKey", ClassManagement},
		{"ec2:CreateVpc", ClassManagement},
		{"iam:CreateRole", ClassManagement},
		{"s3:CreateBucket", ClassManagement},
		{"s3:DeleteBucket", ClassManagement},
		{"logs:CreateLogGroup", ClassManagement},
		{"logs:DeleteLogGroup", ClassManagement},
		{"logs:DescribeLogGroups", ClassManagement},
		{"logs:PutRetentionPolicy", ClassManagement},

		// Data-plane
		{"dynamodb:PutItem", ClassDataPlane},
		{"dynamodb:GetItem", ClassDataPlane},
		{"dynamodb:Query", ClassDataPlane},
		{"dynamodb:Scan", ClassDataPlane},
		{"s3:GetObject", ClassDataPlane},
		{"s3:PutObject", ClassDataPlane},
		{"s3:DeleteObject", ClassDataPlane},
		{"kms:Encrypt", ClassDataPlane},
		{"kms:Decrypt", ClassDataPlane},
		{"kinesis:PutRecords", ClassDataPlane},
		{"sqs:SendMessage", ClassDataPlane},
		{"logs:CreateLogStream", ClassDataPlane},
		{"logs:PutLogEvents", ClassDataPlane},
		{"backup-storage:MountCapsule", ClassDataPlane},
		{"s3tables:CreateTable", ClassDataPlane},

		// Optional sub-resources
		{"backup:PutBackupVaultAccessPolicy", ClassOptional},
		{"backup:PutBackupVaultNotifications", ClassOptional},
		{"backup:PutBackupVaultLockConfiguration", ClassOptional},
		{"s3:PutBucketWebsite", ClassOptional},
		{"s3:PutBucketLogging", ClassOptional},
		{"s3:PutReplicationConfiguration", ClassOptional},
		{"dynamodb:ImportTable", ClassOptional},
		{"secretsmanager:GetRandomPassword", ClassOptional},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := classifyPermission(tt.action)
			if got != tt.class {
				t.Errorf("classifyPermission(%q) = %d, want %d", tt.action, got, tt.class)
			}
		})
	}
}

func TestClassTag(t *testing.T) {
	tests := []struct {
		class PermissionClass
		tag   string
	}{
		{ClassManagement, "[required]"},
		{ClassOptional, "[optional]"},
		{ClassDataPlane, "[data-plane]"},
		{ClassServiceRole, "[service-role]"},
		{ClassUnknown, "[unknown]"},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			got := classTag(tt.class)
			if got != tt.tag {
				t.Errorf("classTag(%d) = %q, want %q", tt.class, got, tt.tag)
			}
		})
	}
}

func TestFormatMissing_WithClassification(t *testing.T) {
	missing := []MissingAction{
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

	output := FormatMissing(missing)

	// Check header
	if !strings.Contains(output, "Missing IAM permissions (3)") {
		t.Errorf("expected header with count, got: %s", output)
	}

	// Check tags appear in output
	checks := []string{
		"backup:CreateBackupVault [required]",
		"backup:PutBackupVaultAccessPolicy [optional]",
		"kms:CreateGrant [required]",
	}
	for _, want := range checks {
		if !strings.Contains(output, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}

func TestFormatMissing_NoClass(t *testing.T) {
	missing := []MissingAction{
		{
			ResourceType: "aws_backup_vault",
			ResourceName: "this",
			Change:       "create",
			Action:       "backup:CreateBackupVault",
			Service:      "backup",
			Class:        "",
		},
	}

	output := FormatMissing(missing)

	// Should NOT have a trailing space before newline (no tag)
	if !strings.Contains(output, "needs backup:CreateBackupVault\n") {
		t.Errorf("expected no classification tag, got:\n%s", output)
	}
}
