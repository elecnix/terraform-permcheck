package iam

import (
	"bytes"
	"encoding/json"
	"os"
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
