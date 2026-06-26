package plan

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/plan.json")
	if err != nil {
		t.Fatal(err)
	}

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}

	if len(changes) != 3 {
		t.Fatalf("expected 3 changes (excluding no-op s3_bucket), got %d", len(changes))
	}

	found := make(map[string]bool)
	for _, c := range changes {
		found[c.Type] = true
	}

	for _, want := range []string{"aws_backup_vault", "aws_dynamodb_table", "aws_iam_role"} {
		if !found[want] {
			t.Errorf("missing expected resource type %q in plan", want)
		}
	}

	// s3_bucket should not appear since it's "no-op"
	if found["aws_s3_bucket"] {
		t.Error("no-op resource should not appear in changes")
	}
}

func TestParseEmptyStdin(t *testing.T) {
	raw := json.RawMessage(`{"resource_changes": []}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes, got %d", len(changes))
	}
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := Parse([]byte("not json"), "aws_")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
