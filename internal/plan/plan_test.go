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

func TestParseOutput(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/plan_with_output.json")
	if err != nil {
		t.Fatal(err)
	}

	value, err := ParseOutput(raw, "deploy_policy_json")
	if err != nil {
		t.Fatal(err)
	}

	expected := `"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DeployAll\",\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"`
	if string(value) != expected {
		t.Errorf("unexpected output value:\n got: %s\nwant: %s", string(value), expected)
	}
}

func TestParseOutputMissing(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/plan_with_output.json")
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseOutput(raw, "nonexistent_output")
	if err == nil {
		t.Fatal("expected error for missing output")
	}
}

func TestParseOutputNoPlannedValues(t *testing.T) {
	raw := []byte(`{"resource_changes": []}`)
	_, err := ParseOutput(raw, "anything")
	if err == nil {
		t.Fatal("expected error for plan without planned_values")
	}
}

func TestParseStateOutput(t *testing.T) {
	stateJSON := []byte(`{"outputs": {"my_policy": {"value": "{\"Version\":\"2012-10-17\"}", "type": "string"}}}`)
	value, err := ParseStateOutput(stateJSON, "my_policy")
	if err != nil {
		t.Fatal(err)
	}

	expected := `"{\"Version\":\"2012-10-17\"}"`
	if string(value) != expected {
		t.Errorf("unexpected state output value:\n got: %s\nwant: %s", string(value), expected)
	}
}

func TestParseStateOutputMissing(t *testing.T) {
	stateJSON := []byte(`{"outputs": {}}`)
	_, err := ParseStateOutput(stateJSON, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing state output")
	}
}

func TestParseStateOutputNoOutputs(t *testing.T) {
	stateJSON := []byte(`{}`)
	_, err := ParseStateOutput(stateJSON, "anything")
	if err == nil {
		t.Fatal("expected error for state JSON without outputs")
	}
}
