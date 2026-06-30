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

func TestParseAttributePresence(t *testing.T) {
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_kms_key",
				"name": "tagged",
				"change": {
					"actions": ["create"],
					"after": {
						"description": "test",
						"tags": {"Environment": "test"},
						"enable_key_rotation": false,
						"deletion_window_in_days": null,
						"policy": ""
					}
				}
			},
			{
				"type": "aws_kms_key",
				"name": "untagged",
				"change": {
					"actions": ["create"],
					"after": {"description": "no tags", "tags": {}}
				}
			}
		]
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(changes))
	}

	tagged := changes[0]
	if tagged.Attributes == nil {
		t.Fatal("expected tagged resource to have parsed attributes")
	}
	if !tagged.Attributes["tags"] {
		t.Error("expected tags to be present on tagged resource")
	}
	if !tagged.Attributes["description"] {
		t.Error("expected description to be present")
	}
	if tagged.Attributes["enable_key_rotation"] {
		t.Error("expected false bool to count as absent (GetOk semantics)")
	}
	if tagged.Attributes["deletion_window_in_days"] {
		t.Error("expected null to count as absent")
	}
	if tagged.Attributes["policy"] {
		t.Error("expected empty string to count as absent")
	}

	untagged := changes[1]
	if untagged.Attributes["tags"] {
		t.Error("expected empty tags map to count as absent")
	}
}

func TestParseNoAfter(t *testing.T) {
	// A plan with no "after" (e.g. delete) yields nil Attributes (unknown).
	raw := []byte(`{"resource_changes":[{"type":"aws_kms_key","name":"x","change":{"actions":["delete"]}}]}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Attributes != nil {
		t.Errorf("expected nil Attributes when no after present, got %v", changes[0].Attributes)
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
