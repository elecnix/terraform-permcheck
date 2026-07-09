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

func TestParseAttributeValues(t *testing.T) {
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_wafv2_web_acl_association",
				"name": "known",
				"change": {
					"actions": ["create"],
					"after": {
						"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188",
						"web_acl_arn": "",
						"count": 1
					}
				}
			},
			{
				"type": "aws_wafv2_web_acl_association",
				"name": "computed",
				"change": {
					"actions": ["create"],
					"after": {"web_acl_arn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/x/y"}
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

	known := changes[0]
	if got := known.AttributeValues["resource_arn"]; got != "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188" {
		t.Errorf("expected resource_arn string value captured, got %q", got)
	}
	// Empty strings and non-string values are omitted.
	if _, ok := known.AttributeValues["web_acl_arn"]; ok {
		t.Error("expected empty string value to be omitted from AttributeValues")
	}
	if _, ok := known.AttributeValues["count"]; ok {
		t.Error("expected non-string value to be omitted from AttributeValues")
	}

	// resource_arn computed at apply time (not in after) → not captured.
	computed := changes[1]
	if _, ok := computed.AttributeValues["resource_arn"]; ok {
		t.Error("expected absent resource_arn to be omitted from AttributeValues")
	}
}

func TestParseTagsAllImpliesTags(t *testing.T) {
	// A resource tagged only via provider default_tags has an empty `tags` but a
	// populated `tags_all`; the tag gate must still be satisfied.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_kms_key",
				"name": "default_tagged",
				"change": {
					"actions": ["create"],
					"after": {"tags": {}, "tags_all": {"ManagedBy": "terraform"}}
				}
			}
		]
	}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if !changes[0].Attributes["tags"] {
		t.Error("expected tags gate to be satisfied when tags_all is populated via default_tags")
	}
}

func TestParseUnknownTagsImpliesTags(t *testing.T) {
	// A resource whose `tags` is set to a value computed at apply time reports
	// `tags`/`tags_all` as null in `after` and `after_unknown.tags == true`.
	// The tags will still be applied, so the tag gate must be satisfied.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_kms_key",
				"name": "computed_tags",
				"change": {
					"actions": ["create"],
					"after": {"tags": null, "tags_all": null},
					"after_unknown": {"tags": true, "tags_all": true}
				}
			}
		]
	}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if !changes[0].Attributes["tags"] {
		t.Error("expected tags gate to be satisfied when tags are known after apply (after_unknown.tags == true)")
	}
}

func TestParseUnknownTagsAllDoesNotImplyTags(t *testing.T) {
	// An untagged resource with no default_tags still reports
	// `after_unknown.tags_all == true` (tags_all is provider-computed), but no
	// tags will ever be applied. Only `after_unknown.tags` — never tags_all —
	// may satisfy the gate, otherwise every untagged resource false-positives.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_kms_key",
				"name": "untagged",
				"change": {
					"actions": ["create"],
					"after": {"tags": null, "tags_all": null},
					"after_unknown": {"tags_all": true}
				}
			}
		]
	}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if changes[0].Attributes["tags"] {
		t.Error("expected an unknown tags_all alone NOT to satisfy the tags gate")
	}
}

func TestParseNoAfter(t *testing.T) {
	// A plan with no "after" and no "before" (e.g. delete of a resource with no
	// recorded state) yields nil Attributes (unknown).
	raw := []byte(`{"resource_changes":[{"type":"aws_kms_key","name":"x","change":{"actions":["delete"]}}]}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Attributes != nil {
		t.Errorf("expected nil Attributes when neither before nor after present, got %v", changes[0].Attributes)
	}
}

func TestParseDeleteAttributePresenceFromBefore(t *testing.T) {
	// Delete changes carry no "after" state, but the provider's d.GetOk reads
	// prior state at destroy time — which the plan JSON exposes as "before".
	// Attributes for a delete must reflect "before", not "after".
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_secretsmanager_secret_version",
				"name": "example",
				"change": {
					"actions": ["delete"],
					"before": {
						"version_stages": ["AWSCURRENT"],
						"secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:x",
						"stage_hint": null,
						"tags": {}
					},
					"after": null
				}
			}
		]
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	del := changes[0]
	if del.Change != "delete" {
		t.Fatalf("expected delete change, got %q", del.Change)
	}
	if del.Attributes == nil {
		t.Fatal("expected Attributes to be populated from before on a delete change")
	}
	if !del.Attributes["version_stages"] {
		t.Error("expected version_stages to be present (set in before)")
	}
	if !del.Attributes["secret_id"] {
		t.Error("expected secret_id to be present (set in before)")
	}
	if del.Attributes["stage_hint"] {
		t.Error("expected null before value to count as absent")
	}
	if del.Attributes["tags"] {
		t.Error("expected empty tags map in before to count as absent")
	}
}

func TestParseDeleteAttributePresenceUnsetInBefore(t *testing.T) {
	// A delete whose prior state never had the gating attribute set must report
	// it absent, so the conditional permission it gates can be suppressed.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_secretsmanager_secret_version",
				"name": "example",
				"change": {
					"actions": ["delete"],
					"before": {"secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:x"},
					"after": null
				}
			}
		]
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if changes[0].Attributes["version_stages"] {
		t.Error("expected version_stages to be absent when unset in before")
	}
}

func TestParseDeleteAttributeValuesFromBefore(t *testing.T) {
	// AttributeValues (used for cross-service callback resolution) must also
	// come from before on delete changes.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_wafv2_web_acl_association",
				"name": "assoc",
				"change": {
					"actions": ["delete"],
					"before": {
						"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188",
						"web_acl_arn": ""
					},
					"after": null
				}
			}
		]
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if got := changes[0].AttributeValues["resource_arn"]; got != "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188" {
		t.Errorf("expected resource_arn value from before, got %q", got)
	}
}

func TestParseReplaceStillUsesAfter(t *testing.T) {
	// Replace actions ([\"delete\",\"create\"] / [\"create\",\"delete\"]) map to
	// "create" and must keep using after, not before — only pure deletes read
	// from before.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_kms_key",
				"name": "replaced",
				"change": {
					"actions": ["delete", "create"],
					"before": {"tags": {}},
					"after": {"tags": {"Environment": "test"}}
				}
			}
		]
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if changes[0].Change != "create" {
		t.Fatalf("expected replace to map to create, got %q", changes[0].Change)
	}
	if !changes[0].Attributes["tags"] {
		t.Error("expected replace (create) to read tags from after, not before")
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
