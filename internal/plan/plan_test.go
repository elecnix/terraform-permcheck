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

func TestParseReferences(t *testing.T) {
	// A plan carrying a configuration section with an expression that
	// references another resource: the reference must surface on the change
	// even though the resulting value is computed at apply time.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_secretsmanager_secret_version",
				"name": "b",
				"change": {
					"actions": ["create"],
					"after": {"secret_string": "placeholder"},
					"after_unknown": {"secret_id": true, "arn": true}
				}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{
						"address": "aws_secretsmanager_secret.b",
						"mode": "managed",
						"type": "aws_secretsmanager_secret",
						"name": "b",
						"expressions": {"name": {"constant_value": "example-b"}}
					},
					{
						"address": "aws_secretsmanager_secret_version.b",
						"mode": "managed",
						"type": "aws_secretsmanager_secret_version",
						"name": "b",
						"expressions": {
							"secret_id": {
								"references": [
									"aws_secretsmanager_secret.b.id",
									"aws_secretsmanager_secret.b"
								]
							},
							"secret_string": {"constant_value": "placeholder"}
						}
					}
				]
			}
		}
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	rc := changes[0]
	refs := rc.References["secret_id"]
	if len(refs) != 2 {
		t.Fatalf("expected 2 references for secret_id, got %v", refs)
	}
	if refs[0] != "aws_secretsmanager_secret.b.id" || refs[1] != "aws_secretsmanager_secret.b" {
		t.Errorf("unexpected references: %v", refs)
	}
	// A constant-only expression contributes no references.
	if rc.References["secret_string"] != nil {
		t.Errorf("expected no references for constant secret_string, got %v", rc.References["secret_string"])
	}
}

func TestParseReferencesAbsent(t *testing.T) {
	// Without a configuration section there are no references (static HCL mode
	// and minimal plan fixtures behave the same).
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_secretsmanager_secret_version",
				"name": "b",
				"change": {"actions": ["create"]}
			}
		]
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if changes[0].References != nil {
		t.Errorf("expected nil References when configuration is absent, got %v", changes[0].References)
	}
}

func TestParseReferencesNestedModule(t *testing.T) {
	// A resource declared inside a module: its references must be found by
	// walking module_calls.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_secretsmanager_secret_version",
				"name": "b",
				"change": {"actions": ["create"]}
			}
		],
		"configuration": {
			"root_module": {
				"module_calls": {
					"secrets": {
						"module": {
							"resources": [
								{
									"address": "module.secrets.aws_secretsmanager_secret_version.b",
									"mode": "managed",
									"type": "aws_secretsmanager_secret_version",
									"name": "b",
									"expressions": {
										"secret_id": {"references": ["aws_secretsmanager_secret.b"]}
									}
								}
							]
						}
					}
				}
			}
		}
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	refs := changes[0].References["secret_id"]
	if len(refs) != 1 || refs[0] != "aws_secretsmanager_secret.b" {
		t.Errorf("expected [aws_secretsmanager_secret.b], got %v", refs)
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

func TestParseChangedAttributes(t *testing.T) {
	// The provider's d.HasChange reports whether an attribute differs between
	// prior and planned state. ChangedAttributes must record that per attribute
	// so the tool can suppress update-path calls gated on d.HasChange when the
	// attribute did not change.
	tests := []struct {
		name string
		raw  string
		want map[string]bool // nil means "unknown" (map must be nil)
	}{
		{
			name: "update with one attribute changed",
			raw: `{
				"resource_changes": [
					{
						"type": "aws_iam_role",
						"name": "example",
						"change": {
							"actions": ["update"],
							"before": {"permissions_boundary": "arn:aws:iam::aws:policy/boundary", "assume_role_policy": "v1"},
							"after": {"permissions_boundary": "arn:aws:iam::aws:policy/boundary", "assume_role_policy": "v2"}
						}
					}
				]
			}`,
			want: map[string]bool{"permissions_boundary": false, "assume_role_policy": true},
		},
		{
			name: "object attributes compared structurally, not textually",
			raw: `{
				"resource_changes": [
					{
						"type": "aws_iam_role",
						"name": "example",
						"change": {
							"actions": ["update"],
							"before": {"inline_policy": {"a": "1", "b": "2"}},
							"after": {"inline_policy": {"b": "2", "a": "1"}}
						}
					}
				]
			}`,
			want: map[string]bool{"inline_policy": false},
		},
		{
			name: "attribute computed at apply counts as changed",
			raw: `{
				"resource_changes": [
					{
						"type": "aws_iam_role",
						"name": "example",
						"change": {
							"actions": ["update"],
							"before": {"permissions_boundary": "arn:aws:iam::aws:policy/boundary"},
							"after": {"permissions_boundary": null},
							"after_unknown": {"permissions_boundary": true}
						}
					}
				]
			}`,
			want: map[string]bool{"permissions_boundary": true},
		},
		{
			name: "create counts every planned attribute as changed",
			raw: `{
				"resource_changes": [
					{
						"type": "aws_iam_role",
						"name": "example",
						"change": {
							"actions": ["create"],
							"before": null,
							"after": {"permissions_boundary": "arn:aws:iam::aws:policy/boundary"}
						}
					}
				]
			}`,
			want: map[string]bool{"permissions_boundary": true},
		},
		{
			// Terraform writes no diff for an attribute that is null on a
			// create, so the provider's d.HasChange reads false for it.
			name: "create counts an attribute planned as null as unchanged",
			raw: `{
				"resource_changes": [
					{
						"type": "aws_iam_role",
						"name": "example",
						"change": {
							"actions": ["create"],
							"before": null,
							"after": {"permissions_boundary": "arn:aws:iam::aws:policy/boundary", "description": null}
						}
					}
				]
			}`,
			want: map[string]bool{"permissions_boundary": true, "description": false},
		},
		{
			name: "delete has no planned state, so the change is unknown",
			raw: `{
				"resource_changes": [
					{
						"type": "aws_iam_role",
						"name": "example",
						"change": {
							"actions": ["delete"],
							"before": {"permissions_boundary": "arn:aws:iam::aws:policy/boundary"},
							"after": null
						}
					}
				]
			}`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes, err := Parse([]byte(tt.raw), "aws_")
			if err != nil {
				t.Fatal(err)
			}
			if len(changes) != 1 {
				t.Fatalf("expected 1 change, got %d", len(changes))
			}

			got := changes[0].ChangedAttributes
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil ChangedAttributes, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected ChangedAttributes %v, got nil", tt.want)
			}
			for attr, want := range tt.want {
				if got[attr] != want {
					t.Errorf("ChangedAttributes[%q] = %v, want %v", attr, got[attr], want)
				}
			}
			if len(got) != len(tt.want) {
				t.Errorf("ChangedAttributes has %d keys, want %d: %v", len(got), len(tt.want), got)
			}
		})
	}
}

func TestParseConfiguredAttributes(t *testing.T) {
	// A destroy plan: the configuration section keeps only the attributes the
	// author wrote, while the prior state carries every computed default. The
	// gap between the two tells a defaulted attribute from a configured one.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_secretsmanager_secret_version",
				"name": "b",
				"change": {
					"actions": ["delete"],
					"before": {"id": "sv-1", "version_stages": ["AWSCURRENT"]}
				}
			},
			{
				"type": "aws_secretsmanager_secret_version",
				"name": "c",
				"change": {
					"actions": ["delete"],
					"before": {"id": "sv-2", "version_stages": ["AWSCURRENT", "AWSPREVIOUS"]}
				}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{
						"mode": "managed",
						"type": "aws_secretsmanager_secret_version",
						"name": "b",
						"expressions": {"secret_string": {"constant_value": "placeholder"}}
					},
					{
						"mode": "managed",
						"type": "aws_secretsmanager_secret_version",
						"name": "c",
						"expressions": {
							"secret_string": {"constant_value": "placeholder"},
							"version_stages": {"constant_value": ["AWSPREVIOUS"]}
						}
					}
				]
			}
		}
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(changes))
	}

	// b: only secret_string written, so version_stages holds its default.
	if changes[0].Configured["version_stages"] {
		t.Error("version_stages should not count as configured for b")
	}
	if !changes[0].Configured["secret_string"] {
		t.Error("secret_string should count as configured for b")
	}

	// c: version_stages written, so the call's guard can turn true.
	if !changes[1].Configured["version_stages"] {
		t.Error("version_stages should count as configured for c")
	}
}

func TestParseConfiguredAttributesAbsent(t *testing.T) {
	// Without a configuration section, nothing is known about what the author
	// wrote, so Configured stays nil and callers must not treat it as absent.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_secretsmanager_secret_version",
				"name": "b",
				"change": {"actions": ["delete"], "before": {"id": "sv-1"}}
			}
		]
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if changes[0].Configured != nil {
		t.Errorf("expected nil Configured when configuration is absent, got %v", changes[0].Configured)
	}
}

func TestParseConfiguredAttributesCreate(t *testing.T) {
	// A create keeps the same rule: the configuration section, not the planned
	// state, records what the author wrote.
	raw := []byte(`{
		"resource_changes": [
			{
				"type": "aws_secretsmanager_secret_version",
				"name": "b",
				"change": {
					"actions": ["create"],
					"after": {"version_stages": ["AWSCURRENT"], "secret_string": "placeholder"}
				}
			}
		],
		"configuration": {
			"root_module": {
				"resources": [
					{
						"mode": "managed",
						"type": "aws_secretsmanager_secret_version",
						"name": "b",
						"expressions": {"secret_string": {"constant_value": "placeholder"}}
					}
				]
			}
		}
	}`)

	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if changes[0].Configured["version_stages"] {
		t.Error("version_stages should not count as configured when the author left it out")
	}
}

func TestParseConfiguredAttributesIgnoresDataSource(t *testing.T) {
	// A data source sharing the managed resource's type and name must not
	// supply the configured set.
	raw := []byte(`{
		"resource_changes": [
			{"type": "aws_secretsmanager_secret_version", "name": "b",
			 "change": {"actions": ["delete"], "before": {"version_stages": ["AWSCURRENT"]}}}
		],
		"configuration": {"root_module": {"resources": [
			{"mode": "data", "type": "aws_secretsmanager_secret_version", "name": "b",
			 "expressions": {"version_stages": {"constant_value": ["AWSPREVIOUS"]}}},
			{"mode": "managed", "type": "aws_secretsmanager_secret_version", "name": "b",
			 "expressions": {"secret_string": {"constant_value": "x"}}}
		]}}
	}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if changes[0].Configured["version_stages"] {
		t.Error("data source expressions leaked into the managed resource's configured set")
	}
	if !changes[0].Configured["secret_string"] {
		t.Error("managed resource expressions should be configured")
	}
}

func TestParseConfiguredAttributesSameNameInTwoModules(t *testing.T) {
	// Two module instances declare the same type and name; each change must
	// read its own module's configuration, picked by module_address.
	raw := []byte(`{
		"resource_changes": [
			{"module_address": "module.second", "type": "aws_secretsmanager_secret_version", "name": "this",
			 "change": {"actions": ["delete"], "before": {"version_stages": ["AWSCURRENT"]}}},
			{"module_address": "module.outer[0].module.inner[\"k\"]", "type": "aws_secretsmanager_secret_version", "name": "this",
			 "change": {"actions": ["delete"], "before": {"version_stages": ["AWSCURRENT"]}}},
			{"type": "aws_secretsmanager_secret_version", "name": "this",
			 "change": {"actions": ["delete"], "before": {"version_stages": ["AWSCURRENT"]}}}
		],
		"configuration": {"root_module": {
			"resources": [
				{"mode": "managed", "type": "aws_secretsmanager_secret_version", "name": "this",
				 "expressions": {"secret_string": {"constant_value": "root"}}}
			],
			"module_calls": {
				"first": {"module": {"resources": [
					{"mode": "managed", "type": "aws_secretsmanager_secret_version", "name": "this",
					 "expressions": {"version_stages": {"constant_value": ["AWSPREVIOUS"]}}}
				]}},
				"second": {"module": {"resources": [
					{"mode": "managed", "type": "aws_secretsmanager_secret_version", "name": "this",
					 "expressions": {"secret_string": {"constant_value": "second"}}}
				]}},
				"outer": {"module": {"module_calls": {"inner": {"module": {"resources": [
					{"mode": "managed", "type": "aws_secretsmanager_secret_version", "name": "this",
					 "expressions": {"version_stages": {"constant_value": ["AWSPREVIOUS"]}}}
				]}}}}}
			}
		}}
	}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if changes[0].Configured["version_stages"] || !changes[0].Configured["secret_string"] {
		t.Errorf("module.second read the wrong module: %v", changes[0].Configured)
	}
	if !changes[1].Configured["version_stages"] {
		t.Errorf("nested indexed module address not resolved: %v", changes[1].Configured)
	}
	if changes[2].Configured["version_stages"] || !changes[2].Configured["secret_string"] {
		t.Errorf("root resource read a module's configuration: %v", changes[2].Configured)
	}
}
