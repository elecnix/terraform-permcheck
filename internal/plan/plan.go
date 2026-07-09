// Package plan parses terraform plan JSON output from `terraform show -json plan.tfplan`.
package plan

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ResourceChange is a single resource action extracted from a plan.
type ResourceChange struct {
	Type   string // terraform resource type, e.g. "aws_backup_vault"
	Name   string // terraform resource name, e.g. "this"
	Change string // "create", "update", or "delete"

	// Attributes records which top-level attributes are meaningfully set,
	// following terraform's GetOk semantics: a key maps to true only when its
	// value is non-null and non-zero. For create/update/replace it reflects the
	// planned "after" state; for a pure delete it reflects the prior "before"
	// state, since that's what the provider's d.GetOk reads at destroy time. It
	// is nil when the plan carries neither state, meaning presence is unknown.
	// Used to gate conditional permissions on attribute presence.
	Attributes map[string]bool

	// AttributeValues records the concrete string values of top-level
	// attributes — from "after" for create/update/replace, from "before" for a
	// pure delete. Only known, non-empty string values are included (values
	// computed at apply time are absent). Used to resolve cross-service
	// callback targets — e.g. the service embedded in an
	// aws_wafv2_web_acl_association's resource_arn. It is nil when the plan
	// carries no corresponding state.
	AttributeValues map[string]string
}

// tfPlanJSON mirrors the subset of `terraform show -json plan.tfplan` we need.
type tfPlanJSON struct {
	ResourceChanges []tfResourceChange `json:"resource_changes"`
}

type tfResourceChange struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Change struct {
		Actions      []string        `json:"actions"`
		Before       json.RawMessage `json:"before"`
		After        json.RawMessage `json:"after"`
		AfterUnknown json.RawMessage `json:"after_unknown"`
	} `json:"change"`
}

// actionsToChange converts terraform action slices to a single verb.
// ["create"] → "create", ["update"] → "update", ["delete"] → "delete",
// ["create","delete"] (replace) → "create" (needs create perms).
func actionsToChange(actions []string) string {
	if len(actions) == 0 {
		return "no-op"
	}
	if len(actions) == 1 {
		return actions[0]
	}
	// Multi-action (e.g. replace): check if it includes create.
	for _, a := range actions {
		if a == "create" {
			return "create"
		}
	}
	return actions[0]
}

// Parse extracts every resource change from raw terraform plan JSON,
// keeping only resources whose type starts with prefix (e.g. "aws_").
// If prefix is empty, all resource types are kept.
func Parse(raw []byte, prefix string) ([]*ResourceChange, error) {
	var plan tfPlanJSON
	if err := json.Unmarshal(raw, &plan); err != nil {
		return nil, err
	}

	var changes []*ResourceChange
	for _, rc := range plan.ResourceChanges {
		if prefix != "" && !strings.HasPrefix(rc.Type, prefix) {
			continue
		}
		action := actionsToChange(rc.Change.Actions)
		if action == "no-op" {
			continue
		}
		// Pure deletes carry no "after" state. At destroy time the provider's
		// d.GetOk reads prior state, exposed by the plan JSON as "before" — so
		// evaluate attribute presence/values there instead. Replace actions
		// (mapped to "create" above) still need "after", since that's the state
		// being applied.
		attrSource, afterUnknown := rc.Change.After, rc.Change.AfterUnknown
		if action == "delete" {
			attrSource, afterUnknown = rc.Change.Before, nil // before-values are never "unknown"
		}
		changes = append(changes, &ResourceChange{
			Type:            rc.Type,
			Name:            rc.Name,
			Change:          action,
			Attributes:      attributePresence(attrSource, afterUnknown),
			AttributeValues: attributeStringValues(attrSource),
		})
	}
	return changes, nil
}

// attributePresence reports which top-level attributes of a resource change
// state (either the planned "after" state, or "before" for a pure delete) are
// meaningfully set. afterUnknown is the parallel "after_unknown" object, where
// a top-level attribute maps to true when its value is computed at apply time
// (always nil when state is "before", since prior state is never unknown).
// Returns nil when state is absent or null (presence unknown).
func attributePresence(state, afterUnknown json.RawMessage) map[string]bool {
	if len(state) == 0 || string(state) == "null" {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(state, &fields); err != nil {
		return nil
	}
	present := make(map[string]bool, len(fields))
	for k, v := range fields {
		present[k] = isMeaningful(v)
	}

	// The provider's transparent tagging keys off the effective tag set
	// (tags_all = provider default_tags ∪ resource tags), so a resource can be
	// tagged — and require kms:TagResource — via default_tags even with no
	// resource-level `tags` block. Treat the canonical `tags` gate as satisfied
	// whenever either is set.
	if present["tags_all"] {
		present["tags"] = true
	}

	// A `tags` value computed at apply time (e.g. tags = { X = some.arn })
	// shows as null in "after" but true in "after_unknown". The tags will still
	// be applied, so the gate must be satisfied. Only `tags` counts here, never
	// `tags_all`: tags_all is provider-computed and reads as unknown even on an
	// untagged resource with no default_tags, which would false-positive on
	// every such resource.
	if unknownAttrSet(afterUnknown, "tags") {
		present["tags"] = true
	}

	return present
}

// unknownAttrSet reports whether a top-level attribute is marked fully
// computed-at-apply in a change's "after_unknown" object (i.e. the attribute
// maps to the JSON literal true).
func unknownAttrSet(afterUnknown json.RawMessage, attr string) bool {
	if len(afterUnknown) == 0 {
		return false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(afterUnknown, &fields); err != nil {
		return false
	}
	var unknown bool
	if err := json.Unmarshal(fields[attr], &unknown); err != nil {
		return false
	}
	return unknown
}

// attributeStringValues extracts the concrete string values of top-level
// attributes from a resource change state (either the planned "after" state,
// or "before" for a pure delete). Only non-empty JSON strings are captured;
// null, empty, and non-string values (numbers, bools, objects, arrays, and
// values computed at apply time) are omitted. Returns nil when state is
// absent or null.
func attributeStringValues(state json.RawMessage) map[string]string {
	if len(state) == 0 || string(state) == "null" {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(state, &fields); err != nil {
		return nil
	}
	values := make(map[string]string)
	for k, v := range fields {
		var s string
		if err := json.Unmarshal(v, &s); err == nil && s != "" {
			values[k] = s
		}
	}
	return values
}

// isMeaningful reports whether a JSON value is set to a non-zero value,
// mirroring terraform's d.GetOk semantics (null, "", false, 0, empty
// map/array all count as unset).
func isMeaningful(raw json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	switch val := v.(type) {
	case nil:
		return false
	case bool:
		return val
	case float64:
		return val != 0
	case string:
		return val != ""
	case []any:
		return len(val) > 0
	case map[string]any:
		return len(val) > 0
	default:
		return true
	}
}

// tfOutput holds the subset of a Terraform output we need.
type tfOutput struct {
	Value json.RawMessage `json:"value"`
}

// tfPlanWithOutputs mirrors the planned_values.outputs section of a plan.
type tfPlanWithOutputs struct {
	PlannedValues struct {
		Outputs map[string]tfOutput `json:"outputs"`
	} `json:"planned_values"`
}

// ParseOutput extracts the value of a named output from a terraform plan JSON
// (from `terraform show -json plan.tfplan`). It navigates to
// planned_values.outputs.<name>.value and returns the raw JSON value.
func ParseOutput(raw []byte, name string) (json.RawMessage, error) {
	var plan tfPlanWithOutputs
	if err := json.Unmarshal(raw, &plan); err != nil {
		return nil, fmt.Errorf("parse plan for output %q: %w", name, err)
	}

	output, ok := plan.PlannedValues.Outputs[name]
	if !ok {
		return nil, fmt.Errorf("output %q not found in plan outputs", name)
	}

	return output.Value, nil
}

// tfStateOutputs mirrors the outputs section of terraform state JSON
// (from `terraform show -json`).
type tfStateOutputs struct {
	Outputs map[string]tfOutput `json:"outputs"`
}

// ParseStateOutput extracts the value of a named output from terraform state
// JSON (from `terraform show -json` without a plan file). It navigates to
// outputs.<name>.value and returns the raw JSON value.
func ParseStateOutput(raw []byte, name string) (json.RawMessage, error) {
	var state tfStateOutputs
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("parse state for output %q: %w", name, err)
	}

	output, ok := state.Outputs[name]
	if !ok {
		return nil, fmt.Errorf("output %q not found in state outputs", name)
	}

	return output.Value, nil
}
