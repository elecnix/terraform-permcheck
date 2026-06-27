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
}

// tfPlanJSON mirrors the subset of `terraform show -json plan.tfplan` we need.
type tfPlanJSON struct {
	ResourceChanges []tfResourceChange `json:"resource_changes"`
}

type tfResourceChange struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Change struct {
		Actions []string `json:"actions"`
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
		changes = append(changes, &ResourceChange{
			Type:   rc.Type,
			Name:   rc.Name,
			Change: action,
		})
	}
	return changes, nil
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
