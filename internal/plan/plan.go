// Package plan parses terraform plan JSON output from `terraform show -json plan.tfplan`.
package plan

import (
	"encoding/json"
	"fmt"
	"reflect"
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

	// ChangedAttributes records which top-level attributes differ between the
	// prior "before" state and the planned "after" state, following terraform's
	// d.HasChange semantics. An attribute computed at apply time counts as
	// changed, since terraform still applies a diff for it. A create or a
	// replace measures against empty prior state, because the provider's Create
	// starts from nothing. It is nil when the
	// plan carries no planned state (a pure delete), meaning change is unknown.
	// Used to gate permissions on whether an attribute changed.
	ChangedAttributes map[string]bool

	// AttributeValues records the concrete string values of top-level
	// attributes — from "after" for create/update/replace, from "before" for a
	// pure delete. Only known, non-empty string values are included (values
	// computed at apply time are absent). Used to resolve resource-scoped
	// coverage — e.g. the service embedded in an aws_wafv2_web_acl_association's
	// resource_arn, or a target secret's name referenced by an
	// aws_secretsmanager_secret_version's secret_id. It is nil when the plan
	// carries no corresponding state.
	AttributeValues map[string]string

	// References records, per top-level attribute, the addresses of the
	// resources it references — from the plan's configuration section, which
	// keeps the original expressions even when the value is computed at apply
	// time (e.g. secret_id referencing
	// ["aws_secretsmanager_secret.b.id", "aws_secretsmanager_secret.b"]).
	// Nil when no reference data is available (static HCL mode).
	References map[string][]string

	// Configured records which top-level attributes the author wrote, taken
	// from the plan's configuration section: it lists an attribute only when
	// the configuration sets it. The gap to the state is what separates a
	// configured attribute from one holding a default — an unconfigured
	// version_stages still reads as ["AWSCURRENT"] in the prior state. It is
	// nil when the plan carries no configuration section, meaning the set of
	// configured attributes is unknown.
	Configured map[string]bool
}

// tfPlanJSON mirrors the subset of `terraform show -json plan.tfplan` we need.
type tfPlanJSON struct {
	ResourceChanges []tfResourceChange `json:"resource_changes"`
	Configuration   *tfConfiguration   `json:"configuration"`
}

// tfConfiguration mirrors the plan's configuration section, which retains the
// original attribute expressions (including resource references) even when the
// resulting values are computed at apply time.
type tfConfiguration struct {
	RootModule *tfModule `json:"root_module"`
}

// tfModule mirrors a module's resources and nested module calls in the
// configuration section.
type tfModule struct {
	Resources   []tfConfigResource      `json:"resources"`
	ModuleCalls map[string]tfModuleCall `json:"module_calls"`
}

// tfConfigResource mirrors a single resource entry in the configuration
// section.
type tfConfigResource struct {
	Type        string                  `json:"type"`
	Name        string                  `json:"name"`
	Mode        string                  `json:"mode"`
	Expressions map[string]tfExpression `json:"expressions"`
}

// tfExpression mirrors a single attribute expression; only its references
// matter here. The references list records every resource the expression
// references even when the value is computed at apply time.
type tfExpression struct {
	References []string `json:"references"`
}

// tfModuleCall mirrors a module call in the configuration section, whose
// nested module_calls/resources hold the module's own resources.
type tfModuleCall struct {
	Module tfModule `json:"module"`
}

type tfResourceChange struct {
	ModuleAddress string `json:"module_address"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Change        struct {
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
			Type:              rc.Type,
			Name:              rc.Name,
			Change:            action,
			Attributes:        attributePresence(attrSource, afterUnknown),
			ChangedAttributes: changedAttributes(changeBaseline(rc.Change.Actions, rc.Change.Before), rc.Change.After, rc.Change.AfterUnknown),
			AttributeValues:   attributeStringValues(attrSource),
			References:        resourceReferences(plan.Configuration, rc.Type, rc.Name),
			Configured:        configuredAttributes(plan.Configuration, rc.ModuleAddress, rc.Type, rc.Name),
		})
	}
	return changes, nil
}

// resourceReferences walks the plan's configuration section (root module and
// nested modules) for a resource of the given type and name and returns, per
// attribute, the list of addresses the attribute references. Returns nil when
// the plan carries no configuration section or the resource isn't found.
func resourceReferences(cfg *tfConfiguration, resType, resName string) map[string][]string {
	if cfg == nil || cfg.RootModule == nil {
		return nil
	}
	refs := referencesInModule(cfg.RootModule, resType, resName)
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// configuredAttributes returns the set of top-level attributes a resource's
// configuration writes. The module address picks the module instance the
// resource lives in, so two modules declaring the same type and name each read
// their own configuration. Returns nil when the plan carries no configuration
// section or the resource isn't found, which reads as "unknown", not "none".
func configuredAttributes(cfg *tfConfiguration, moduleAddr, resType, resName string) map[string]bool {
	if cfg == nil || cfg.RootModule == nil {
		return nil
	}
	m := moduleForAddress(cfg.RootModule, moduleAddr)
	if m == nil {
		return nil
	}
	for _, r := range m.Resources {
		if r.Mode != "" && r.Mode != "managed" {
			continue
		}
		if r.Type != resType || r.Name != resName {
			continue
		}
		// A resource in the configuration with no expressions is configured
		// with nothing, which is not the same as absent from it.
		configured := make(map[string]bool, len(r.Expressions))
		for attr := range r.Expressions {
			configured[attr] = true
		}
		return configured
	}
	return nil
}

// moduleForAddress follows a resource change's module_address (for example
// `module.a[0].module.b["k"]`) down the configuration's module calls. Instance
// keys are dropped: the configuration describes a module call, not its
// instances. Returns nil when a module in the path is not in the configuration
// or the address is not a module address.
func moduleForAddress(root *tfModule, addr string) *tfModule {
	m := root
	names, ok := moduleCallNames(addr)
	if !ok {
		return nil
	}
	for _, name := range names {
		mc, ok := m.ModuleCalls[name]
		if !ok {
			return nil
		}
		next := mc.Module
		m = &next
	}
	return m
}

// moduleCallNames returns the module call names in a module address, in order,
// without instance keys. It splits on dots outside brackets, since a key may
// itself contain dots. It reports false for an address that is not a sequence
// of `module.<name>` pairs, so a malformed address never resolves to a module.
func moduleCallNames(addr string) ([]string, bool) {
	if addr == "" {
		return nil, true
	}
	var parts []string
	depth, start := 0, 0
	for i := 0; i <= len(addr); i++ {
		if i < len(addr) {
			switch addr[i] {
			case '[':
				depth++
			case ']':
				depth--
				if depth < 0 {
					return nil, false
				}
			}
			if addr[i] != '.' || depth > 0 {
				continue
			}
		}
		parts = append(parts, addr[start:i])
		start = i + 1
	}
	if depth != 0 {
		return nil, false
	}

	var names []string
	if len(parts)%2 != 0 {
		return nil, false
	}
	for i := 0; i < len(parts); i += 2 {
		if parts[i] != "module" {
			return nil, false
		}
		name := parts[i+1]
		if j := strings.IndexByte(name, '['); j >= 0 {
			name = name[:j]
		}
		if name == "" {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

// referencesInModule searches a config module (recursively) for the resource
// and returns its per-attribute reference lists.
func referencesInModule(m *tfModule, resType, resName string) map[string][]string {
	for _, r := range m.Resources {
		if r.Mode != "" && r.Mode != "managed" {
			continue
		}
		if r.Type != resType || r.Name != resName {
			continue
		}
		refs := make(map[string][]string)
		for attr, expr := range r.Expressions {
			if len(expr.References) > 0 {
				refs[attr] = expr.References
			}
		}
		return refs
	}
	for _, mc := range m.ModuleCalls {
		if refs := referencesInModule(&mc.Module, resType, resName); refs != nil {
			return refs
		}
	}
	return nil
}

// attributePresence reports which top-level attributes of a resource change
// state (either the planned "after" state, or "before" for a pure delete) are
// meaningfully set. afterUnknown is the parallel "after_unknown" object, where
// a top-level attribute maps to true when its value is computed at apply time
// (always nil when state is "before", since prior state is never unknown).
// Returns nil when state is absent or null (presence unknown).
func attributePresence(state, afterUnknown json.RawMessage) map[string]bool {
	fields, ok := stateFields(state)
	if !ok {
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

// changeBaseline returns the prior state a change is measured against. A
// replace destroys the old object and creates the new one from empty state, so
// the provider's Create reads d.HasChange as true for every attribute it sets,
// even one equal to the old value. The baseline for a replace is therefore
// empty, the same as for a create; any other change measures against before.
func changeBaseline(actions []string, before json.RawMessage) json.RawMessage {
	var creates, deletes bool
	for _, a := range actions {
		creates = creates || a == "create"
		deletes = deletes || a == "delete"
	}
	if creates && deletes {
		return nil
	}
	return before
}

// changedAttributes reports which top-level attributes differ between the
// prior "before" state and the planned "after" state. An attribute marked
// computed at apply time in after_unknown counts as changed, because terraform
// applies a diff for it either way. Values are compared structurally, so a
// re-ordered but identical object counts as unchanged. before is null on a
// create, so every attribute planned with a value counts as a change; an
// attribute planned as null counts as unchanged, matching the absent diff entry
// the provider sees. Returns nil when there is no planned state, meaning change
// is unknown.
func changedAttributes(before, after, afterUnknown json.RawMessage) map[string]bool {
	afterFields, ok := stateFields(after)
	if !ok {
		return nil
	}
	beforeFields, _ := stateFields(before) // absent or null prior state reads as empty

	changed := make(map[string]bool, len(afterFields))
	for attr, afterValue := range afterFields {
		if unknownAttrSet(afterUnknown, attr) {
			changed[attr] = true
			continue
		}
		changed[attr] = !sameJSONValue(beforeFields[attr], afterValue)
	}

	// An attribute the prior state carried that the planned state does not is a
	// removal, and the provider's d.HasChange reports true for it — that is how
	// a guard like d.HasChange("permissions_boundary") fires the delete-path
	// call. A plan that omits the key rather than setting it to null would
	// otherwise read as unchanged here, and the permission would be dropped.
	// Erring toward "changed" keeps the permission, which is the safe side.
	for attr := range beforeFields {
		if _, present := afterFields[attr]; !present {
			changed[attr] = true
		}
	}
	return changed
}

// stateFields decodes a resource change state object into its top-level
// fields. It reports false when the state is absent, null, or not an object.
func stateFields(state json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(state) == 0 || string(state) == "null" {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(state, &fields); err != nil {
		return nil, false
	}
	return fields, true
}

// sameJSONValue reports whether two raw JSON values are equal in structure.
// A missing value (empty raw message) is treated as JSON null.
func sameJSONValue(a, b json.RawMessage) bool {
	var av, bv any
	if err := json.Unmarshal(nonEmptyOrNull(a), &av); err != nil {
		return string(a) != string(b)
	}
	if err := json.Unmarshal(nonEmptyOrNull(b), &bv); err != nil {
		return string(a) != string(b)
	}
	return reflect.DeepEqual(av, bv)
}

// nonEmptyOrNull replaces an absent raw message with the JSON literal null,
// so it decodes to the same nil value a null attribute carries.
func nonEmptyOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

// unknownAttrSet reports whether a top-level attribute is marked fully
// computed-at-apply in a change's "after_unknown" object (i.e. the attribute
// maps to the JSON literal true).
func unknownAttrSet(afterUnknown json.RawMessage, attr string) bool {
	fields, ok := stateFields(afterUnknown)
	if !ok {
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
	fields, ok := stateFields(state)
	if !ok {
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
