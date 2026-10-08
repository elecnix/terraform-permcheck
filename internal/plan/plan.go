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
	// ModuleAddress is the module the resource lives in, as terraform
	// writes it (module.prod, module.a[0].module.b). It is empty for a
	// resource in the root module.
	ModuleAddress string
	Type          string // terraform resource type, e.g. "aws_backup_vault"
	Name          string // terraform resource name, e.g. "this"
	// Address is the full instance address as terraform prints it, e.g.
	// `module.a["x"].aws_iam_role.r[0]`. It is empty when the source has
	// none (static HCL mode).
	Address string
	// Change is "create", "update", "delete", or NoOp. A replace becomes two
	// changes, a delete that reads the prior state and a create that reads
	// the planned state, in the order terraform runs them.
	Change string

	// Attributes records which top-level attributes are meaningfully set,
	// following terraform's GetOk semantics: a key maps to true only when its
	// value is non-null and non-zero. For a create or update it reflects the
	// planned "after" state; for a delete it reflects the prior "before"
	// state, since that's what the provider's d.GetOk reads at destroy time.
	// An attribute computed at apply time counts as set when the author
	// configured it, since the provider reads a value for it then. It is nil
	// when the plan carries neither state, meaning presence is unknown. Used
	// to gate conditional permissions on attribute presence.
	Attributes map[string]bool

	// ChangedAttributes records which top-level attributes differ between the
	// prior "before" state and the planned "after" state, following terraform's
	// d.HasChange semantics. An attribute computed at apply time counts as
	// changed, since terraform still applies a diff for it. A create or a
	// replace measures against empty prior state, because the provider's Create
	// starts from nothing. It is nil for a delete, meaning change is unknown.
	// Used to gate permissions on whether an attribute changed.
	ChangedAttributes map[string]bool

	// AttributeValues records the concrete string values of top-level
	// attributes — from "after" for a create or update, from "before" for a
	// delete. Only known, non-empty string values are included (values
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

	// paths keeps the decoded states for gates on nested attribute paths.
	// Nil for a change built without plan state.
	paths *pathState
}

// NoOp is the Change of a resource the plan leaves as it is. Parse keeps it so
// that a change referencing it can read its values, but it needs no
// permission.
const NoOp = "no-op"

// Checked reports whether the change needs permissions checked: every change
// but a no-op.
func (rc *ResourceChange) Checked() bool {
	return rc.Change != NoOp
}

// InstanceName returns the resource name with the count or for_each key the
// address carries: q, q[0] or q["k"]. It reads the key from the address, so
// the key keeps terraform's quoting. A change without an address, or with
// one of an unexpected form, yields Name.
func (rc *ResourceChange) InstanceName() string {
	rest := rc.Address
	if rc.ModuleAddress != "" {
		rest = strings.TrimPrefix(rest, rc.ModuleAddress+".")
	}
	local := rc.Type + "." + rc.Name
	if !strings.HasPrefix(rest, local) {
		return rc.Name
	}
	if key := rest[len(local):]; strings.HasPrefix(key, "[") {
		return rc.Name + key
	}
	return rc.Name
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

// UnmarshalJSON reads an attribute expression or a nested block. Terraform
// writes a nested block (ttl { ... }) as a list of objects that each map
// attribute names to expressions. A block keeps the references of every
// expression inside it. Any other shape reads as an expression with no
// references rather than failing the whole plan.
func (e *tfExpression) UnmarshalJSON(raw []byte) error {
	var blocks []map[string]tfExpression
	if json.Unmarshal(raw, &blocks) == nil {
		for _, block := range blocks {
			for _, expr := range block {
				e.References = append(e.References, expr.References...)
			}
		}
		return nil
	}
	var expr struct {
		References []string `json:"references"`
	}
	if json.Unmarshal(raw, &expr) == nil {
		e.References = expr.References
	}
	return nil
}

// tfModuleCall mirrors a module call in the configuration section, whose
// nested module_calls/resources hold the module's own resources.
type tfModuleCall struct {
	Module tfModule `json:"module"`
}

type tfResourceChange struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Change        struct {
		Actions      []string        `json:"actions"`
		Before       json.RawMessage `json:"before"`
		After        json.RawMessage `json:"after"`
		AfterUnknown json.RawMessage `json:"after_unknown"`
	} `json:"change"`
}

// changeActions returns the changes to check for a resource change's
// terraform actions, in the order terraform runs them. A replace
// (["delete","create"] or ["create","delete"]) yields both. A forget removes
// the object from state without calling the provider, so it yields nothing.
// An empty action list reads as a no-op.
func changeActions(actions []string) []string {
	if len(actions) == 0 {
		return []string{NoOp}
	}
	var out []string
	for _, a := range actions {
		if a != "forget" {
			out = append(out, a)
		}
	}
	return out
}

// Parse extracts every managed resource change from raw terraform plan JSON,
// keeping only resources whose type starts with prefix (e.g. "aws_"). If
// prefix is empty, all resource types are kept. Data sources are skipped: a
// read calls no mutating API. A no-op is kept so that references can resolve
// to it; Checked reports false for it.
func Parse(raw []byte, prefix string) ([]*ResourceChange, error) {
	var plan tfPlanJSON
	if err := json.Unmarshal(raw, &plan); err != nil {
		return nil, err
	}

	configs := indexConfiguration(plan.Configuration)
	var changes []*ResourceChange
	for _, rc := range plan.ResourceChanges {
		if prefix != "" && !strings.HasPrefix(rc.Type, prefix) {
			continue
		}
		if rc.Mode != "" && rc.Mode != "managed" {
			continue
		}
		actions := changeActions(rc.Change.Actions)
		if len(actions) == 0 {
			continue
		}
		e := decodeEntry(rc, configs.resource(rc.ModuleAddress, rc.Type, rc.Name))
		for _, action := range actions {
			changes = append(changes, e.change(action))
		}
	}
	return changes, nil
}

// planEntry is one resource_changes entry with its states and its
// configuration decoded once, however many changes it yields.
type planEntry struct {
	rc tfResourceChange
	// before, after and unknown are the top-level fields of the prior
	// state, the planned state and after_unknown. hasBefore and hasAfter
	// report whether the state is present and an object.
	before, after, unknown map[string]json.RawMessage
	hasBefore, hasAfter    bool
	configured             map[string]bool
	references             map[string][]string
	// beforeValue, afterValue and unknownValue are the same three states
	// decoded whole, for gates on nested attribute paths.
	beforeValue, afterValue, unknownValue any
}

func decodeEntry(rc tfResourceChange, cfg *tfConfigResource) *planEntry {
	e := &planEntry{rc: rc}
	e.before, e.hasBefore = stateFields(rc.Change.Before)
	e.after, e.hasAfter = stateFields(rc.Change.After)
	e.unknown, _ = stateFields(rc.Change.AfterUnknown)
	e.configured = configuredAttributes(cfg)
	e.references = resourceReferences(cfg)
	e.beforeValue = decodeState(rc.Change.Before)
	e.afterValue = decodeState(rc.Change.After)
	e.unknownValue = decodeState(rc.Change.AfterUnknown)
	return e
}

// change builds the change for one action of the entry. A delete reads the
// prior "before" state, since that is what the provider's d.GetOk reads at
// destroy time; its change set is unknown. Any other action reads the
// planned "after" state. A create measures change against empty prior state,
// since the provider's Create starts from nothing, even within a replace.
func (e *planEntry) change(action string) *ResourceChange {
	state, hasState, unknown := e.after, e.hasAfter, e.unknown
	paths := &pathState{state: e.afterValue, unknown: e.unknownValue, before: e.beforeValue, after: e.afterValue, afterUnknown: e.unknownValue}
	var changed map[string]bool
	switch action {
	case "delete":
		state, hasState, unknown = e.before, e.hasBefore, nil // before-values are never "unknown"
		// The change of a delete is unknown, even within a replace.
		paths = &pathState{state: e.beforeValue}
	case "create":
		changed = changedAttributes(nil, e.after, e.hasAfter, e.unknown)
		paths.before = nil
	default:
		changed = changedAttributes(e.before, e.after, e.hasAfter, e.unknown)
	}
	return &ResourceChange{
		ModuleAddress:     e.rc.ModuleAddress,
		Type:              e.rc.Type,
		Name:              e.rc.Name,
		Address:           e.rc.Address,
		Change:            action,
		Attributes:        attributePresence(state, hasState, unknown, e.configured),
		ChangedAttributes: changed,
		AttributeValues:   attributeStringValues(state, hasState),
		References:        e.references,
		Configured:        e.configured,
		paths:             paths,
	}
}

// resourceReferences returns, per attribute, the addresses a resource's
// configuration references, relative to the module the resource lives in.
// Returns nil when the resource has no configuration entry.
func resourceReferences(r *tfConfigResource) map[string][]string {
	if r == nil {
		return nil
	}
	refs := make(map[string][]string)
	for attr, expr := range r.Expressions {
		if len(expr.References) > 0 {
			refs[attr] = expr.References
		}
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// configuredAttributes returns the set of top-level attributes a resource's
// configuration writes. Returns nil when the resource has no configuration
// entry, which reads as "unknown", not "none".
func configuredAttributes(r *tfConfigResource) map[string]bool {
	if r == nil {
		return nil
	}
	// A resource in the configuration with no expressions is configured
	// with nothing, which is not the same as absent from it.
	configured := make(map[string]bool, len(r.Expressions))
	for attr := range r.Expressions {
		configured[attr] = true
	}
	return configured
}

// configKey identifies a managed resource in the configuration section: the
// module call path without instance keys ("a.b" for module.a[0].module.b),
// the type and the name.
type configKey struct {
	module, typ, name string
}

// configIndex maps each managed resource in the configuration section to its
// entry, so a lookup does not scan the module's resources.
type configIndex map[configKey]*tfConfigResource

// indexConfiguration indexes every managed resource of the configuration
// section, in the root module and in every module call. It returns nil when
// the plan carries no configuration section.
func indexConfiguration(cfg *tfConfiguration) configIndex {
	if cfg == nil || cfg.RootModule == nil {
		return nil
	}
	idx := make(configIndex)
	var walk func(m *tfModule, path string)
	walk = func(m *tfModule, path string) {
		for i := range m.Resources {
			r := &m.Resources[i]
			if r.Mode != "" && r.Mode != "managed" {
				continue
			}
			idx[configKey{path, r.Type, r.Name}] = r
		}
		for name, mc := range m.ModuleCalls {
			child := mc.Module
			if path != "" {
				name = path + "." + name
			}
			walk(&child, name)
		}
	}
	walk(cfg.RootModule, "")
	return idx
}

// resource returns the configuration entry of a managed resource in the
// module at moduleAddr (for example `module.a[0].module.b["k"]`). Instance
// keys are dropped: the configuration describes a module call, not its
// instances. It returns nil when the plan carries no configuration section,
// the resource is not in it, or the address is not a module address.
func (idx configIndex) resource(moduleAddr, resType, resName string) *tfConfigResource {
	if idx == nil {
		return nil
	}
	names, ok := moduleCallNames(moduleAddr)
	if !ok {
		return nil
	}
	return idx[configKey{strings.Join(names, "."), resType, resName}]
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

// attributePresence reports which top-level attributes of a resource change
// state (either the planned "after" state, or "before" for a delete) are
// meaningfully set. afterUnknown is the parallel "after_unknown" object, which
// marks the values computed at apply time (always nil when state is "before",
// since prior state is never unknown). configured is the set of attributes
// the configuration writes, or nil when the plan carries no configuration.
// Returns nil when state is absent or null (presence unknown).
func attributePresence(fields map[string]json.RawMessage, ok bool, unknown map[string]json.RawMessage, configured map[string]bool) map[string]bool {
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

	// An attribute computed at apply time (parent_id = aws_x.y.id) shows as
	// null in "after" and as true in "after_unknown", at the top level or
	// inside a nested block. The provider reads a value for it at apply time,
	// so the gate must be satisfied. An attribute the author did not configure
	// is unknown only because the provider computes it, and the provider's
	// Create reads no value for it, so it stays unset when the configuration
	// says so. tags_all never counts: it is provider-computed and reads as
	// unknown even on an untagged resource with no default_tags.
	for attr, u := range unknown {
		if attr == "tags_all" || !anyUnknown(u) {
			continue
		}
		if configured == nil || configured[attr] {
			present[attr] = true
		}
	}

	return present
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
func changedAttributes(beforeFields, afterFields map[string]json.RawMessage, hasAfter bool, unknownFields map[string]json.RawMessage) map[string]bool {
	if !hasAfter {
		return nil
	}

	changed := make(map[string]bool, len(afterFields))
	for attr, afterValue := range afterFields {
		if anyUnknown(unknownFields[attr]) {
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

// anyUnknown reports whether an "after_unknown" value marks anything as
// computed at apply time: it is true, or a list or object holding a true
// value at any depth.
func anyUnknown(raw json.RawMessage) bool {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return false
	}
	return holdsTrue(v)
}

// holdsTrue reports whether a decoded JSON value is true or contains true.
func holdsTrue(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case []any:
		for _, e := range val {
			if holdsTrue(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range val {
			if holdsTrue(e) {
				return true
			}
		}
	}
	return false
}

// attributeStringValues extracts the concrete string values of top-level
// attributes from a resource change state (either the planned "after" state,
// or "before" for a pure delete). Only non-empty JSON strings are captured;
// null, empty, and non-string values (numbers, bools, objects, arrays, and
// values computed at apply time) are omitted. Returns nil when state is
// absent or null.
func attributeStringValues(fields map[string]json.RawMessage, ok bool) map[string]string {
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
