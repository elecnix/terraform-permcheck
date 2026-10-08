// Package cloud defines the interface for cloud schema registries and
// provides implementations for AWS, GCP, and Azure.
package cloud

import (
	"sort"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// Schema maps a cloud resource type to the IAM permissions required
// to create, read, update, delete, and list it.
type Schema struct {
	TypeName    string
	Permissions map[string][]string          // key: "create", "read", "update", "delete", "list" → action strings
	Conditional map[string]map[string]string // op → action → condition attribute name (empty if unconditional)
	// ChangeGated maps op → action → the attribute whose change gates the
	// action (a d.HasChange guard in the provider). It is separate from
	// Conditional because an action gated on presence is evaluated from the
	// planned state, while an action gated on change is evaluated from the
	// difference between prior and planned state.
	ChangeGated map[string]map[string]string

	// ValueConditional marks the conditional actions whose gating attribute is
	// compared by value, not by presence (op → action → true). The attribute
	// carries a default, so the call only runs when the author configured it.
	ValueConditional map[string]map[string]bool

	// BestEffort marks the actions whose failure the provider ignores
	// (op → action → true): it discards the call's error, or makes the call
	// only to clean up after an operation that already failed. A policy that
	// denies such an action does not make the apply fail.
	BestEffort map[string]map[string]bool

	// Gates lists every gated path of the actions the provider reaches on
	// more than one (op → action → gates). Such an action is needed when any
	// of its gates holds, and the maps above hold no gate for it.
	Gates map[string]map[string][]iam.Gate

	// Incomplete names the operations whose permissions the provider could
	// not fully determine, such as a create in which the provider-source
	// parser found no call that creates anything. ChainProvider merges in a
	// later provider's permissions for these operations.
	Incomplete map[string]bool
}

// GetPermissions returns the permission map (implements iam.SchemaLike).
func (s *Schema) GetPermissions() map[string][]string {
	return s.Permissions
}

// GetConditional returns the conditional-permission metadata, mapping
// op → action → gating attribute name (implements iam.SchemaLike).
func (s *Schema) GetConditional() map[string]map[string]string {
	return s.Conditional
}

// GetChangeGated returns the change-gated permission metadata, mapping
// op → action → the attribute whose change gates the action
// (implements iam.SchemaLike).
func (s *Schema) GetChangeGated() map[string]map[string]string {
	return s.ChangeGated
}

// GetValueConditional returns the actions whose gating attribute is compared by
// value (implements iam.SchemaLike).
func (s *Schema) GetValueConditional() map[string]map[string]bool {
	return s.ValueConditional
}

// GetGates returns the gates of the actions reached on several paths,
// mapping op → action → gates.
func (s *Schema) GetGates() map[string]map[string][]iam.Gate {
	return s.Gates
}

// GetBestEffort returns the actions whose failure the provider ignores
// (implements iam.SchemaLike).
func (s *Schema) GetBestEffort() map[string]map[string]bool {
	return s.BestEffort
}

// Provider resolves cloud resource types to their required IAM permissions.
type Provider interface {
	// Name returns the provider name (e.g. "aws").
	Name() string

	// Resolve maps a terraform resource type (e.g. "aws_backup_vault") to
	// the cloud-native resource type and fetches its required permissions.
	Resolve(tfType string) (*Schema, error)
}

// ChainProvider tries multiple providers in order, returning the first
// successful resolution. This allows combining a fallback provider (CFN
// schema registry) with a more precise provider (provider source parser).
type ChainProvider struct {
	providers []Provider
}

// NewChainProvider creates a ChainProvider that tries each provider in order.
func NewChainProvider(providers ...Provider) *ChainProvider {
	return &ChainProvider{providers: providers}
}

// Name returns the name of the first provider.
func (c *ChainProvider) Name() string {
	if len(c.providers) > 0 {
		return c.providers[0].Name()
	}
	return "chain"
}

// Resolve tries each provider in order and returns the first successful
// result. When that result marks operations incomplete, each later provider
// that knows the type adds its actions for those operations, so a parse that
// missed a call cannot report it as not needed.
func (c *ChainProvider) Resolve(tfType string) (*Schema, error) {
	var lastErr error
	for i, p := range c.providers {
		schema, err := p.Resolve(tfType)
		if err == nil {
			return c.completeFrom(schema, tfType, c.providers[i+1:]), nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// completeFrom fills the incomplete operations of schema from the first later
// provider that knows the type and has actions for them. It returns schema
// itself when nothing needs or can take filling, and a merged copy otherwise.
//
// The copy is made once, on the first operation any provider fills: the first
// provider may have cached the schema it returned, so merging has to write to
// a copy, and one copy serves every later provider.
func (c *ChainProvider) completeFrom(schema *Schema, tfType string, rest []Provider) *Schema {
	merged := schema
	copied := false
	for _, p := range rest {
		ops := incompleteOps(merged)
		if len(ops) == 0 {
			break
		}
		fallback, err := p.Resolve(tfType)
		if err != nil {
			continue
		}
		for _, op := range ops {
			if len(fallback.Permissions[op]) == 0 {
				continue
			}
			if !copied {
				merged = schema.clone()
				copied = true
			}
			merged.mergeOperation(op, fallback)
		}
	}
	return merged
}

// incompleteOps lists the operations a schema still needs filling for, as a
// sorted snapshot: mergeOperation clears entries from the schema's own map, so
// walking that map directly would be walking a map under mutation.
func incompleteOps(s *Schema) []string {
	if len(s.Incomplete) == 0 {
		return nil
	}
	ops := make([]string, 0, len(s.Incomplete))
	for op := range s.Incomplete {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	return ops
}

// clone copies a schema deeply enough that merging into the copy leaves the
// original, which a provider may cache, unchanged.
func (s *Schema) clone() *Schema {
	out := *s
	out.Permissions = make(map[string][]string, len(s.Permissions))
	for op, actions := range s.Permissions {
		out.Permissions[op] = append([]string(nil), actions...)
	}
	out.Conditional = cloneNested(s.Conditional)
	out.ChangeGated = cloneNested(s.ChangeGated)
	out.ValueConditional = cloneNested(s.ValueConditional)
	out.BestEffort = cloneNested(s.BestEffort)
	out.Gates = cloneNested(s.Gates)
	out.Incomplete = make(map[string]bool, len(s.Incomplete))
	for op, v := range s.Incomplete {
		out.Incomplete[op] = v
	}
	return &out
}

// mergeOperation adds the fallback's actions for op that s lacks, with the
// gates the fallback puts on them, and marks op complete. Actions s already
// has keep their own gates.
func (s *Schema) mergeOperation(op string, fallback *Schema) {
	have := make(map[string]bool, len(s.Permissions[op]))
	for _, a := range s.Permissions[op] {
		have[a] = true
	}
	for _, a := range fallback.Permissions[op] {
		if have[a] {
			continue
		}
		have[a] = true
		s.Permissions[op] = append(s.Permissions[op], a)
		copyGate(&s.Conditional, fallback.Conditional, op, a)
		copyGate(&s.ChangeGated, fallback.ChangeGated, op, a)
		copyGate(&s.ValueConditional, fallback.ValueConditional, op, a)
		copyGate(&s.BestEffort, fallback.BestEffort, op, a)
		copyGate(&s.Gates, fallback.Gates, op, a)
	}
	delete(s.Incomplete, op)
}

// cloneNested copies a two-level op → action → value map.
func cloneNested[V any](m map[string]map[string]V) map[string]map[string]V {
	if m == nil {
		return nil
	}
	out := make(map[string]map[string]V, len(m))
	for op, inner := range m {
		cp := make(map[string]V, len(inner))
		for k, v := range inner {
			cp[k] = v
		}
		out[op] = cp
	}
	return out
}

// copyGate copies the gate src holds for op and action, if any, into dst.
func copyGate[V any](dst *map[string]map[string]V, src map[string]map[string]V, op, action string) {
	v, ok := src[op][action]
	if !ok {
		return
	}
	if *dst == nil {
		*dst = make(map[string]map[string]V)
	}
	if (*dst)[op] == nil {
		(*dst)[op] = make(map[string]V)
	}
	(*dst)[op][action] = v
}
