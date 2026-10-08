// Package cloud defines the interface for cloud schema registries and
// provides implementations for AWS, GCP, and Azure.
package cloud

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

// Resolve tries each provider in order, returning the first successful result.
func (c *ChainProvider) Resolve(tfType string) (*Schema, error) {
	var lastErr error
	for _, p := range c.providers {
		schema, err := p.Resolve(tfType)
		if err == nil {
			return schema, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
