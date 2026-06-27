// Package cloud defines the interface for cloud schema registries and
// provides implementations for AWS, GCP, and Azure.
package cloud

// Schema maps a cloud resource type to the IAM permissions required
// to create, read, update, delete, and list it.
type Schema struct {
	TypeName    string
	Permissions map[string][]string          // key: "create", "read", "update", "delete", "list" → action strings
	Conditional map[string]map[string]string // op → action → condition attribute name (empty if unconditional)
}

// GetPermissions returns the permission map (implements iam.SchemaLike).
func (s *Schema) GetPermissions() map[string][]string {
	return s.Permissions
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
