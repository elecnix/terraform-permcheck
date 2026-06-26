// Package cloud defines the interface for cloud schema registries and
// provides implementations for AWS, GCP, and Azure.
package cloud

// Schema maps a cloud resource type to the IAM permissions required
// to create, read, update, delete, and list it.
type Schema struct {
	TypeName    string
	Permissions map[string][]string // key: "create", "read", "update", "delete", "list"
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
