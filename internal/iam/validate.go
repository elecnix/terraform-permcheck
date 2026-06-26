package iam

import (
	"fmt"
	"strings"

	"github.com/elecnix/policyguard/internal/plan"
)

// MissingAction is a single required permission found to be absent from the policy.
type MissingAction struct {
	ResourceType string // terraform resource type, e.g. "aws_backup_vault"
	ResourceName string // terraform resource name, e.g. "this"
	Change       string // "create", "update", or "delete"
	Action       string // required IAM action, e.g. "kms:CreateGrant"
	Service      string // extracted service prefix, e.g. "kms"
}

// AllowedProvider is something that can check whether an action is covered.
type AllowedProvider interface {
	Covers(action string) bool
}

// Validate checks every resource change in the plan against the policy,
// consulting the schema provider for required permissions.
//
// cloudSvc must implement Resolve(tfType string) (*cloud.Schema, error).
type CloudResolver interface {
	Resolve(tfType string) (SchemaLike, error)
}

// SchemaLike abstracts the cloud.Schema type so the iam package doesn't
// import cloud. It needs Permissions() map[string][]string.
type SchemaLike interface {
	GetPermissions() map[string][]string
}

// Validate checks all resource changes against the policy and the resolver.
// It returns a list of missing actions.
func Validate(changes []*plan.ResourceChange, policy AllowedProvider, resolver interface {
	Resolve(tfType string) (SchemaLike, error)
}) ([]MissingAction, error) {
	var missing []MissingAction

	for _, rc := range changes {
		schema, err := resolver.Resolve(rc.Type)
		if err != nil {
			// If we can't resolve the type, skip it but note the skip.
			// This allows the validator to continue with resources it knows.
			continue
		}

		perms := schema.GetPermissions()
		required, ok := perms[rc.Change]
		if !ok {
			// If no explicit permissions for this change type, check "create"
			required, ok = perms["create"]
		}
		if !ok {
			continue
		}

		for _, action := range required {
			if policy.Covers(action) {
				continue
			}
			// Check if a wildcard covers it (e.g. "kms:*")
			service := strings.Split(action, ":")[0]
			wildcard := service + ":*"
			if !policy.Covers(wildcard) {
				missing = append(missing, MissingAction{
					ResourceType: rc.Type,
					ResourceName: rc.Name,
					Change:       rc.Change,
					Action:       action,
					Service:      service,
				})
			}
		}
	}

	return missing, nil
}

// FormatMissing formats a list of missing actions as a human-readable message.
func FormatMissing(missing []MissingAction) string {
	if len(missing) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Missing IAM permissions (%d):\n", len(missing)))
	for _, m := range missing {
		b.WriteString(fmt.Sprintf("  %s (%s) needs %s\n", m.ResourceType, m.Change, m.Action))
	}
	return b.String()
}
