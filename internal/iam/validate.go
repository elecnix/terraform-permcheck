package iam

import (
	"fmt"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// PermissionClass categorizes an IAM permission as management-plane or data-plane.
type PermissionClass int

const (
	ClassUnknown     PermissionClass = iota
	ClassManagement                  // provisioning/configuration actions (needed by deploy role)
	ClassDataPlane                   // data access actions (belongs to application roles)
	ClassServiceRole                 // actions only AWS service roles need
	ClassOptional                    // actions for optional sub-resources (access policy, notifications, etc.)
)

// classifyPermission categorizes a single IAM action string.
func classifyPermission(action string) PermissionClass {
	service := strings.Split(action, ":")[0]
	verb := ""
	if idx := strings.Index(action, ":"); idx >= 0 {
		verb = action[idx+1:]
	}

	// Full-action patterns that are clearly data-plane
	dataPlaneActions := map[string]bool{
		// DynamoDB data-plane
		"dynamodb:PutItem": true, "dynamodb:GetItem": true, "dynamodb:UpdateItem": true,
		"dynamodb:DeleteItem": true, "dynamodb:Query": true, "dynamodb:Scan": true,
		"dynamodb:BatchWriteItem": true, "dynamodb:BatchGetItem": true,
		// S3 object-level operations
		"s3:GetObject": true, "s3:GetObjectMetadata": true,
		"s3:PutObject": true, "s3:PutObjectAcl": true,
		"s3:DeleteObject": true, "s3:AbortMultipartUpload": true,
		// KMS data-plane (encrypt/decrypt at object level)
		"kms:Encrypt": true, "kms:Decrypt": true,
		"kms:GenerateDataKey": true, "kms:GenerateDataKeyWithoutPlaintext": true,
		"kms:ReEncryptFrom": true, "kms:ReEncryptTo": true,
		// Kinesis data-plane
		"kinesis:PutRecords": true, "kinesis:GetRecords": true,
		"kinesis:DescribeStream": true,
		// SQS data-plane
		"sqs:SendMessage": true, "sqs:ReceiveMessage": true,
		"sqs:DeleteMessage": true, "sqs:ChangeMessageVisibility": true,
	}

	if dataPlaneActions[action] {
		return ClassDataPlane
	}

	// Service-level prefix checks for data-plane services
	dataPlaneServices := map[string]bool{
		"s3tables":       true, // S3 Tables is a data-plane service
		"backup-storage": true, // backup-storage is the AWS Backup data-plane
		"logs":           true, // CloudWatch Logs data-plane (CreateLogStream, PutLogEvents)
	}

	if dataPlaneServices[service] {
		// exceptions: logs management-plane operations
		if strings.HasPrefix(verb, "CreateLogGroup") || strings.HasPrefix(verb, "DeleteLogGroup") ||
			strings.HasPrefix(verb, "DescribeLogGroups") || strings.HasPrefix(verb, "PutRetentionPolicy") {
			return ClassManagement
		}
		return ClassDataPlane
	}

	// Optional sub-resource permissions — only needed when the terraform config
	// sets the corresponding attribute block (access_policy, notifications, lock_configuration, etc.)
	optionalActions := map[string]bool{
		"backup:PutBackupVaultAccessPolicy":         true,
		"backup:PutBackupVaultNotifications":        true,
		"backup:PutBackupVaultLockConfiguration":    true,
		"backup:DeleteBackupVaultAccessPolicy":      true,
		"backup:DeleteBackupVaultNotifications":     true,
		"backup:DeleteBackupVaultLockConfiguration": true,
		"backup:GetBackupVaultAccessPolicy":         true,
		"backup:GetBackupVaultNotifications":        true,
	}

	if optionalActions[action] {
		return ClassOptional
	}

	// S3 sub-resource configurators — only needed when the terraform config sets
	// the corresponding attribute (website, cors, replication, logging, etc.)
	s3OptionalPrefixes := []string{
		"s3:PutBucketWebsite", "s3:PutBucketCORS", "s3:PutBucketReplication",
		"s3:PutBucketLogging", "s3:PutAccelerateConfiguration",
		"s3:PutAnalyticsConfiguration", "s3:PutInventoryConfiguration",
		"s3:PutMetricsConfiguration", "s3:PutBucketObjectLockConfiguration",
		"s3:PutIntelligentTieringConfiguration", "s3:PutBucketAbac",
		"s3:PutObjectLockConfiguration", "s3:PutReplicationConfiguration",
		"s3:GetBucketMetadataTableConfiguration", "s3:CreateBucketMetadataTableConfiguration",
		"s3:GetBucketAccelerateConfiguration", "s3:GetBucketAnalyticsConfiguration",
		"s3:GetBucketCORS", "s3:GetBucketInventoryConfiguration",
		"s3:GetBucketLogging", "s3:GetBucketMetricsConfiguration",
		"s3:GetBucketNotification", "s3:GetBucketObjectLockConfiguration",
		"s3:GetBucketReplication", "s3:GetBucketWebsite",
		"s3:GetObjectLockConfiguration", "s3:GetBucketPolicy",
		"s3:GetBucketTagging", "s3:GetBucketVersioning",
	}
	for _, p := range s3OptionalPrefixes {
		if strings.HasPrefix(action, p) {
			return ClassOptional
		}
	}

	// DynamoDB optional features (import/export, Kinesis streaming, contributor insights)
	dynamoDBOptionalPrefixes := []string{
		"dynamodb:ImportTable", "dynamodb:DescribeImport",
		"dynamodb:EnableKinesisStreamingDestination", "dynamodb:DisableKinesisStreamingDestination",
		"dynamodb:UpdateContributorInsights", "dynamodb:DescribeContributorInsights",
		"dynamodb:GetResourcePolicy", "dynamodb:PutResourcePolicy",
		"dynamodb:CreateTableReplica", "dynamodb:AssociateTableReplica",
	}
	for _, p := range dynamoDBOptionalPrefixes {
		if strings.HasPrefix(action, p) {
			return ClassOptional
		}
	}

	// IAM policy sub-types that the deploy role doesn't manage
	iamOptionalActions := map[string]bool{
		"iam:GetUserPolicy": true, "iam:GetGroupPolicy": true,
		"iam:PutUserPolicy": true, "iam:PutGroupPolicy": true,
	}
	if iamOptionalActions[action] {
		return ClassOptional
	}

	// Secrets Manager optional
	if action == "secretsmanager:GetRandomPassword" || action == "secretsmanager:ReplicateSecretToRegions" {
		return ClassOptional
	}

	return ClassManagement
}

// MissingAction is a single required permission found to be absent from the policy.
type MissingAction struct {
	ResourceType string // terraform resource type, e.g. "aws_backup_vault"
	ResourceName string // terraform resource name, e.g. "this"
	Change       string // "create", "update", or "delete"
	Action       string // required IAM action, e.g. "kms:CreateGrant"
	Service      string // extracted service prefix, e.g. "kms"
	Filtered     bool   // true if this was filtered out (data-plane / optional)
	Class        string // classification tag: "[required]", "[optional]", "[data-plane]", "[service-role]", or ""
}

// AllowedProvider is something that can check whether an action is covered.
type AllowedProvider interface {
	Covers(action string) bool
}

// SchemaLike abstracts the cloud.Schema type so the iam package doesn't
// import cloud.
type SchemaLike interface {
	GetPermissions() map[string][]string
	// GetConditional maps op → action → gating attribute name. An action with a
	// non-empty gating attribute is only required when that attribute is set in
	// the planned resource.
	GetConditional() map[string]map[string]string
}

// FilterConfig controls which permission classes are filtered out of validation.
type FilterConfig struct {
	// ExcludeDataPlane excludes data-plane permissions (dynamodb:PutItem, s3:GetObject, etc.)
	ExcludeDataPlane bool
	// ExcludeOptional excludes optional sub-resource permissions (vault access policy, S3 website, etc.)
	ExcludeOptional bool
	// ExcludeServiceRole excludes permissions only AWS service roles need (backup-storage, etc.)
	ExcludeServiceRole bool
}

// DefaultFilter returns a FilterConfig that excludes data-plane and optional
// permissions but keeps management-plane and service-role permissions.
func DefaultFilter() FilterConfig {
	return FilterConfig{
		ExcludeDataPlane:   true,
		ExcludeOptional:    true,
		ExcludeServiceRole: false, // keep these — they might be needed
	}
}

// Validate checks all resource changes against the policy and the resolver.
// The filter controls which permission classes are excluded from validation.
func Validate(changes []*plan.ResourceChange, policy AllowedProvider, resolver interface {
	Resolve(tfType string) (SchemaLike, error)
}, filter FilterConfig) ([]MissingAction, error) {
	var missing []MissingAction

	for _, rc := range changes {
		schema, err := resolver.Resolve(rc.Type)
		if err != nil {
			continue
		}

		perms := schema.GetPermissions()
		op := rc.Change
		required, ok := perms[op]
		if !ok {
			op = "create"
			required, ok = perms[op]
		}
		if !ok {
			continue
		}
		conditional := schema.GetConditional()[op]

		for _, action := range required {
			// Conditional (attribute-gated) permissions are only required when
			// the gating attribute is meaningfully set in the planned resource.
			// When the plan carries no attribute info (rc.Attributes == nil),
			// presence is unknown and the permission is kept.
			if attr := conditional[action]; attr != "" && rc.Attributes != nil && !rc.Attributes[attr] {
				continue
			}

			if policy.Covers(action) {
				continue
			}
			// Check wildcard coverage
			service := strings.Split(action, ":")[0]
			wildcard := service + ":*"
			if policy.Covers(wildcard) {
				continue
			}

			// Classify and optionally filter
			class := classifyPermission(action)
			if filter.ExcludeDataPlane && class == ClassDataPlane {
				continue
			}
			if filter.ExcludeOptional && class == ClassOptional {
				continue
			}
			if filter.ExcludeServiceRole && class == ClassServiceRole {
				continue
			}

			missing = append(missing, MissingAction{
				ResourceType: rc.Type,
				ResourceName: rc.Name,
				Change:       rc.Change,
				Action:       action,
				Service:      service,
				Class:        classTag(class),
			})
		}
	}

	// Post-process: remove permissions absorbed by S3 sub-resource configs
	missing = filterS3Subresources(missing, changes)

	return missing, nil
}

// missingGroupKey is a grouping key for deduplicating missing actions.
type missingGroupKey struct {
	action string
	class  string
}

// FormatMissing formats a list of missing actions as a human-readable message.
// Permissions are grouped by (Action, Class) so duplicates across resources are
// collapsed into a single entry, followed by the list of affected resources.
func FormatMissing(missing []MissingAction) string {
	if len(missing) == 0 {
		return ""
	}

	// Group by (Action, Class)
	groups := make(map[missingGroupKey][]MissingAction)
	order := make([]missingGroupKey, 0, len(missing))
	seen := make(map[missingGroupKey]bool)
	for _, m := range missing {
		k := missingGroupKey{action: m.Action, class: m.Class}
		groups[k] = append(groups[k], m)
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Missing IAM permissions (%d):\n", len(order)))
	for _, k := range order {
		items := groups[k]
		// Action line with optional class tag
		if k.class != "" {
			b.WriteString(fmt.Sprintf("  %s %s\n", k.action, k.class))
		} else {
			b.WriteString(fmt.Sprintf("  %s\n", k.action))
		}
		// Affected resources
		for _, m := range items {
			b.WriteString(fmt.Sprintf("    → %s.%s (%s)\n", m.ResourceType, m.ResourceName, m.Change))
		}
	}
	return b.String()
}

// DistinctCount returns the number of distinct (Action, Class) pairs in the list.
func DistinctCount(missing []MissingAction) int {
	seen := make(map[missingGroupKey]bool)
	for _, m := range missing {
		seen[missingGroupKey{action: m.Action, class: m.Class}] = true
	}
	return len(seen)
}

// classTag returns a human-readable classification tag for a PermissionClass.
func classTag(c PermissionClass) string {
	switch c {
	case ClassOptional:
		return "[optional]"
	case ClassDataPlane:
		return "[data-plane]"
	case ClassServiceRole:
		return "[service-role]"
	case ClassManagement:
		return "[required]"
	default:
		return "[unknown]"
	}
}
