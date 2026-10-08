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

// s3OptionalPrefixes lists the S3 bucket features that aws_s3_bucket only
// configures when the matching attribute is set (website, cors, replication,
// logging, tags, and so on). Each row is a prefix of an action name.
//
// Two name spaces reach classifyPermission, and they spell some actions
// differently. The CloudFormation schema for AWS::S3::Bucket resolves
// aws_s3_bucket when the provider checkout is unavailable. The provider-source
// parser resolves the aws_s3_bucket_* sub-resources from their SDK calls. Where
// the two disagree, both spellings are listed. Tests check every row against
// golden copies of both under testdata/.
var s3OptionalPrefixes = []string{
	// Website, CORS, logging
	"s3:PutBucketWebsite", "s3:GetBucketWebsite", "s3:DeleteBucketWebsite",
	"s3:PutBucketCORS", "s3:GetBucketCORS", "s3:DeleteBucketCors",
	"s3:PutBucketLogging", "s3:GetBucketLogging",
	// Replication
	"s3:PutBucketReplication", "s3:DeleteBucketReplication",
	"s3:PutReplicationConfiguration", "s3:GetReplicationConfiguration",
	// Transfer acceleration
	"s3:PutAccelerateConfiguration", "s3:GetAccelerateConfiguration",
	// Analytics, inventory, metrics, intelligent tiering
	"s3:PutAnalyticsConfiguration", "s3:GetAnalyticsConfiguration",
	"s3:DeleteBucketAnalyticsConfiguration",
	"s3:PutInventoryConfiguration", "s3:GetInventoryConfiguration",
	"s3:PutMetricsConfiguration", "s3:GetMetricsConfiguration",
	"s3:DeleteBucketMetricsConfiguration",
	"s3:PutIntelligentTieringConfiguration", "s3:GetIntelligentTieringConfiguration",
	// Object lock
	"s3:PutBucketObjectLockConfiguration", "s3:GetBucketObjectLockConfiguration",
	"s3:PutObjectLockConfiguration",
	// Server-side encryption
	"s3:PutEncryptionConfiguration", "s3:GetEncryptionConfiguration",
	"s3:DeleteBucketEncryption",
	// Lifecycle
	"s3:PutLifecycleConfiguration", "s3:GetLifecycleConfiguration", "s3:DeleteBucketLifecycle",
	// Notifications, versioning, ownership controls, public access block
	"s3:PutBucketNotification", "s3:GetBucketNotification",
	"s3:PutBucketVersioning", "s3:GetBucketVersioning",
	"s3:PutBucketOwnershipControls", "s3:GetBucketOwnershipControls",
	"s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock",
	// Tags
	"s3:PutBucketTagging", "s3:GetBucketTagging",
	"s3:TagResource", "s3:UntagResource", "s3:ListTagsForResource",
	// Bucket policy and requester pays
	"s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:DeleteBucketPolicy",
	"s3:PutBucketRequestPayment", "s3:GetBucketRequestPayment",
	// Attribute-based access control
	"s3:PutBucketAbac", "s3:GetBucketAbac",
	// Metadata tables (Update covers the journal, inventory and annotation tables)
	"s3:CreateBucketMetadataTableConfiguration", "s3:GetBucketMetadataTableConfiguration",
	"s3:DeleteBucketMetadataTableConfiguration", "s3:UpdateBucketMetadata",
}

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
		// Listing the versions to delete when force_destroy empties a bucket
		"s3:ListBucketVersions": true,
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

// classifyResourcePermission classifies an action for one resource type. An
// S3 bucket feature is optional on aws_s3_bucket, which only configures it when
// the matching attribute is set. A dedicated aws_s3_bucket_* resource exists to
// configure that feature, so there the same action is required.
func classifyResourcePermission(tfType, action string) PermissionClass {
	class := classifyPermission(action)
	if class == ClassOptional && strings.HasPrefix(tfType, "aws_s3_bucket_") && strings.HasPrefix(action, "s3:") {
		return ClassManagement
	}
	return class
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
	// ResourceScopeUnverified marks an action the policy grants only on some
	// resources while the target ARN is unknown (--strict-resources). The
	// grant may or may not apply, so the finding is unverified, not missing.
	ResourceScopeUnverified bool
	// ConditionAttribute is the attribute gating this action, e.g.
	// "kms_key_arn": set in the planned resource (d.GetOk) or changed between
	// prior and planned state (d.HasChange). Empty for an unconditional action.
	ConditionAttribute string
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
	// the planned resource (a d.GetOk or d.Get guard).
	GetConditional() map[string]map[string]string
	// GetChangeGated maps op → action → the attribute whose change gates the
	// action (a d.HasChange guard). Such an action is only required when that
	// attribute differs between the prior and the planned resource.
	GetChangeGated() map[string]map[string]string
	// GetValueConditional maps op → action → true when the gating attribute is
	// compared by value, so its default keeps the guard satisfied on its own.
	// Such an action is only required when the author configured the attribute.
	GetValueConditional() map[string]map[string]bool
	// GetBestEffort maps op → action → true when the provider ignores the
	// action's failure. Such an action is never required: it is classed
	// optional.
	GetBestEffort() map[string]map[string]bool
}

// FilterConfig controls which permission classes are filtered out of validation.
type FilterConfig struct {
	// ExcludeDataPlane excludes data-plane permissions (dynamodb:PutItem, s3:GetObject, etc.)
	ExcludeDataPlane bool
	// ExcludeOptional excludes optional sub-resource permissions (vault access policy, S3 website, etc.)
	ExcludeOptional bool
	// ExcludeServiceRole excludes permissions only AWS service roles need (backup-storage, etc.)
	ExcludeServiceRole bool
	// ExcludeConditional excludes permissions gated on a schema attribute
	// (d.GetOk or d.HasChange guard). When true, only unconditional [required]
	// actions are kept.
	ExcludeConditional bool
	// StrictResources reports an action as unverified when the tool cannot
	// derive its target ARN and the policy grants it only on some resources.
	// When it is off, an action-only match counts as coverage there.
	StrictResources bool
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
		changeGated := schema.GetChangeGated()[op]
		valueConditional := schema.GetValueConditional()[op]
		bestEffortActions := schema.GetBestEffort()[op]
		multiGates := schemaGates(schema, op)

		for _, action := range required {
			service := strings.Split(action, ":")[0]
			var gateAttr string
			var bestEffort bool
			if gates, ok := multiGates[action]; ok {
				// An action reached on several paths is needed when any of
				// them runs.
				var needed bool
				needed, gateAttr, bestEffort = evaluateGates(gates, rc)
				if !needed {
					continue
				}
			} else {
				condAttr := conditional[action]
				changeAttr := changeGated[action]
				// An action is reported only when every gate it carries holds, so a
				// failing presence gate or a failing change gate each drops it. The
				// tag names both gating attributes, since either can be the reason.
				gateAttr = gateAttribute(condAttr, changeAttr)
				bestEffort = bestEffortActions[action]

				// Conditional (attribute-gated) permissions: when the plan carries
				// attribute info and the gating attribute is NOT meaningfully set,
				// skip the permission. When Attributes is nil (e.g. static HCL
				// mode), presence is unknown and the permission is kept.
				if condAttr != "" && !conditionMet(condAttr, valueConditional[action], rc) {
					continue
				}

				// Change-gated permissions: the provider makes these calls only
				// when the attribute changed, so drop the permission when the plan
				// shows no change. When ChangedAttributes is nil (static HCL mode,
				// or a delete with no planned state), the change is unknown and the
				// permission is kept.
				if changeAttr != "" && rc.ChangedAttributes != nil && !rc.ChangedAttributes[changeAttr] {
					continue
				}
			}

			// Action coverage, resource-scoped when the target ARN is derivable
			// from the plan and the policy declares per-resource grants. In
			// strict mode, a grant limited to some resources does not count
			// when the target is unknown.
			targets := resourceTargetARNs(rc, changes)
			unverified := false
			if coversActionOnTargets(policy, action, targets) {
				if !filter.StrictResources || len(targets) > 0 || !resourceScopeUnverified(policy, action) {
					continue
				}
				unverified = true
			}

			// Classify and optionally filter
			class := classifyResourcePermission(rc.Type, action)
			// A call whose failure the provider ignores cannot fail the
			// apply, so it is optional whatever its action.
			if bestEffort && class == ClassManagement {
				class = ClassOptional
			}
			if filter.ExcludeDataPlane && class == ClassDataPlane {
				continue
			}
			if filter.ExcludeOptional && class == ClassOptional {
				continue
			}
			if filter.ExcludeServiceRole && class == ClassServiceRole {
				continue
			}
			if filter.ExcludeConditional && gateAttr != "" {
				continue
			}

			missing = append(missing, MissingAction{
				ResourceType:       rc.Type,
				ResourceName:       rc.Name,
				Change:             rc.Change,
				Action:             action,
				Service:            service,
				Class:              classTag(class),
				ConditionAttribute: gateAttr,

				ResourceScopeUnverified: unverified,
			})
		}
	}

	// Cross-service callback permissions: actions in a different service that
	// AWS invokes at apply time (e.g. elasticloadbalancing:SetWebACL for an
	// aws_wafv2_web_acl_association targeting an ALB). These are invisible to
	// schema/source resolution, so they're checked separately here.
	for _, rc := range changes {
		for _, m := range append(crossServiceMissing(rc, policy, filter.StrictResources), passRoleMissing(rc, policy, changes, filter.StrictResources)...) {
			if filter.ExcludeConditional && m.ConditionAttribute != "" {
				continue
			}
			missing = append(missing, m)
		}
	}

	// Post-process: remove permissions absorbed by S3 sub-resource configs
	missing = filterS3Subresources(missing, changes)

	return missing, nil
}

// gateAttribute names the attributes gating an action, for the
// [conditional: <attr>] tag. An action can carry a presence gate, a change
// gate, or both, so both names appear when both apply. Empty when neither
// gate applies.
func gateAttribute(presenceAttr, changeAttr string) string {
	switch {
	case presenceAttr == "":
		return changeAttr
	case changeAttr == "" || changeAttr == presenceAttr:
		return presenceAttr
	default:
		return presenceAttr + "+" + changeAttr
	}
}

// conditionMet reports whether a guard on an attribute lets its call run for
// this resource change.
//
// A presence guard (d.GetOk) needs the attribute to hold a non-zero value in
// the planned or prior state.
//
// A value guard — a set that must be non-empty, say — reads the attribute's
// value, and the provider's default already supplies a non-zero one. Only the
// configuration can tell a set the author wrote from one the provider filled,
// so a value guard asks the configuration section instead. With no
// configuration to read, both kinds fall back to presence, which keeps the
// permission rather than dropping one the provider may still need.
func conditionMet(attr string, valueGuarded bool, rc *plan.ResourceChange) bool {
	if valueGuarded && rc.Configured != nil {
		return rc.Configured[attr]
	}
	if rc.Attributes == nil {
		return true
	}
	return rc.Attributes[attr]
}

// missingGroupKey is a grouping key for deduplicating missing actions.
type missingGroupKey struct {
	action     string
	class      string
	condition  string
	unverified bool
}

// groupKey returns the key that groups m with identical findings on other
// resources.
func groupKey(m MissingAction) missingGroupKey {
	return missingGroupKey{action: m.Action, class: m.Class, condition: m.ConditionAttribute, unverified: m.ResourceScopeUnverified}
}

// unverifiedTag marks a finding whose coverage depends on a resource scope the
// tool cannot check (--strict-resources).
const unverifiedTag = "[unverified: resource scope]"

// groupMissing groups missing actions by groupKey, preserving first-seen order.
func groupMissing(missing []MissingAction) (map[missingGroupKey][]MissingAction, []missingGroupKey) {
	groups := make(map[missingGroupKey][]MissingAction)
	order := make([]missingGroupKey, 0, len(missing))
	for _, m := range missing {
		k := groupKey(m)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], m)
	}
	return groups, order
}

// FormatMissing formats a list of missing actions as a human-readable message.
// Permissions are grouped by (Action, Class, ConditionAttribute) so duplicates
// across resources are collapsed into a single entry, followed by the list of
// affected resources. Findings unverified for resource scope get a section of
// their own after the missing ones. When locations is non-nil and a resource
// has a matching FileLocation entry (keyed by "type.name"), the file path and
// line number are appended to the resource line.
func FormatMissing(missing []MissingAction, locations map[string]FileLocation) string {
	if len(missing) == 0 {
		return ""
	}

	groups, order := groupMissing(missing)
	var plain, unverified []missingGroupKey
	for _, k := range order {
		if k.unverified {
			unverified = append(unverified, k)
		} else {
			plain = append(plain, k)
		}
	}

	var b strings.Builder
	if len(plain) > 0 {
		b.WriteString(fmt.Sprintf("Missing IAM permissions (%d):\n", len(plain)))
		writeMissingGroups(&b, plain, groups, locations)
	}
	if len(unverified) > 0 {
		if len(plain) > 0 {
			b.WriteString("\n")
		}
		b.WriteString(fmt.Sprintf("Unverified IAM permissions (%d), granted only on resources whose ARN the plan does not show:\n", len(unverified)))
		writeMissingGroups(&b, unverified, groups, locations)
	}
	return b.String()
}

// writeMissingGroups writes one action line per group key, each followed by
// its affected resources.
func writeMissingGroups(b *strings.Builder, keys []missingGroupKey, groups map[missingGroupKey][]MissingAction, locations map[string]FileLocation) {
	for _, k := range keys {
		// Action line with optional class and condition tags
		line := k.action
		if k.condition != "" {
			line += fmt.Sprintf(" [conditional: %s]", k.condition)
		} else if k.class != "" {
			line += " " + k.class
		}
		if k.unverified {
			line += " " + unverifiedTag
		}
		b.WriteString(fmt.Sprintf("  %s\n", line))
		// Affected resources
		for _, m := range groups[k] {
			resourceLine := fmt.Sprintf("    → %s.%s (%s)", m.ResourceType, m.ResourceName, m.Change)
			if locations != nil {
				key := m.ResourceType + "." + stripResourceIndex(m.ResourceName)
				if loc, ok := locations[key]; ok {
					resourceLine += fmt.Sprintf(" [%s:%d]", loc.Path, loc.Line)
				}
			}
			b.WriteString(resourceLine + "\n")
		}
	}
}

// DistinctCount returns the number of distinct (Action, Class, ConditionAttribute)
// groups in the list, unverified ones included.
func DistinctCount(missing []MissingAction) int {
	_, order := groupMissing(missing)
	return len(order)
}

// UnverifiedCount returns the number of distinct groups that are unverified
// for resource scope.
func UnverifiedCount(missing []MissingAction) int {
	_, order := groupMissing(missing)
	n := 0
	for _, k := range order {
		if k.unverified {
			n++
		}
	}
	return n
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
