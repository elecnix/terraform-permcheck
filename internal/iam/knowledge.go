package iam

import "strings"

// AWS permission knowledge.
//
// The producers, the CloudFormation registry and the provider-source parser,
// say which actions an operation on a resource reaches. This file says what
// those actions mean: which ones touch data rather than infrastructure, which
// ones configure an optional feature, which ones a dedicated sub-resource
// owns, and which ones AWS calls in another service at apply time.
//
// Each action name appears in one row, so the rule that classifies an action
// and the rule that hands it to a sub-resource cannot spell it two ways.
// knowledge_test.go checks that every name is one a producer emits, using the
// golden lists under testdata/. A row that names nothing a producer emits can
// never fire.
//
// targetRules (resource_scope.go) stays apart. Its rows are functions of a
// resource change, not facts about an action name.

// rule is what the tool knows about one action name.
type rule struct {
	// action is the action name exactly as a producer emits it.
	action string
	// class is the action's class on any resource that is not a dedicated
	// sub-resource for it.
	class PermissionClass
	// ownedBy is the aws_s3_bucket_* type that configures this bucket
	// feature on its own. When the plan has one, aws_s3_bucket leaves the
	// action to it. Empty when no sub-resource owns the action.
	ownedBy string
}

// serviceClasses gives a class to every action of a service.
var serviceClasses = map[string]PermissionClass{
	"s3tables":       ClassDataPlane, // S3 Tables is a data-plane service
	"backup-storage": ClassDataPlane, // backup-storage is the AWS Backup data-plane
}

// The aws_s3_bucket_* types that own a bucket feature.
const (
	s3Accelerate         = "aws_s3_bucket_accelerate_configuration"
	s3ACL                = "aws_s3_bucket_acl"
	s3Analytics          = "aws_s3_bucket_analytics_configuration"
	s3CORS               = "aws_s3_bucket_cors_configuration"
	s3Encryption         = "aws_s3_bucket_server_side_encryption_configuration"
	s3IntelligentTiering = "aws_s3_bucket_intelligent_tiering_configuration"
	s3Inventory          = "aws_s3_bucket_inventory"
	s3Lifecycle          = "aws_s3_bucket_lifecycle_configuration"
	s3Logging            = "aws_s3_bucket_logging"
	s3Metric             = "aws_s3_bucket_metric"
	s3Notification       = "aws_s3_bucket_notification"
	s3ObjectLock         = "aws_s3_bucket_object_lock_configuration"
	s3OwnershipControls  = "aws_s3_bucket_ownership_controls"
	s3Policy             = "aws_s3_bucket_policy"
	s3PublicAccessBlock  = "aws_s3_bucket_public_access_block"
	s3RequestPayment     = "aws_s3_bucket_request_payment_configuration"
	s3Replication        = "aws_s3_bucket_replication_configuration"
	s3Versioning         = "aws_s3_bucket_versioning"
	s3Website            = "aws_s3_bucket_website_configuration"
)

// optionalS3 is a bucket feature that aws_s3_bucket only configures when the
// matching attribute is set, owned by the sub-resource ownedBy.
func optionalS3(action, ownedBy string) rule {
	return rule{action: action, class: ClassOptional, ownedBy: ownedBy}
}

// rules lists every action the tool classifies other than [required]. An
// action with no row is a management-plane action. A row exists only for a
// name a producer emits: the SQS messaging calls, Kinesis GetRecords and the
// log-reading calls are data-plane too, but no resource reaches them.
var rules = []rule{
	// DynamoDB data-plane
	{action: "dynamodb:PutItem", class: ClassDataPlane},
	{action: "dynamodb:GetItem", class: ClassDataPlane},
	{action: "dynamodb:UpdateItem", class: ClassDataPlane},
	{action: "dynamodb:DeleteItem", class: ClassDataPlane},
	{action: "dynamodb:Query", class: ClassDataPlane},
	{action: "dynamodb:Scan", class: ClassDataPlane},
	{action: "dynamodb:BatchWriteItem", class: ClassDataPlane},
	{action: "dynamodb:BatchGetItem", class: ClassDataPlane},
	// S3 object-level operations
	{action: "s3:GetObject", class: ClassDataPlane},
	{action: "s3:GetObjectMetadata", class: ClassDataPlane},
	{action: "s3:PutObject", class: ClassDataPlane},
	{action: "s3:PutObjectAcl", class: ClassDataPlane},
	{action: "s3:DeleteObject", class: ClassDataPlane},
	{action: "s3:AbortMultipartUpload", class: ClassDataPlane},
	// Listing the versions to delete when force_destroy empties a bucket
	{action: "s3:ListBucketVersions", class: ClassDataPlane},
	// KMS data-plane (encrypt/decrypt at object level)
	{action: "kms:Encrypt", class: ClassDataPlane},
	{action: "kms:Decrypt", class: ClassDataPlane},
	{action: "kms:GenerateDataKey", class: ClassDataPlane},
	{action: "kms:GenerateDataKeyWithoutPlaintext", class: ClassDataPlane},
	{action: "kms:ReEncryptFrom", class: ClassDataPlane},
	{action: "kms:ReEncryptTo", class: ClassDataPlane},
	// Kinesis data-plane
	{action: "kinesis:PutRecords", class: ClassDataPlane},
	{action: "kinesis:DescribeStream", class: ClassDataPlane},
	// CloudWatch Logs data-plane: writing log events and querying them.
	// Creating a log stream is provisioning, since the provider calls it for
	// aws_cloudwatch_log_stream.
	{action: "logs:PutLogEvents", class: ClassDataPlane},
	{action: "logs:StartQuery", class: ClassDataPlane},

	// Backup vault features, only needed when the configuration sets the
	// matching block (access_policy, notifications, lock_configuration).
	{action: "backup:PutBackupVaultAccessPolicy", class: ClassOptional},
	{action: "backup:PutBackupVaultNotifications", class: ClassOptional},
	{action: "backup:PutBackupVaultLockConfiguration", class: ClassOptional},
	{action: "backup:DeleteBackupVaultAccessPolicy", class: ClassOptional},
	{action: "backup:DeleteBackupVaultNotifications", class: ClassOptional},
	{action: "backup:DeleteBackupVaultLockConfiguration", class: ClassOptional},
	{action: "backup:GetBackupVaultAccessPolicy", class: ClassOptional},
	{action: "backup:GetBackupVaultNotifications", class: ClassOptional},

	// DynamoDB optional features (import/export, Kinesis streaming,
	// contributor insights, resource policy, replicas)
	{action: "dynamodb:ImportTable", class: ClassOptional},
	{action: "dynamodb:DescribeImport", class: ClassOptional},
	{action: "dynamodb:EnableKinesisStreamingDestination", class: ClassOptional},
	{action: "dynamodb:DisableKinesisStreamingDestination", class: ClassOptional},
	{action: "dynamodb:UpdateContributorInsights", class: ClassOptional},
	{action: "dynamodb:DescribeContributorInsights", class: ClassOptional},
	{action: "dynamodb:GetResourcePolicy", class: ClassOptional},
	{action: "dynamodb:PutResourcePolicy", class: ClassOptional},
	{action: "dynamodb:CreateTableReplica", class: ClassOptional},
	{action: "dynamodb:AssociateTableReplica", class: ClassOptional},

	// IAM policy sub-types that the deploy role doesn't manage
	{action: "iam:GetUserPolicy", class: ClassOptional},
	{action: "iam:GetGroupPolicy", class: ClassOptional},
	{action: "iam:PutUserPolicy", class: ClassOptional},
	{action: "iam:PutGroupPolicy", class: ClassOptional},

	// Secrets Manager optional
	{action: "secretsmanager:GetRandomPassword", class: ClassOptional},
	{action: "secretsmanager:ReplicateSecretToRegions", class: ClassOptional},

	// S3 bucket features. aws_s3_bucket only configures one when the matching
	// attribute is set, and a dedicated aws_s3_bucket_* resource exists to
	// configure most of them on their own.
	//
	// The CloudFormation schema for AWS::S3::Bucket resolves aws_s3_bucket
	// when the provider checkout is unavailable. The provider-source parser
	// resolves aws_s3_bucket and the sub-resources from their SDK calls. Where
	// the two spell an action differently, both spellings have a row.
	//
	// Website, CORS, logging
	optionalS3("s3:PutBucketWebsite", s3Website),
	optionalS3("s3:GetBucketWebsite", s3Website),
	optionalS3("s3:DeleteBucketWebsite", s3Website),
	optionalS3("s3:PutBucketCORS", s3CORS),
	optionalS3("s3:GetBucketCORS", s3CORS),
	optionalS3("s3:DeleteBucketCors", s3CORS),
	optionalS3("s3:PutBucketLogging", s3Logging),
	optionalS3("s3:GetBucketLogging", s3Logging),
	// Replication
	optionalS3("s3:PutBucketReplication", s3Replication),
	optionalS3("s3:DeleteBucketReplication", s3Replication),
	optionalS3("s3:PutReplicationConfiguration", s3Replication),
	optionalS3("s3:GetReplicationConfiguration", s3Replication),
	// Transfer acceleration
	optionalS3("s3:PutAccelerateConfiguration", s3Accelerate),
	optionalS3("s3:GetAccelerateConfiguration", s3Accelerate),
	// Analytics, inventory, metrics, intelligent tiering
	optionalS3("s3:PutAnalyticsConfiguration", s3Analytics),
	optionalS3("s3:GetAnalyticsConfiguration", s3Analytics),
	optionalS3("s3:DeleteBucketAnalyticsConfiguration", s3Analytics),
	optionalS3("s3:PutInventoryConfiguration", s3Inventory),
	optionalS3("s3:GetInventoryConfiguration", s3Inventory),
	optionalS3("s3:PutMetricsConfiguration", s3Metric),
	optionalS3("s3:GetMetricsConfiguration", s3Metric),
	optionalS3("s3:DeleteBucketMetricsConfiguration", s3Metric),
	optionalS3("s3:PutIntelligentTieringConfiguration", s3IntelligentTiering),
	optionalS3("s3:GetIntelligentTieringConfiguration", s3IntelligentTiering),
	// Object lock
	optionalS3("s3:PutBucketObjectLockConfiguration", s3ObjectLock),
	optionalS3("s3:GetBucketObjectLockConfiguration", s3ObjectLock),
	optionalS3("s3:PutObjectLockConfiguration", s3ObjectLock),
	// Server-side encryption
	optionalS3("s3:PutEncryptionConfiguration", s3Encryption),
	optionalS3("s3:GetEncryptionConfiguration", s3Encryption),
	optionalS3("s3:DeleteBucketEncryption", s3Encryption),
	// Lifecycle
	optionalS3("s3:PutLifecycleConfiguration", s3Lifecycle),
	optionalS3("s3:GetLifecycleConfiguration", s3Lifecycle),
	optionalS3("s3:DeleteBucketLifecycle", s3Lifecycle),
	// The S3 on Outposts lifecycle call of
	// aws_s3control_bucket_lifecycle_configuration
	optionalS3("s3:DeleteBucketLifecycleConfiguration", ""),
	// Notifications, versioning, ownership controls, public access block
	optionalS3("s3:PutBucketNotification", s3Notification),
	optionalS3("s3:GetBucketNotification", s3Notification),
	// AWS::SecurityLake::SubscriberNotification lists the SDK names of the
	// notification calls.
	optionalS3("s3:PutBucketNotificationConfiguration", ""),
	optionalS3("s3:GetBucketNotificationConfiguration", ""),
	optionalS3("s3:PutBucketVersioning", s3Versioning),
	optionalS3("s3:GetBucketVersioning", s3Versioning),
	optionalS3("s3:PutBucketOwnershipControls", s3OwnershipControls),
	optionalS3("s3:GetBucketOwnershipControls", s3OwnershipControls),
	optionalS3("s3:PutBucketPublicAccessBlock", s3PublicAccessBlock),
	optionalS3("s3:GetBucketPublicAccessBlock", s3PublicAccessBlock),
	// Tags
	optionalS3("s3:PutBucketTagging", ""),
	optionalS3("s3:GetBucketTagging", ""),
	optionalS3("s3:TagResource", ""),
	optionalS3("s3:UntagResource", ""),
	optionalS3("s3:ListTagsForResource", ""),
	// Bucket policy and requester pays
	optionalS3("s3:PutBucketPolicy", s3Policy),
	optionalS3("s3:GetBucketPolicy", s3Policy),
	optionalS3("s3:DeleteBucketPolicy", s3Policy),
	optionalS3("s3:PutBucketRequestPayment", s3RequestPayment),
	optionalS3("s3:GetBucketRequestPayment", s3RequestPayment),
	// Attribute-based access control
	optionalS3("s3:PutBucketAbac", ""),
	optionalS3("s3:GetBucketAbac", ""),
	// Metadata tables
	optionalS3("s3:CreateBucketMetadataTableConfiguration", ""),
	optionalS3("s3:GetBucketMetadataTableConfiguration", ""),
	optionalS3("s3:DeleteBucketMetadataTableConfiguration", ""),
	optionalS3("s3:UpdateBucketMetadataJournalTableConfiguration", ""),
	optionalS3("s3:UpdateBucketMetadataInventoryTableConfiguration", ""),
	optionalS3("s3:UpdateBucketMetadataAnnotationTableConfiguration", ""),
	// The bucket ACL stays [required] on aws_s3_bucket, which writes it on
	// create, but aws_s3_bucket_acl takes it over when the plan has one.
	{action: "s3:PutBucketAcl", class: ClassManagement, ownedBy: s3ACL},
}

// ruleIndex looks up a rule by action name.
var ruleIndex = func() map[string]rule {
	m := make(map[string]rule, len(rules))
	for _, r := range rules {
		m[r.action] = r
	}
	return m
}()

// actionClass returns the class of action on a resource that is not a
// dedicated sub-resource for it.
func actionClass(action string) PermissionClass {
	if class, ok := serviceClasses[actionService(action)]; ok {
		return class
	}
	if r, ok := ruleIndex[action]; ok {
		return r.class
	}
	return ClassManagement
}

// decision is what the rules decide about one action on one resource.
type decision struct {
	// class is the action's class on this resource.
	class PermissionClass
	// absorbedBy is the sub-resource type in the plan that takes the action
	// over from this resource, or empty. An absorbed action is reported on
	// the sub-resource, not here.
	absorbedBy string
}

// decide classifies action on a resource of type tfType. bestEffort marks a
// call whose failure the provider ignores. inPlan holds the resource types the
// plan changes, so a sub-resource can take an action over from aws_s3_bucket.
func decide(tfType, action string, bestEffort bool, inPlan map[string]bool) decision {
	r := ruleIndex[action]
	if tfType == "aws_s3_bucket" && r.ownedBy != "" && inPlan[r.ownedBy] {
		return decision{class: r.class, absorbedBy: r.ownedBy}
	}
	class := actionClass(action)
	// A dedicated aws_s3_bucket_* resource exists to configure its feature,
	// so the action that is optional on aws_s3_bucket is required there.
	if class == ClassOptional && strings.HasPrefix(tfType, "aws_s3_bucket_") && actionService(action) == "s3" {
		class = ClassManagement
	}
	// A call whose failure the provider ignores cannot fail the apply, so it
	// is optional whatever its action.
	if bestEffort && class == ClassManagement {
		class = ClassOptional
	}
	return decision{class: class}
}

// actionService returns the service prefix of an action, e.g. "s3".
func actionService(action string) string {
	return strings.Split(action, ":")[0]
}

// Cross-service callback permissions.
//
// Some AWS APIs require IAM actions from a *different* service than the API
// being called. The primary API performs a cross-service callback at apply
// time that the terraform provider never invokes directly, so the required
// action is invisible to both the CloudFormation schema and the provider
// source parser.
//
// The canonical example is aws_wafv2_web_acl_association: the provider calls
// wafv2:AssociateWebACL, but AWS WAFv2 then calls into the target service to
// attach the ACL — elasticloadbalancing:SetWebACL for an ALB,
// apigateway:SetWebACL for an API Gateway stage, and so on. Which callback
// applies is determined by the service embedded in the target resource_arn.

// crossServiceCallback is a required IAM action in a service other than the
// one whose API the terraform provider calls directly.
type crossServiceCallback struct {
	// targetService is the AWS service prefix (as it appears in an ARN's third
	// segment) that selects this callback, e.g. "elasticloadbalancing".
	targetService string
	// action is the IAM action required in the callback service.
	action string
}

// crossServiceRule describes the cross-service callbacks for a terraform
// resource type and the attribute whose ARN value selects among them.
type crossServiceRule struct {
	// arnAttribute is the resource attribute holding the target ARN.
	arnAttribute string
	// callbacks lists the candidate callbacks keyed by target service.
	callbacks []crossServiceCallback
}

// crossServiceRules maps a terraform resource type to its cross-service
// callback rule.
var crossServiceRules = map[string]crossServiceRule{
	"aws_wafv2_web_acl_association": {
		arnAttribute: "resource_arn",
		callbacks: []crossServiceCallback{
			{targetService: "elasticloadbalancing", action: "elasticloadbalancing:SetWebACL"},
			{targetService: "apigateway", action: "apigateway:SetWebACL"},
			{targetService: "appsync", action: "appsync:SetWebACL"},
		},
	},
}
