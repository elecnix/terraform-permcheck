package iam

import "github.com/elecnix/terraform-permcheck/internal/plan"

// s3SubresourcePermissions maps S3 sub-resource terraform types to the
// s3 permissions they absorb from the parent aws_s3_bucket resource.
// When a sub-resource config is present in the plan, its listed permissions
// should be attributed to the sub-resource instead of the parent bucket.
//
// This avoids duplicate warnings when both aws_s3_bucket and e.g.
// aws_s3_bucket_server_side_encryption_configuration appear in the same plan.
var s3SubresourcePermissions = map[string][]string{
	"aws_s3_bucket_server_side_encryption_configuration": {
		"s3:PutBucketEncryption",
	},
	"aws_s3_bucket_versioning": {
		"s3:PutBucketVersioning",
	},
	"aws_s3_bucket_logging": {
		"s3:PutBucketLogging",
	},
	"aws_s3_bucket_website_configuration": {
		"s3:PutBucketWebsite",
	},
	"aws_s3_bucket_cors_configuration": {
		"s3:PutBucketCORS",
	},
	"aws_s3_bucket_acl": {
		"s3:PutBucketAcl",
	},
	"aws_s3_bucket_policy": {
		"s3:PutBucketPolicy",
		"s3:GetBucketPolicy",
	},
	"aws_s3_bucket_accelerate_configuration": {
		"s3:PutAccelerateConfiguration",
	},
	"aws_s3_bucket_object_lock_configuration": {
		"s3:PutBucketObjectLockConfiguration",
	},
	"aws_s3_bucket_replication_configuration": {
		"s3:PutBucketReplication",
	},
	"aws_s3_bucket_lifecycle_configuration": {
		"s3:PutBucketLifecycleConfiguration",
		"s3:GetBucketLifecycleConfiguration",
	},
	"aws_s3_bucket_public_access_block": {
		"s3:PutBucketPublicAccessBlock",
		"s3:GetBucketPublicAccessBlock",
	},
}

// s3SubresourceAbsorbed returns a set of s3: action strings that should be
// absorbed by the given sub-resource terraform type (i.e., removed from
// the parent aws_s3_bucket's missing permissions).
func s3SubresourceAbsorbed(subType string) map[string]bool {
	actions, ok := s3SubresourcePermissions[subType]
	if !ok {
		return nil
	}
	m := make(map[string]bool, len(actions))
	for _, a := range actions {
		m[a] = true
	}
	return m
}

// filterS3Subresources removes permissions from the parent aws_s3_bucket's
// missing actions when the corresponding sub-resource config exists in the
// plan changes. Returns the filtered slice.
func filterS3Subresources(missing []MissingAction, changes []*plan.ResourceChange) []MissingAction {
	// Determine which S3 sub-resource types are present in the plan
	subsPresent := make(map[string]bool)
	for _, rc := range changes {
		if _, ok := s3SubresourcePermissions[rc.Type]; ok {
			subsPresent[rc.Type] = true
		}
	}
	if len(subsPresent) == 0 {
		return missing
	}

	// Build the set of absorbed permissions
	absorbed := make(map[string]bool)
	for subType := range subsPresent {
		for _, action := range s3SubresourcePermissions[subType] {
			absorbed[action] = true
		}
	}

	// Filter out absorbed permissions from aws_s3_bucket's missing actions
	var filtered []MissingAction
	for _, m := range missing {
		if m.ResourceType == "aws_s3_bucket" && absorbed[m.Action] {
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
}
