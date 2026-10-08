package iam

import (
	"testing"
)

func TestActionClass(t *testing.T) {
	tests := []struct {
		action string
		class  permissionClass
	}{
		// Management-plane
		{"backup:CreateBackupVault", classManagement},
		{"backup:DeleteBackupVault", classManagement},
		{"dynamodb:CreateTable", classManagement},
		{"dynamodb:DescribeTable", classManagement},
		{"dynamodb:UpdateTable", classManagement},
		{"kms:CreateGrant", classManagement},
		{"kms:DescribeKey", classManagement},
		{"ec2:CreateVpc", classManagement},
		{"iam:CreateRole", classManagement},
		{"s3:CreateBucket", classManagement},
		{"s3:DeleteBucket", classManagement},
		{"logs:CreateLogGroup", classManagement},
		{"logs:DeleteLogGroup", classManagement},
		{"logs:DescribeLogGroups", classManagement},
		{"logs:PutRetentionPolicy", classManagement},
		// Managing an aws_cloudwatch_log_stream or a log group's tags and KMS
		// key is provisioning work (issue #54).
		{"logs:CreateLogStream", classManagement},
		{"logs:DeleteLogStream", classManagement},
		{"logs:DescribeLogStreams", classManagement},
		{"logs:TagResource", classManagement},
		{"logs:UntagResource", classManagement},
		{"logs:AssociateKmsKey", classManagement},
		{"logs:DeleteRetentionPolicy", classManagement},
		{"logs:PutSubscriptionFilter", classManagement},

		// Data-plane
		{"dynamodb:PutItem", classDataPlane},
		{"dynamodb:GetItem", classDataPlane},
		{"dynamodb:Query", classDataPlane},
		{"dynamodb:Scan", classDataPlane},
		{"s3:GetObject", classDataPlane},
		{"s3:PutObject", classDataPlane},
		{"s3:DeleteObject", classDataPlane},
		{"kms:Encrypt", classDataPlane},
		{"kms:Decrypt", classDataPlane},
		{"kinesis:PutRecords", classDataPlane},
		{"logs:PutLogEvents", classDataPlane},
		{"logs:StartQuery", classDataPlane},
		{"backup-storage:MountCapsule", classDataPlane},
		{"s3tables:CreateTable", classDataPlane},

		// Optional sub-resources
		{"backup:PutBackupVaultAccessPolicy", classOptional},
		{"backup:PutBackupVaultNotifications", classOptional},
		{"backup:PutBackupVaultLockConfiguration", classOptional},
		{"s3:PutBucketWebsite", classOptional},
		{"s3:PutBucketLogging", classOptional},
		{"s3:PutReplicationConfiguration", classOptional},
		{"dynamodb:ImportTable", classOptional},
		{"secretsmanager:GetRandomPassword", classOptional},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := actionClass(tt.action)
			if got != tt.class {
				t.Errorf("actionClass(%q) = %d, want %d", tt.action, got, tt.class)
			}
		})
	}
}

func TestClassTag(t *testing.T) {
	tests := []struct {
		class permissionClass
		tag   string
	}{
		{classManagement, "[required]"},
		{classOptional, "[optional]"},
		{classDataPlane, "[data-plane]"},
		{classUnknown, "[unknown]"},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			got := classTag(tt.class)
			if got != tt.tag {
				t.Errorf("classTag(%d) = %q, want %q", tt.class, got, tt.tag)
			}
		})
	}
}
