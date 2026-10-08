package iam

import (
	"testing"
)

func TestActionClass(t *testing.T) {
	tests := []struct {
		action string
		class  Class
	}{
		// Management-plane
		{"backup:CreateBackupVault", ClassManagement},
		{"backup:DeleteBackupVault", ClassManagement},
		{"dynamodb:CreateTable", ClassManagement},
		{"dynamodb:DescribeTable", ClassManagement},
		{"dynamodb:UpdateTable", ClassManagement},
		{"kms:CreateGrant", ClassManagement},
		{"kms:DescribeKey", ClassManagement},
		{"ec2:CreateVpc", ClassManagement},
		{"iam:CreateRole", ClassManagement},
		{"s3:CreateBucket", ClassManagement},
		{"s3:DeleteBucket", ClassManagement},
		{"logs:CreateLogGroup", ClassManagement},
		{"logs:DeleteLogGroup", ClassManagement},
		{"logs:DescribeLogGroups", ClassManagement},
		{"logs:PutRetentionPolicy", ClassManagement},
		// Managing an aws_cloudwatch_log_stream or a log group's tags and KMS
		// key is provisioning work (issue #54).
		{"logs:CreateLogStream", ClassManagement},
		{"logs:DeleteLogStream", ClassManagement},
		{"logs:DescribeLogStreams", ClassManagement},
		{"logs:TagResource", ClassManagement},
		{"logs:UntagResource", ClassManagement},
		{"logs:AssociateKmsKey", ClassManagement},
		{"logs:DeleteRetentionPolicy", ClassManagement},
		{"logs:PutSubscriptionFilter", ClassManagement},

		// Data-plane
		{"dynamodb:PutItem", ClassDataPlane},
		{"dynamodb:GetItem", ClassDataPlane},
		{"dynamodb:Query", ClassDataPlane},
		{"dynamodb:Scan", ClassDataPlane},
		{"s3:GetObject", ClassDataPlane},
		{"s3:PutObject", ClassDataPlane},
		{"s3:DeleteObject", ClassDataPlane},
		{"kms:Encrypt", ClassDataPlane},
		{"kms:Decrypt", ClassDataPlane},
		{"kinesis:PutRecords", ClassDataPlane},
		{"logs:PutLogEvents", ClassDataPlane},
		{"logs:StartQuery", ClassDataPlane},
		{"backup-storage:MountCapsule", ClassDataPlane},
		{"s3tables:CreateTable", ClassDataPlane},

		// Optional sub-resources
		{"backup:PutBackupVaultAccessPolicy", ClassOptional},
		{"backup:PutBackupVaultNotifications", ClassOptional},
		{"backup:PutBackupVaultLockConfiguration", ClassOptional},
		{"s3:PutBucketWebsite", ClassOptional},
		{"s3:PutBucketLogging", ClassOptional},
		{"s3:PutReplicationConfiguration", ClassOptional},
		{"dynamodb:ImportTable", ClassOptional},
		{"secretsmanager:GetRandomPassword", ClassOptional},
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
