package cloud

import (
	"testing"
)

func TestCfnKeys(t *testing.T) {
	tests := []struct {
		tfType string
		want0  string // first key
		want1  string // second key (if different from first)
	}{
		{"aws_backup_vault", "aws-backup-vault", "aws-backup-backupvault"},
		{"aws_dynamodb_table", "aws-dynamodb-table", "aws-dynamodb-dynamodbtable"},
		{"aws_iam_role", "aws-iam-role", "aws-iam-iamrole"},
		{"aws_s3_bucket", "aws-s3-bucket", "aws-s3-s3bucket"},
		{"aws_lambda_function", "aws-lambda-function", "aws-lambda-lambdafunction"},
		{"aws_secretsmanager_secret", "aws-secretsmanager-secret", "aws-secretsmanager-secretsmanagersecret"},
	}

	for _, tt := range tests {
		t.Run(tt.tfType, func(t *testing.T) {
			keys := cfnKeys(tt.tfType)
			if len(keys) < 1 {
				t.Fatalf("expected at least 1 key, got 0")
			}
			if keys[0] != tt.want0 {
				t.Errorf("key[0] = %q, want %q", keys[0], tt.want0)
			}
			if tt.want1 != "" && tt.want1 != tt.want0 {
				if len(keys) < 2 || keys[1] != tt.want1 {
					t.Errorf("key[1] = %v, want %q", keys, tt.want1)
				}
			}
		})
	}
}

func TestCfnKeysNonAWS(t *testing.T) {
	keys := cfnKeys("google_storage_bucket")
	if len(keys) != 0 {
		t.Errorf("expected empty keys for non-AWS type, got %v", keys)
	}
}

func TestNewAWSProvider(t *testing.T) {
	p := NewAWSProvider()
	if p.Name() != "aws" {
		t.Errorf("expected name 'aws', got %q", p.Name())
	}
	if p.baseURL == "" {
		t.Error("expected non-empty baseURL")
	}
}

// TestAWSProviderResolveReal checks the live CFN registry for known resource types.
func TestAWSProviderResolveReal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in short mode")
	}
	p := NewAWSProvider()

	tests := []struct {
		tfType       string
		wantAction   string // must appear in create permissions
		wantKmsGrant bool   // kms:CreateGrant should appear in create permissions
	}{
		{"aws_backup_vault", "backup:CreateBackupVault", true},
		{"aws_dynamodb_table", "dynamodb:CreateTable", false},
		{"aws_iam_role", "iam:CreateRole", false},
	}

	for _, tt := range tests {
		t.Run(tt.tfType, func(t *testing.T) {
			schema, err := p.Resolve(tt.tfType)
			if err != nil {
				t.Fatalf("resolve %s: %v", tt.tfType, err)
			}
			createPerms := schema.GetPermissions()["create"]
			if len(createPerms) == 0 {
				t.Fatal("expected non-empty create permissions")
			}

			found := false
			for _, a := range createPerms {
				if a == tt.wantAction {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %q in create permissions, got %v", tt.wantAction, createPerms)
			}

			if tt.wantKmsGrant {
				foundKms := false
				for _, a := range createPerms {
					if a == "kms:CreateGrant" {
						foundKms = true
						break
					}
				}
				if !foundKms {
					t.Errorf("expected kms:CreateGrant in create permissions, got %v", createPerms)
				}
			}
		})
	}
}
