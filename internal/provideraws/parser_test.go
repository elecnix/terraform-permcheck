package provideraws

import (
	"testing"
)

func TestParseResourceFile_BackupVault(t *testing.T) {
	src := `
package backup

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceVaultCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	input := &backup.CreateBackupVaultInput{BackupVaultName: aws.String(name)}
	_, err := conn.CreateBackupVault(ctx, input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Backup Vault: %s", err)
	}
	return append(diags, resourceVaultRead(ctx, d, meta)...)
}

func resourceVaultRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	output, err := findBackupVaultByName(ctx, conn, d.Id())
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Backup Vault: %s", err)
	}
	return diags
}

func resourceVaultUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	// Tags only.
	if d.HasChangesExcept("tags", "tags_all") {
		return diags
	}
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	_, err := conn.TagResource(ctx, &backup.TagResourceInput{ResourceArn: aws.String(id)})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "tagging Backup Vault: %s", err)
	}
	return append(diags, resourceVaultRead(ctx, d, meta)...)
}

func resourceVaultDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	_, err := conn.DeleteBackupVault(ctx, &backup.DeleteBackupVaultInput{BackupVaultName: aws.String(id)})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Backup Vault: %s", err)
	}
	return diags
}
`

	actions, err := ParseResourceFile(src, "aws_backup_vault", "vault")
	if err != nil {
		t.Fatalf("ParseResourceFile failed: %v", err)
	}

	// Create should find CreateBackupVault and follow the return to resourceVaultRead
	createActions := actions["create"]
	if !containsAction(createActions, "backup:CreateBackupVault") {
		t.Errorf("create: expected backup:CreateBackupVault, got %v", createActions)
	}

	// Delete should find DeleteBackupVault
	deleteActions := actions["delete"]
	if !containsAction(deleteActions, "backup:DeleteBackupVault") {
		t.Errorf("delete: expected backup:DeleteBackupVault, got %v", deleteActions)
	}

	// Update should find TagResource
	updateActions := actions["update"]
	if !containsAction(updateActions, "backup:TagResource") {
		t.Errorf("update: expected backup:TagResource, got %v", updateActions)
	}
}

func TestParseResourceFile_DynamoDBTable(t *testing.T) {
	src := `
package dynamodb

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
)

func resourceTableCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).DynamoDBClient(ctx)
	input := &dynamodb.CreateTableInput{TableName: aws.String(tableName)}
	_, err := conn.CreateTable(ctx, input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating table: %s", err)
	}
	return append(diags, resourceTableRead(ctx, d, meta)...)
}

func resourceTableRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).DynamoDBClient(ctx)
	table, err := findTableByName(ctx, conn, d.Id())
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading table: %s", err)
	}
	// Read also calls DescribeContinuousBackups
	_, err = conn.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: aws.String(d.Id())})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading continuous backups: %s", err)
	}
	return nil
}
`
	actions, err := ParseResourceFile(src, "aws_dynamodb_table", "table")
	if err != nil {
		t.Fatalf("ParseResourceFile failed: %v", err)
	}

	createActions := actions["create"]
	if !containsAction(createActions, "dynamodb:CreateTable") {
		t.Errorf("create: expected dynamodb:CreateTable, got %v", createActions)
	}

	readActions := actions["read"]
	if !containsAction(readActions, "dynamodb:DescribeContinuousBackups") {
		t.Errorf("read: expected dynamodb:DescribeContinuousBackups, got %v", readActions)
	}
}

func TestParseResourceFile_IAMRole(t *testing.T) {
	src := `
package iam

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	input := &iam.CreateRoleInput{RoleName: aws.String(name)}
	_, err := conn.CreateRole(ctx, input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating IAM Role: %s", err)
	}
	return append(diags, resourceRoleRead(ctx, d, meta)...)
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	output, err := conn.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(id)})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading IAM Role: %s", err)
	}
	return nil
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	_, err := conn.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(id)})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting IAM Role: %s", err)
	}
	return nil
}
`
	actions, err := ParseResourceFile(src, "aws_iam_role", "role")
	if err != nil {
		t.Fatalf("ParseResourceFile failed: %v", err)
	}

	createActions := actions["create"]
	if !containsAction(createActions, "iam:CreateRole") {
		t.Errorf("create: expected iam:CreateRole, got %v", createActions)
	}

	readActions := actions["read"]
	if !containsAction(readActions, "iam:GetRole") {
		t.Errorf("read: expected iam:GetRole, got %v", readActions)
	}

	deleteActions := actions["delete"]
	if !containsAction(deleteActions, "iam:DeleteRole") {
		t.Errorf("delete: expected iam:DeleteRole, got %v", deleteActions)
	}
}

func TestParseResourceFile_S3Bucket(t *testing.T) {
	src := `
package s3

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func resourceBucketCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	input := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
	_, err := conn.CreateBucket(ctx, input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating S3 Bucket: %s", err)
	}
	if _, ok := d.GetOk("versioning"); ok {
		_, err := conn.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket)})
		if err != nil {
			return sdkdiag.AppendErrorf(diags, "setting versioning: %s", err)
		}
	}
	return append(diags, resourceBucketRead(ctx, d, meta)...)
}
`
	actions, err := ParseResourceFile(src, "aws_s3_bucket", "bucket")
	if err != nil {
		t.Fatalf("ParseResourceFile failed: %v", err)
	}

	createActions := actions["create"]
	if !containsAction(createActions, "s3:CreateBucket") {
		t.Errorf("create: expected s3:CreateBucket, got %v", createActions)
	}
	// PutBucketVersioning is conditional and should still be found
	if !containsAction(createActions, "s3:PutBucketVersioning") {
		t.Errorf("create: expected s3:PutBucketVersioning (conditional), got %v", createActions)
	}
}

func TestSDKMethodToIAMAction(t *testing.T) {
	tests := []struct {
		method  string
		service string
		want    string
	}{
		{"CreateBackupVault", "backup", "backup:CreateBackupVault"},
		{"DeleteBackupVault", "backup", "backup:DeleteBackupVault"},
		{"DescribeBackupVault", "backup", "backup:DescribeBackupVault"},
		{"CreateTable", "dynamodb", "dynamodb:CreateTable"},
		{"UpdateTable", "dynamodb", "dynamodb:UpdateTable"},
		{"DescribeTable", "dynamodb", "dynamodb:DescribeTable"},
		{"DescribeContinuousBackups", "dynamodb", "dynamodb:DescribeContinuousBackups"},
		{"CreateRole", "iam", "iam:CreateRole"},
		{"GetRole", "iam", "iam:GetRole"},
		{"DeleteRole", "iam", "iam:DeleteRole"},
		{"CreateBucket", "s3", "s3:CreateBucket"},
		{"PutBucketVersioning", "s3", "s3:PutBucketVersioning"},
		{"ListRecoveryPointsByBackupVault", "backup", "backup:ListRecoveryPointsByBackupVault"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := sdKMethodToIAMAction(tt.method, tt.service)
			if got != tt.want {
				t.Errorf("sdKMethodToIAMAction(%q, %q) = %q, want %q", tt.method, tt.service, got, tt.want)
			}
		})
	}
}

func TestClientMethodToService(t *testing.T) {
	tests := []struct {
		clientMethod string
		want         string
	}{
		{"BackupClient", "backup"},
		{"DynamoDBClient", "dynamodb"},
		{"IAMClient", "iam"},
		{"S3Client", "s3"},
		{"STSClient", "sts"},
		{"KMSClient", "kms"},
		{"LambdaClient", "lambda"},
		{"EC2Client", "ec2"},
		{"SQSClient", "sqs"},
		{"SNSClient", "sns"},
		{"RDSClient", "rds"},
		{"CloudWatchLogsClient", "logs"},
	}

	for _, tt := range tests {
		t.Run(tt.clientMethod, func(t *testing.T) {
			got := clientMethodToService(tt.clientMethod)
			if got != tt.want {
				t.Errorf("clientMethodToService(%q) = %q, want %q", tt.clientMethod, got, tt.want)
			}
		})
	}
}

func containsAction(actions []string, want string) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}

func TestResourceTypeFromFile(t *testing.T) {
	tests := []struct {
		service string
		file    string
		want    string
	}{
		{"backup", "vault.go", "aws_backup_vault"},
		{"dynamodb", "table.go", "aws_dynamodb_table"},
		{"iam", "role.go", "aws_iam_role"},
		{"s3", "bucket.go", "aws_s3_bucket"},
		{"kms", "key.go", "aws_kms_key"},
		{"lambda", "function.go", "aws_lambda_function"},
	}

	for _, tt := range tests {
		t.Run(tt.service+"/"+tt.file, func(t *testing.T) {
			got := resourceTypeFromFile(tt.service, tt.file)
			if got != tt.want {
				t.Errorf("resourceTypeFromFile(%q, %q) = %q, want %q", tt.service, tt.file, got, tt.want)
			}
		})
	}
}

func TestResourceNameFromSource(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{`package backup
func resourceVaultCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {}`, "Vault"},
		{`package dynamodb
func resourceTableCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {}`, "Table"},
		{`package iam
func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {}`, "Role"},
		{`package s3
func resourceBucketCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {}`, "Bucket"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := resourceNameFromSource([]byte(tt.src))
			if got != tt.want {
				t.Errorf("resourceNameFromSource() = %q, want %q", got, tt.want)
			}
		})
	}
}
