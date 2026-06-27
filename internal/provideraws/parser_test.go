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

func TestParseResourceFile_IAMRole_Helpers(t *testing.T) {
	// Simulates the real IAM role.go pattern where Create and Read delegate to helpers
	src := `
package iam

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
)

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	output, err := retryCreateRole(ctx, conn, input)
	if err != nil {
		return diags
	}
	if v, ok := d.GetOk("inline_policy"); ok {
		addRoleInlinePolicies(ctx, conn, policies)
	}
	return append(diags, resourceRoleRead(ctx, d, meta)...)
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	output, err := findRoleByName(ctx, conn, d.Id())
	if err != nil {
		return diags
	}
	_ = output
	return diags
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	err := deleteRole(ctx, conn, d.Id(), true, true)
	if err != nil {
		return diags
	}
	return diags
}

func retryCreateRole(ctx context.Context, conn *iam.Client, input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	return conn.CreateRole(ctx, input)
}

func findRoleByName(ctx context.Context, conn *iam.Client, name string) (*awstypes.Role, error) {
	return findRole(ctx, conn, input)
}

func findRole(ctx context.Context, conn *iam.Client, input *iam.GetRoleInput) (*awstypes.Role, error) {
	output, err := conn.GetRole(ctx, input)
	return output, err
}

func addRoleInlinePolicies(ctx context.Context, conn *iam.Client, policies []*awstypes.PutRolePolicyInput) error {
	for _, p := range policies {
		_, err := conn.PutRolePolicy(ctx, p)
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteRole(ctx context.Context, conn *iam.Client, roleName string, forceDetach, deletePolicy bool) error {
	_, err := conn.DeleteRole(ctx, input)
	return err
}
`
	actions, err := ParseResourceFile(src, "aws_iam_role", "Role")
	if err != nil {
		t.Fatalf("ParseResourceFile failed: %v", err)
	}

	// Create should find CreateRole through the retryCreateRole helper
	createActions := actions["create"]
	if !containsAction(createActions, "iam:CreateRole") {
		t.Errorf("create: expected iam:CreateRole (via retryCreateRole helper), got %v", createActions)
	}
	if !containsAction(createActions, "iam:PutRolePolicy") {
		t.Errorf("create: expected iam:PutRolePolicy (via addRoleInlinePolicies helper), got %v", createActions)
	}
	// Create should also include Read permissions from the return-follow
	if !containsAction(createActions, "iam:GetRole") {
		t.Errorf("create: expected iam:GetRole (via findRoleByName → findRole → return-follow from Read), got %v", createActions)
	}

	// Read should find GetRole through the findRoleByName → findRole chain
	readActions := actions["read"]
	if !containsAction(readActions, "iam:GetRole") {
		t.Errorf("read: expected iam:GetRole (via findRoleByName → findRole), got %v", readActions)
	}

	// Delete should find DeleteRole through the deleteRole helper
	deleteActions := actions["delete"]
	if !containsAction(deleteActions, "iam:DeleteRole") {
		t.Errorf("delete: expected iam:DeleteRole (via deleteRole helper), got %v", deleteActions)
	}
}

func TestParseResourceFile_ElastiCache_Helpers(t *testing.T) {
	// Simulates the real ElastiCache cluster.go pattern
	src := `
package elasticache

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
)

func resourceClusterCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ElastiCacheClient(ctx)
	clusterID, _, err := createCacheCluster(ctx, conn, partition, input)
	if err != nil {
		return diags
	}
	d.SetId(clusterID)
	return append(diags, resourceClusterRead(ctx, d, meta)...)
}

func resourceClusterRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ElastiCacheClient(ctx)
	cluster, err := findCacheClusterByID(ctx, conn, d.Id())
	if err != nil {
		return diags
	}
	_ = cluster
	return diags
}

func resourceClusterDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ElastiCacheClient(ctx)
	err := deleteCacheCluster(ctx, conn, d.Id(), finalSnapshotID)
	if err != nil {
		return diags
	}
	return diags
}

func createCacheCluster(ctx context.Context, conn *elasticache.Client, partition string, input *elasticache.CreateCacheClusterInput) (string, string, error) {
	output, err := conn.CreateCacheCluster(ctx, input)
	return aws.ToString(output.Id), aws.ToString(output.Arn), err
}

func findCacheClusterByID(ctx context.Context, conn *elasticache.Client, id string) (*awstypes.CacheCluster, error) {
	output, err := conn.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{CacheClusterId: aws.String(id)})
	return output.CacheClusters[0], err
}

func deleteCacheCluster(ctx context.Context, conn *elasticache.Client, id string, finalSnapshotID string) error {
	_, err := conn.DeleteCacheCluster(ctx, &elasticache.DeleteCacheClusterInput{CacheClusterId: aws.String(id)})
	return err
}
`
	actions, err := ParseResourceFile(src, "aws_elasticache_cluster", "Cluster")
	if err != nil {
		t.Fatalf("ParseResourceFile failed: %v", err)
	}

	createActions := actions["create"]
	if !containsAction(createActions, "elasticache:CreateCacheCluster") {
		t.Errorf("create: expected elasticache:CreateCacheCluster (via createCacheCluster helper), got %v", createActions)
	}
	// Create follows return to Read, which calls findCacheClusterByID → DescribeCacheClusters
	if !containsAction(createActions, "elasticache:DescribeCacheClusters") {
		t.Errorf("create: expected elasticache:DescribeCacheClusters (via return-follow → findCacheClusterByID), got %v", createActions)
	}

	readActions := actions["read"]
	if !containsAction(readActions, "elasticache:DescribeCacheClusters") {
		t.Errorf("read: expected elasticache:DescribeCacheClusters, got %v", readActions)
	}

	deleteActions := actions["delete"]
	if !containsAction(deleteActions, "elasticache:DeleteCacheCluster") {
		t.Errorf("delete: expected elasticache:DeleteCacheCluster (via deleteCacheCluster helper), got %v", deleteActions)
	}
}

func TestParseResourceFile_HelperDepthLimit(t *testing.T) {
	// Ensure we don't recurse infinitely with mutually recursive helpers
	src := `
package backup

func resourceVaultCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	output, err := helperA(ctx, conn, input)
	_ = output
	return errorCheck(err)
}

func helperA(ctx context.Context, conn *backup.Client, input *backup.CreateBackupVaultInput) (*backup.CreateBackupVaultOutput, error) {
	output, err := helperB(ctx, conn, input)
	return output, err
}

func helperB(ctx context.Context, conn *backup.Client, input *backup.CreateBackupVaultInput) (*backup.CreateBackupVaultOutput, error) {
	output, err := helperA(ctx, conn, input)
	return output, err
}
`
	actions, err := ParseResourceFile(src, "aws_backup_vault", "Vault")
	if err != nil {
		t.Fatalf("ParseResourceFile failed: %v", err)
	}

	// Should not panic or hang, even with mutually recursive helpers
	// Both helpers have no direct conn.Method() calls, so create should be empty
	if _, ok := actions["create"]; ok {
		t.Logf("create actions (should be empty): %v", actions["create"])
	}
}
