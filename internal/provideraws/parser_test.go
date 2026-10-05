package provideraws

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
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
		// S3 SDK v2 normalization: method name differs from canonical IAM action
		{"PutPublicAccessBlock", "s3", "s3:PutBucketPublicAccessBlock"},
		{"GetPublicAccessBlock", "s3", "s3:GetBucketPublicAccessBlock"},
		{"DeletePublicAccessBlock", "s3", "s3:DeleteBucketPublicAccessBlock"},
		{"PutBucketNotificationConfiguration", "s3", "s3:PutBucketNotification"},
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

func TestSDKPackageToIAMService(t *testing.T) {
	tests := []struct {
		pkg  string
		want string
	}{
		{"s3", ""},                 // exact match, no lookup needed
		{"iam", ""},                // exact match
		{"dynamodb", ""},           // exact match
		{"cloudwatchlogs", "logs"}, // package name differs from IAM namespace
		{"s3control", "s3"},
		{"sfn", "states"},
		{"eventbridge", "events"}, // IAM prefix is events, not eventbridge
		{"unknownpkg", ""},        // unknown, no mapping
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			got := sdkPackageToIAMService(tt.pkg)
			if got != tt.want {
				t.Errorf("sdkPackageToIAMService(%q) = %q, want %q", tt.pkg, got, tt.want)
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

func TestParseResourceFileStructured_ConditionalCalls(t *testing.T) {
	src := `
package backup

import (
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func resourceVaultCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)

	// Unconditional: always needed
	_, err := conn.CreateBackupVault(ctx, &backup.CreateBackupVaultInput{})
	if err != nil { return nil }

	// Conditional: only if kms_key_arn is set
	if v, ok := d.GetOk("kms_key_arn"); ok {
		kmsConn := meta.(*conns.AWSClient).KMSClient(ctx)
		_, err := kmsConn.CreateGrant(ctx, &kms.CreateGrantInput{})
		if err != nil { return nil }
	}

	// Conditional: only if tags are set
	if _, ok := d.GetOk("tags"); ok {
		conn.TagResource(ctx, &backup.TagResourceInput{})
	}

	return nil
}
`

	actions, err := ParseResourceFileStructured(src, "aws_backup_vault", "Vault")
	if err != nil {
		t.Fatalf("ParseResourceFileStructured failed: %v", err)
	}

	createActions := actions["create"]

	// Find unconditional CreateBackupVault
	var createVault *ExtractedAction
	var createGrant *ExtractedAction
	var tagResource *ExtractedAction
	for i := range createActions {
		switch createActions[i].Action {
		case "backup:CreateBackupVault":
			createVault = &createActions[i]
		case "kms:CreateGrant":
			createGrant = &createActions[i]
		case "backup:TagResource":
			tagResource = &createActions[i]
		}
	}

	// CreateBackupVault: unconditional
	if createVault == nil {
		t.Fatal("expected backup:CreateBackupVault in actions")
	}
	if createVault.Conditional {
		t.Errorf("CreateBackupVault should be unconditional, got conditional=%v reason=%q",
			createVault.Conditional, createVault.Condition)
	}

	// kms:CreateGrant: conditional on kms_key_arn
	if createGrant == nil {
		t.Fatal("expected kms:CreateGrant in actions")
	}
	if !createGrant.Conditional {
		t.Error("kms:CreateGrant should be conditional")
	}
	if createGrant.Condition != "kms_key_arn" {
		t.Errorf("kms:CreateGrant condition = %q, want %q", createGrant.Condition, "kms_key_arn")
	}

	// TagResource: conditional on tags
	if tagResource == nil {
		t.Fatal("expected backup:TagResource in actions")
	}
	if !tagResource.Conditional {
		t.Error("TagResource should be conditional")
	}
	if tagResource.Condition != "tags" {
		t.Errorf("TagResource condition = %q, want %q", tagResource.Condition, "tags")
	}
}

func TestParseResourceFileStructured_IfGet(t *testing.T) {
	// Test the d.Get("attribute").(bool) pattern
	src := `
package backup

func resourceVaultDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)

	if d.Get("force_destroy").(bool) {
		conn.ListRecoveryPointsByBackupVault(ctx, &backup.ListRecoveryPointsByBackupVaultInput{})
	}

	conn.DeleteBackupVault(ctx, &backup.DeleteBackupVaultInput{})
	return nil
}
`

	actions, err := ParseResourceFileStructured(src, "aws_backup_vault", "Vault")
	if err != nil {
		t.Fatalf("ParseResourceFileStructured failed: %v", err)
	}

	deleteActions := actions["delete"]

	var listPoints *ExtractedAction
	var deleteVault *ExtractedAction
	for i := range deleteActions {
		switch deleteActions[i].Action {
		case "backup:ListRecoveryPointsByBackupVault":
			listPoints = &deleteActions[i]
		case "backup:DeleteBackupVault":
			deleteVault = &deleteActions[i]
		}
	}

	if listPoints == nil {
		t.Fatal("expected ListRecoveryPointsByBackupVault")
	}
	if !listPoints.Conditional {
		t.Error("ListRecoveryPointsByBackupVault should be conditional")
	}
	if listPoints.Condition != "force_destroy" {
		t.Errorf("condition = %q, want force_destroy", listPoints.Condition)
	}

	// DeleteBackupVault: unconditional (outside the if block)
	if deleteVault == nil {
		t.Fatal("expected DeleteBackupVault")
	}
	if deleteVault.Conditional {
		t.Error("DeleteBackupVault should be unconditional")
	}
}

func TestExtractConditionAttribute(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{`if v, ok := d.GetOk("kms_key_arn"); ok { foo() }`, "kms_key_arn"},
		{`if _, ok := d.GetOk("tags"); ok { foo() }`, "tags"},
		{`if d.Get("force_destroy").(bool) { foo() }`, "force_destroy"},
		{`if err != nil { foo() }`, ""},
		{`if d.HasChangesExcept("tags") { foo() }`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			// Parse the if-statement from Go source
			src := "package x\nfunc f() {\n" + tt.src + "\n}"
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			var got string
			ast.Inspect(f, func(n ast.Node) bool {
				if ifStmt, ok := n.(*ast.IfStmt); ok {
					got = extractConditionAttribute(ifStmt)
					return false
				}
				return true
			})

			if got != tt.want {
				t.Errorf("extractConditionAttribute = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseResourceFile_IAMRole_Helpers(t *testing.T) {
	src := `
package iam

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
)

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	input := &iam.CreateRoleInput{RoleName: aws.String(name)}
	output, err := retryCreateRole(ctx, conn, input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating IAM Role: %s", err)
	}
	_ = output
	d.SetId("test")
	return append(diags, resourceRoleRead(ctx, d, meta)...)
}

func retryCreateRole(ctx context.Context, conn *iam.Client, input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	return conn.CreateRole(ctx, input)
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	output, err := findRoleByName(ctx, conn, d.Id())
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading IAM Role: %s", err)
	}
	_ = output
	return nil
}

func findRoleByName(ctx context.Context, conn *iam.Client, id string) (*iam.Role, error) {
	return findRole(ctx, conn, id)
}

func findRole(ctx context.Context, conn *iam.Client, id string) (*iam.Role, error) {
	return conn.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(id)})
}
`
	actions, err := ParseResourceFile(src, "aws_iam_role", "Role")
	if err != nil {
		t.Fatalf("ParseResourceFile failed: %v", err)
	}

	createActions := actions["create"]
	if !containsAction(createActions, "iam:CreateRole") {
		t.Errorf("create: expected iam:CreateRole (followed through retryCreateRole helper), got %v", createActions)
	}
	// Create returns resourceRoleRead → should include GetRole from read chain
	if !containsAction(createActions, "iam:GetRole") {
		t.Errorf("create: expected iam:GetRole (followed through findRoleByName → findRole → GetRole chain + return following), got %v", createActions)
	}
	t.Logf("IAM role create actions: %v", createActions)
}

func TestParseResourceFile_ElastiCache_Helpers(t *testing.T) {
	src := `
package elasticache

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
)

func resourceClusterCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ElastiCacheClient(ctx)
	input := &elasticache.CreateCacheClusterInput{CacheClusterId: aws.String(id)}
	clusterID, _, err := createCacheCluster(ctx, conn, "aws", input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Cache Cluster: %s", err)
	}
	d.SetId(clusterID)
	return append(diags, resourceClusterRead(ctx, d, meta)...)
}

func createCacheCluster(ctx context.Context, conn *elasticache.Client, partition string, input *elasticache.CreateCacheClusterInput) (string, string, error) {
	output, err := conn.CreateCacheCluster(ctx, input)
	if err != nil {
		return "", "", err
	}
	return *output.CacheCluster.CacheClusterId, "", nil
}

func resourceClusterRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ElastiCacheClient(ctx)
	output, err := conn.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading: %s", err)
	}
	_ = output
	return nil
}

func resourceClusterDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ElastiCacheClient(ctx)
	_, err := deleteCacheCluster(ctx, conn, "aws", d.Id())
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting: %s", err)
	}
	return nil
}

func deleteCacheCluster(ctx context.Context, conn *elasticache.Client, partition, id string) error {
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
		t.Errorf("create: expected elasticache:CreateCacheCluster (followed through createCacheCluster helper), got %v", createActions)
	}

	deleteActions := actions["delete"]
	if !containsAction(deleteActions, "elasticache:DeleteCacheCluster") {
		t.Errorf("delete: expected elasticache:DeleteCacheCluster (followed through deleteCacheCluster helper), got %v", deleteActions)
	}

	t.Logf("ElastiCache create actions: %v", createActions)
	t.Logf("ElastiCache delete actions: %v", deleteActions)
}

func TestParseResourceFileStructured_ConditionalHelperCall(t *testing.T) {
	// Verifies that helper-resolved SDK actions inherit the conditional
	// context from the call site. When a CRUD function delegates to a
	// helper inside if d.GetOk("replica"), the helper's actions should
	// be marked conditional on "replica".
	src := `
package secretsmanager

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSecretCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).SecretsManagerClient(ctx)

	if _, ok := d.GetOk("replica"); ok {
		removeSecretReplicas(ctx, conn, d.Id())
	}

	return nil
}

func removeSecretReplicas(ctx context.Context, conn *secretsmanager.Client, id string) error {
	_, err := conn.RemoveRegionsFromReplication(ctx, &secretsmanager.RemoveRegionsFromReplicationInput{})
	return err
}
`

	actions, err := ParseResourceFileStructured(src, "aws_secretsmanager_secret", "Secret")
	if err != nil {
		t.Fatalf("ParseResourceFileStructured failed: %v", err)
	}

	createActions := actions["create"]

	var found bool
	for _, ea := range createActions {
		if ea.Action == "secretsmanager:RemoveRegionsFromReplication" {
			found = true
			if !ea.Conditional {
				t.Error("RemoveRegionsFromReplication should be conditional (call site inside if d.GetOk(\"replica\"))")
			}
			if ea.Condition != "replica" {
				t.Errorf("RemoveRegionsFromReplication condition = %q, want %q", ea.Condition, "replica")
			}
		}
	}
	if !found {
		t.Error("expected secretsmanager:RemoveRegionsFromReplication in create actions")
		t.Logf("create actions: %+v", createActions)
	}

	// Also verify that helpers called unconditionally don't get a spurious condition
	// (the existing IAM Role helper test covers this)
}

// traversalCoverageSrc exercises every node type the AST traversal knows how
// to descend into, plus the shapes the traversal deliberately skips. Both
// walkers (SDK call extraction and helper call discovery) run over this same
// source in the tests below, so the expectations pin one traversal's behaviour
// for both observers at once.
const traversalCoverageSrc = `package walk

import (
	"context"
)

func resourceWalkCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	var diags diag.Diagnostics
	ch := make(chan string, 1)
	modes := []string{"a", "b"}

	// BlockStmt + ExprStmt + CallExpr.
	conn.CreateBackupVault(ctx, nil)

	// AssignStmt: client assignment inside a conditional block. The outer
	// connection variable must be restored once the block ends.
	if _, ok := d.GetOk("kms_key_arn"); ok {
		kmsConn := meta.(*conns.AWSClient).KMSClient(ctx)
		kmsConn.CreateGrant(ctx, nil)
	}
	conn.TagResource(ctx, nil)

	// Nested conditionals keep the outermost guard as the reason.
	if _, ok := d.GetOk("outer"); ok {
		if _, ok := d.GetOk("inner"); ok {
			conn.PutBackupVaultAccessPolicy(ctx, nil)
		}
	}

	// else / else-if are walked inside the first guard's conditional context.
	if d.Get("primary").(bool) {
		conn.DeleteBackupVaultCopyPoint(ctx, nil)
	} else if d.Get("secondary").(bool) {
		conn.StartBackupVaultCopyPoint(ctx, nil)
	} else {
		conn.DescribeCopyPoint(ctx, nil)
	}

	// An if-statement that does not guard on d.Get/d.GetOk is not conditional.
	if err != nil {
		conn.DescribeBackupVault(ctx, nil)
	}

	// ForStmt body is walked; the init statement is not.
	for i := 0; i < 3; i++ {
		conn.ListTags(ctx, nil)
	}
	for i := startIndex(conn.ListBackupPlanTemplates(ctx, nil)); i < 3; i++ {
		_ = i
	}

	// RangeStmt body is walked; the range expression is not.
	for _, m := range modes {
		if m == "a" {
			conn.ListTagsForResource(ctx, nil)
		}
	}
	for _, m := range modeNames(conn.ListProtectedPlanTemplates(ctx, nil)) {
		_ = m
	}

	// SwitchStmt / CaseClause.
	switch modes[0] {
	case "a":
		conn.PutBackupVaultNotification(ctx, nil)
	default:
		conn.GetBackupVaultNotification(ctx, nil)
	}

	// LabeledStmt wrapping a loop; break is a no-op.
outer:
	for {
		conn.ListRecoveryPointsByBackupVault(ctx, nil)
		break outer
	}

	// DeferStmt and GoStmt.
	defer conn.DeleteBackupVault(ctx, nil)
	go conn.DescribeRegionSettings(ctx, nil)

	// AssignStmt right-hand side.
	accountSettings := conn.DescribeGlobalSettings(ctx, nil)
	_ = accountSettings

	// Call arguments are walked when the outer call is not an SDK call.
	_ = wrapError(conn.DescribeBackupVaultAccountSettings(ctx, nil))

	// SendStmt is not walked.
	ch <- conn.ListBackupVaults(ctx, nil)

	// Anonymous function bodies are not walked.
	_ = func() { conn.ListTagsForResource(ctx, nil) }

	// A call to a file-local helper; the helper's own SDK calls are resolved
	// separately by the transitive resolution pass.
	walkHelper(ctx, conn, "id")

	// ReturnStmt results are walked.
	return append(diags, wrapError(conn.GetBackupVaultAccessPolicy(ctx, nil)))
}

func walkHelper(ctx context.Context, conn *backup.Client, id string) error {
	_, err := conn.GetBackupVault(ctx, nil)
	return err
}

func startIndex(n int) int {
	return n
}

func modeNames(xs []string) []string {
	return xs
}

func wrapError(err error) error {
	return err
}
`

// TestParseResourceFileStructured_TraversalCoverage pins the exact actions the
// traversal reports for the SDK-call observer, including which shapes are
// deliberately not descended into.
func TestParseResourceFileStructured_TraversalCoverage(t *testing.T) {
	actions, err := ParseResourceFileStructured(traversalCoverageSrc, "aws_backup_vault", "Walk")
	if err != nil {
		t.Fatalf("ParseResourceFileStructured failed: %v", err)
	}

	want := []ExtractedAction{
		{Action: "backup:CreateBackupVault"},
		{Action: "kms:CreateGrant", Conditional: true, Condition: "kms_key_arn"},
		{Action: "backup:TagResource"},
		{Action: "backup:PutBackupVaultAccessPolicy", Conditional: true, Condition: "outer"},
		{Action: "backup:DeleteBackupVaultCopyPoint", Conditional: true, Condition: "primary"},
		{Action: "backup:StartBackupVaultCopyPoint", Conditional: true, Condition: "primary"},
		{Action: "backup:DescribeCopyPoint", Conditional: true, Condition: "primary"},
		{Action: "backup:DescribeBackupVault"},
		{Action: "backup:ListTags"},
		{Action: "backup:ListTagsForResource"},
		{Action: "backup:PutBackupVaultNotification"},
		{Action: "backup:GetBackupVaultNotification"},
		{Action: "backup:ListRecoveryPointsByBackupVault"},
		{Action: "backup:DeleteBackupVault"},
		{Action: "backup:DescribeRegionSettings"},
		{Action: "backup:DescribeGlobalSettings"},
		{Action: "backup:DescribeBackupVaultAccountSettings"},
		{Action: "backup:GetBackupVaultAccessPolicy"},
		{Action: "backup:GetBackupVault"},
	}

	got := actions["create"]
	if !reflect.DeepEqual(got, want) {
		t.Errorf("create actions mismatch\n got: %s\nwant: %s", formatActions(got), formatActions(want))
	}
}

func formatActions(actions []ExtractedAction) string {
	var b strings.Builder
	for i, ea := range actions {
		if i > 0 {
			b.WriteString("\n     ")
		}
		fmt.Fprintf(&b, "%s (conditional=%v reason=%q)", ea.Action, ea.Conditional, ea.Condition)
	}
	return b.String()
}

// TestWalkSkipsAnonymousFunctionBodies documents the limitation that the
// traversal does not descend into anonymous function bodies, such as the
// closure passed to tfresource.RetryWhen. SDK calls made inside such a closure
// are not reported.
func TestWalkSkipsAnonymousFunctionBodies(t *testing.T) {
	src := `package walk

func resourceVaultCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	err := tfresource.RetryWhen(ctx, timeout, func(ctx context.Context) *tf.RetryableError {
		_, err := conn.CreateBackupVault(ctx, nil)
		return tf.RetryableError(err)
	})
	_ = err
	return nil
}
`

	actions, err := ParseResourceFileStructured(src, "aws_backup_vault", "Vault")
	if err != nil {
		t.Fatalf("ParseResourceFileStructured failed: %v", err)
	}

	if got := actions["create"]; len(got) != 0 {
		t.Errorf("expected no actions from inside the anonymous function body, got %s", formatActions(got))
	}
}

const traversalHelperSrc = `package walk

func resourceWalkCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	ch := make(chan string, 1)
	modes := []string{"a", "b"}

	helperBlock(ctx, conn)

	if _, ok := d.GetOk("guard"); ok {
		helperBlock(ctx, conn)
		helperNested(ctx, conn)
	}

	if err != nil {
		helperPlain(ctx, conn)
	}

	if d.Get("primary").(bool) {
		helperBlock(ctx, conn)
	} else {
		helperPrimary(ctx, conn)
	}

	for i := 0; i < 3; i++ {
		helperLoop(ctx, conn)
	}
	for _, m := range modes {
		if m == "a" {
			helperRange(ctx, conn)
		}
	}

	switch modes[0] {
	case "a":
		helperSwitch(ctx, conn)
	default:
		helperDefault(ctx, conn)
	}

outer:
	for {
		helperLabeled(ctx, conn)
		break outer
	}

	defer helperDefer(ctx, conn)
	go helperGo(ctx, conn)

	// The outer call is not a helper call, so its arguments are walked.
	helperOuter(wrapError(helperInner(ctx, conn)))

	// Send statements and anonymous function bodies are not walked.
	ch <- helperSend(ctx, conn)
	_ = func() { helperFuncLit(ctx, conn) }

	return append(diags, wrapError(helperReturned(ctx, conn)))
}

func helperBlock(ctx context.Context, conn *backup.Client) error  { return nil }
func helperNested(ctx context.Context, conn *backup.Client) error { return nil }
func helperPlain(ctx context.Context, conn *backup.Client) error  { return nil }
func helperPrimary(ctx context.Context, conn *backup.Client) error { return nil }
func helperLoop(ctx context.Context, conn *backup.Client) error    { return nil }
func helperRange(ctx context.Context, conn *backup.Client) error   { return nil }
func helperSwitch(ctx context.Context, conn *backup.Client) error  { return nil }
func helperDefault(ctx context.Context, conn *backup.Client) error { return nil }
func helperLabeled(ctx context.Context, conn *backup.Client) error { return nil }
func helperDefer(ctx context.Context, conn *backup.Client) error   { return nil }
func helperGo(ctx context.Context, conn *backup.Client) error       { return nil }
func helperInner(ctx context.Context, conn *backup.Client) error    { return nil }
func helperSend(ctx context.Context, conn *backup.Client) error     { return nil }
func helperFuncLit(ctx context.Context, conn *backup.Client) error  { return nil }
func helperReturned(ctx context.Context, conn *backup.Client) error { return nil }

func helperOuter(ctx context.Context, err error) error { return err }
`

// TestFindHelperCalls_TraversalCoverage pins the exact helper calls reported for
// the helper observer, with the conditional reason recorded at each call site.
func TestFindHelperCalls_TraversalCoverage(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "walk.go", traversalHelperSrc, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var fd *ast.FuncDecl
	for _, decl := range f.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "resourceWalkCreate" {
			fd = d
		}
	}
	if fd == nil {
		t.Fatal("resourceWalkCreate not found")
	}

	want := []helperCall{
		{Name: "helperBlock"},
		{Name: "helperBlock", CondReason: "guard"},
		{Name: "helperNested", CondReason: "guard"},
		{Name: "helperPlain"},
		{Name: "helperBlock", CondReason: "primary"},
		{Name: "helperPrimary", CondReason: "primary"},
		{Name: "helperLoop"},
		{Name: "helperRange"},
		{Name: "helperSwitch"},
		{Name: "helperDefault"},
		{Name: "helperLabeled"},
		{Name: "helperDefer"},
		{Name: "helperGo"},
		// helperOuter is defined in the file but does not receive conn, so it
		// is not a helper call; its arguments are still walked.
		{Name: "helperInner"},
		{Name: "helperReturned"},
	}

	got := findHelperCalls(fd, "conn", f)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("helper calls mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

// plainIfReassignsConnSrc pins the connection-scope restore for if-statements
// that do NOT gate on d.GetOk or d.Get. The service of an extracted action
// comes from the mutable walk context rather than from the receiver in the
// call expression, so an unrestored client assignment inside a plain if would
// silently misattribute every later call to the wrong service.
const plainIfReassignsConnSrc = `package walk

import (
	"context"
)

func resourceWalkCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)

	if err != nil {
		kmsConn := meta.(*conns.AWSClient).KMSClient(ctx)
		kmsConn.CreateGrant(ctx, nil)
	}

	// Must still resolve to backup, not to the kms scope the block above left
	// behind. If the restore is missing this becomes kms:CreateBackupVault,
	// which is not a real IAM action and would never be satisfied by a policy.
	conn.CreateBackupVault(ctx, nil)
	return nil
}
`

func TestParseResourceFileStructured_PlainIfRestoresConnScope(t *testing.T) {
	actions, err := ParseResourceFileStructured(plainIfReassignsConnSrc, "aws_backup_vault", "Walk")
	if err != nil {
		t.Fatalf("ParseResourceFileStructured failed: %v", err)
	}

	want := []ExtractedAction{
		// Inside the plain if: kms scope is in effect, and a plain if is not a
		// conditional gate, so the action is unconditional.
		{Action: "kms:CreateGrant"},
		// After the block: conn scope must be restored.
		{Action: "backup:CreateBackupVault"},
	}

	got := actions["create"]
	if !reflect.DeepEqual(got, want) {
		t.Errorf("create actions mismatch\n got: %s\nwant: %s", formatActions(got), formatActions(want))
	}
}

func TestParseResourceFile_EventBridgeRule(t *testing.T) {
	// The provider's aws_cloudwatch_event_rule resource gets its client from
	// EventBridgeClient(ctx), typed as *eventbridge.Client. EventBridge authorizes
	// under the IAM "events" prefix, so actions must come out as events:*, not eventbridge:*.
	src := `
package eventbridge

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRuleCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).EventBridgeClient(ctx)
	_, err := conn.PutRule(ctx, &eventbridge.PutRuleInput{Name: aws.String(name)})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating EventBridge Rule: %s", err)
	}
	return append(diags, resourceRuleRead(ctx, conn, d)...)
}

func resourceRuleRead(ctx context.Context, conn *eventbridge.Client, d *schema.ResourceData) diag.Diagnostics {
	var diags diag.Diagnostics
	output, err := conn.DescribeRule(ctx, &eventbridge.DescribeRuleInput{Name: aws.String(name)})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading EventBridge Rule: %s", err)
	}
	_ = output
	return diags
}
`

	actions, err := ParseResourceFile(src, "aws_cloudwatch_event_rule", "rule")
	if err != nil {
		t.Fatalf("ParseResourceFile failed: %v", err)
	}

	createActions := actions["create"]
	if !containsAction(createActions, "events:PutRule") {
		t.Errorf("create: expected events:PutRule, got %v", createActions)
	}

	readActions := actions["read"]
	if !containsAction(readActions, "events:DescribeRule") {
		t.Errorf("read: expected events:DescribeRule, got %v", readActions)
	}

	for op, as := range actions {
		for _, a := range as {
			if strings.HasPrefix(a, "eventbridge:") {
				t.Errorf("%s: action %q uses non-existent IAM prefix \"eventbridge\", want \"events\"", op, a)
			}
		}
	}
}
