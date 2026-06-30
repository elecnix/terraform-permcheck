package provideraws

import (
	"go/ast"
	"go/parser"
	"go/token"
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
		{"s3", ""},               // exact match, no lookup needed
		{"iam", ""},              // exact match
		{"dynamodb", ""},         // exact match
		{"cloudwatchlogs", "logs"}, // package name differs from IAM namespace
		{"s3control", "s3"},
		{"sfn", "states"},
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
