package provideraws

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
)

func TestSourceProviderParseAll(t *testing.T) {
	// Create a mock terraform-provider-aws tree with a few resource files
	dir := t.TempDir()

	// Create internal/service/backup/vault.go
	backupDir := filepath.Join(dir, "internal", "service", "backup")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		t.Fatal(err)
	}
	vaultSrc := `
package backup

import (
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func resourceVaultCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	_, err := conn.CreateBackupVault(ctx, &backup.CreateBackupVaultInput{})
	if err != nil { return nil }
	return append(diags, resourceVaultRead(ctx, d, meta)...)
}

func resourceVaultRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	output, err := conn.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{})
	if err != nil { return nil }
	_ = output
	return nil
}

func resourceVaultDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	_, err := conn.DeleteBackupVault(ctx, &backup.DeleteBackupVaultInput{})
	if err != nil { return nil }
	return nil
}
`
	if err := os.WriteFile(filepath.Join(backupDir, "vault.go"), []byte(vaultSrc), 0644); err != nil {
		t.Fatal(err)
	}

	// Create internal/service/dynamodb/table.go
	dynamoDir := filepath.Join(dir, "internal", "service", "dynamodb")
	if err := os.MkdirAll(dynamoDir, 0755); err != nil {
		t.Fatal(err)
	}
	tableSrc := `
package dynamodb

import (
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func resourceTableCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).DynamoDBClient(ctx)
	_, err := conn.CreateTable(ctx, &dynamodb.CreateTableInput{})
	if err != nil { return nil }
	return append(diags, resourceTableRead(ctx, d, meta)...)
}

func resourceTableRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).DynamoDBClient(ctx)
	output, err := conn.DescribeTable(ctx, &dynamodb.DescribeTableInput{})
	if err != nil { return nil }
	_ = output
	return nil
}
`
	if err := os.WriteFile(filepath.Join(dynamoDir, "table.go"), []byte(tableSrc), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewSourceProviderWithPath(dir)
	if err := p.Ensure(); err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}

	// Resolve backup_vault
	schema, err := p.Resolve("aws_backup_vault")
	if err != nil {
		t.Fatalf("resolve aws_backup_vault: %v", err)
	}
	createPerms := schema.GetPermissions()["create"]
	if !containsAction(createPerms, "backup:CreateBackupVault") {
		t.Errorf("create: expected backup:CreateBackupVault, got %v", createPerms)
	}
	if !containsAction(createPerms, "backup:DescribeBackupVault") {
		t.Errorf("create: expected backup:DescribeBackupVault (followed from read), got %v", createPerms)
	}
	deletePerms := schema.GetPermissions()["delete"]
	if !containsAction(deletePerms, "backup:DeleteBackupVault") {
		t.Errorf("delete: expected backup:DeleteBackupVault, got %v", deletePerms)
	}

	// Resolve dynamodb_table
	schema, err = p.Resolve("aws_dynamodb_table")
	if err != nil {
		t.Fatalf("resolve aws_dynamodb_table: %v", err)
	}
	createPerms = schema.GetPermissions()["create"]
	if !containsAction(createPerms, "dynamodb:CreateTable") {
		t.Errorf("create: expected dynamodb:CreateTable, got %v", createPerms)
	}
}

func TestSourceProvider_Has(t *testing.T) {
	dir := t.TempDir()
	dynamoDir := filepath.Join(dir, "internal", "service", "dynamodb")
	if err := os.MkdirAll(dynamoDir, 0755); err != nil {
		t.Fatal(err)
	}
	src := `
package dynamodb

import (
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func resourceTableCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).DynamoDBClient(ctx)
	_, err := conn.CreateTable(ctx, &dynamodb.CreateTableInput{})
	if err != nil { return nil }
	return nil
}
`
	if err := os.WriteFile(filepath.Join(dynamoDir, "table.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewSourceProviderWithPath(dir)
	if p.Has("aws_dynamodb_table") != true {
		t.Error("expected Has to return true for aws_dynamodb_table")
	}
	if p.Has("aws_nonexistent_resource") != false {
		t.Error("expected Has to return false for nonexistent resource")
	}
}

func TestSourceProvider_ImplementsCloudProvider(t *testing.T) {
	var _ cloud.Provider = (*SourceProvider)(nil)
}

func TestResourceTypeFromAnnotation(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "EC2 instance annotation",
			src: `// @SDKResource("aws_instance", name="Instance")
package ec2`,
			want: "aws_instance",
		},
		{
			name: "CloudWatch log group annotation",
			src: `// @SDKResource("aws_cloudwatch_log_group", name="Log Group")
package logs`,
			want: "aws_cloudwatch_log_group",
		},
		{
			name: "IAM role annotation",
			src: `// @SDKResource("aws_iam_role", name="Role")
package iam`,
			want: "aws_iam_role",
		},
		{
			name: "Backup vault annotation",
			src: `// @SDKResource("aws_backup_vault", name="Vault")
package backup`,
			want: "aws_backup_vault",
		},
		{
			name: "no annotation falls back",
			src: `package unannotated
func resourceThingCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {}`,
			want: "",
		},
		{
			name: "annotation with spaces",
			src: `// @SDKResource("aws_s3_bucket_accelerate_configuration", name="Bucket Accelerate Configuration")
package s3`,
			want: "aws_s3_bucket_accelerate_configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resourceTypeFromAnnotation([]byte(tt.src))
			if got != tt.want {
				t.Errorf("resourceTypeFromAnnotation() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseFileAnnotationPreferred(t *testing.T) {
	// Create a mock provider tree where the file name doesn't match the terraform type
	dir := t.TempDir()

	// EC2 instance: file is ec2/ec2_instance.go but @SDKResource says aws_instance
	ec2Dir := filepath.Join(dir, "internal", "service", "ec2")
	if err := os.MkdirAll(ec2Dir, 0755); err != nil {
		t.Fatal(err)
	}
	ec2Src := `
// @SDKResource("aws_instance", name="Instance")
package ec2

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceInstanceCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).EC2Client(ctx)
	_, err := conn.RunInstances(ctx, &ec2.RunInstancesInput{})
	if err != nil { return nil }
	return append(diags, resourceInstanceRead(ctx, d, meta)...)
}

func resourceInstanceRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).EC2Client(ctx)
	output, err := conn.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil { return nil }
	_ = output
	return nil
}

func resourceInstanceDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).EC2Client(ctx)
	_, err := conn.TerminateInstances(ctx, &ec2.TerminateInstancesInput{})
	if err != nil { return nil }
	return nil
}
`
	if err := os.WriteFile(filepath.Join(ec2Dir, "ec2_instance.go"), []byte(ec2Src), 0644); err != nil {
		t.Fatal(err)
	}

	// CloudWatch Logs: file is logs/group.go but @SDKResource says aws_cloudwatch_log_group
	logsDir := filepath.Join(dir, "internal", "service", "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		t.Fatal(err)
	}
	logsSrc := `
// @SDKResource("aws_cloudwatch_log_group", name="Log Group")
package logs

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGroupCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).CloudWatchLogsClient(ctx)
	_, err := conn.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{})
	if err != nil { return nil }
	return append(diags, resourceGroupRead(ctx, d, meta)...)
}

func resourceGroupRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).CloudWatchLogsClient(ctx)
	output, err := conn.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil { return nil }
	_ = output
	return nil
}
`
	if err := os.WriteFile(filepath.Join(logsDir, "group.go"), []byte(logsSrc), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewSourceProviderWithPath(dir)
	if err := p.Ensure(); err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}

	// The EC2 instance should be resolved as aws_instance (from annotation),
	// NOT as aws_ec2_ec2_instance (from file path)
	schema, err := p.Resolve("aws_instance")
	if err != nil {
		t.Fatalf("resolve aws_instance: %v", err)
	}
	createPerms := schema.GetPermissions()["create"]
	if !containsAction(createPerms, "ec2:RunInstances") {
		t.Errorf("create: expected ec2:RunInstances, got %v", createPerms)
	}
	if !containsAction(createPerms, "ec2:DescribeInstances") {
		t.Errorf("create: expected ec2:DescribeInstances (followed from read), got %v", createPerms)
	}

	// The aws_ec2_ec2_instance path-derived type should NOT be resolvable
	if _, err := p.Resolve("aws_ec2_ec2_instance"); err == nil {
		t.Error("expected aws_ec2_ec2_instance to NOT be resolvable (annotation should override)")
	}

	// The CloudWatch log group should be resolved as aws_cloudwatch_log_group,
	// NOT as aws_logs_group
	schema, err = p.Resolve("aws_cloudwatch_log_group")
	if err != nil {
		t.Fatalf("resolve aws_cloudwatch_log_group: %v", err)
	}
	if _, err := p.Resolve("aws_logs_group"); err == nil {
		t.Error("expected aws_logs_group to NOT be resolvable (annotation should override)")
	}
}

func TestParseFileAnnotationFallback(t *testing.T) {
	// When no @SDKResource annotation exists, fall back to file-path derivation
	dir := t.TempDir()

	backupDir := filepath.Join(dir, "internal", "service", "backup")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		t.Fatal(err)
	}
	src := `
package backup

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func resourceVaultCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	_, err := conn.CreateBackupVault(ctx, &backup.CreateBackupVaultInput{})
	if err != nil { return nil }
	return nil
}
`
	if err := os.WriteFile(filepath.Join(backupDir, "vault.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewSourceProviderWithPath(dir)
	if err := p.Ensure(); err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}

	// Should resolve via file-path derivation (no annotation)
	schema, err := p.Resolve("aws_backup_vault")
	if err != nil {
		t.Fatalf("resolve aws_backup_vault: %v", err)
	}
	if schema.TypeName != "aws_backup_vault" {
		t.Errorf("expected TypeName aws_backup_vault, got %q", schema.TypeName)
	}
}
