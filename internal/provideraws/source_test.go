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
