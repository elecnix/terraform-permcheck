package hcl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFile_ResourceBlocks(t *testing.T) {
	src := `
resource "aws_s3_bucket" "main" {
  bucket = "my-bucket"
}

resource "aws_backup_vault" "this" {
  name = "my-vault"
}

data "aws_iam_role" "admin" {
  name = "admin"
}
`
	blocks, err := ParseFile(src)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d: %+v", len(blocks), blocks)
	}

	expected := []ResourceBlock{
		{Mode: "resource", Type: "aws_s3_bucket", Name: "main"},
		{Mode: "resource", Type: "aws_backup_vault", Name: "this"},
		{Mode: "data", Type: "aws_iam_role", Name: "admin"},
	}

	for i, exp := range expected {
		if i >= len(blocks) {
			t.Fatalf("missing expected block %d: %+v", i, exp)
		}
		got := blocks[i]
		if got.Mode != exp.Mode || got.Type != exp.Type || got.Name != exp.Name {
			t.Errorf("block[%d] = %+v, want %+v", i, got, exp)
		}
	}
}

func TestParseFile_CommentsAreSkipped(t *testing.T) {
	src := `
resource "aws_s3_bucket" "main" {
  bucket = "my-bucket"
}

# resource "aws_backup_vault" "commented_out" {
#   name = "nope"
# }

// resource "aws_dynamodb_table" "also_commented" {
//   name = "nope"
// }

/*
resource "aws_iam_role" "block_commented" {
  name = "nope"
}
*/
`
	blocks, err := ParseFile(src)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if len(blocks) != 1 {
		t.Fatalf("expected 1 block (commented ones skipped), got %d: %+v", len(blocks), blocks)
	}
	if blocks[0].Type != "aws_s3_bucket" {
		t.Errorf("expected aws_s3_bucket, got %s", blocks[0].Type)
	}
}

func TestParseFile_NoAWSResources(t *testing.T) {
	src := `
resource "random_string" "suffix" {
  length = 8
}

locals {
  env = "prod"
}

variable "region" {
  default = "us-east-1"
}
`
	blocks, err := ParseFile(src)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// random_string is not aws_*, so the regex won't match it.
	if len(blocks) != 0 {
		t.Errorf("expected 0 blocks, got %d: %+v", len(blocks), blocks)
	}
}

func TestParseDir(t *testing.T) {
	dir := t.TempDir()

	// Create a .tf file
	tf1 := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(tf1, []byte(`
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}

resource "aws_backup_vault" "this" {
  name = "vault"
}
`), 0644); err != nil {
		t.Fatalf("write main.tf: %v", err)
	}

	// Create another .tf file
	tf2 := filepath.Join(dir, "data.tf")
	if err := os.WriteFile(tf2, []byte(`
data "aws_iam_role" "admin" {
  name = "admin"
}
`), 0644); err != nil {
		t.Fatalf("write data.tf: %v", err)
	}

	blocks, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("ParseDir failed: %v", err)
	}

	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d: %+v", len(blocks), blocks)
	}
}

func TestStripComments(t *testing.T) {
	src := `resource "aws_s3_bucket" "main" {
  # this is a comment
  bucket = "my-bucket" // inline comment
  /*
    block comment
  */
}`
	clean := stripComments(src)
	if strings.Contains(clean, "comment") {
		t.Errorf("comments not stripped: %q", clean)
	}
}
