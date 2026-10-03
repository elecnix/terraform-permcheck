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
	blocks, err := ParseFile("main.tf", src)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d: %+v", len(blocks), blocks)
	}

	// Check resource details including filename and line numbers.
	expected := []struct {
		Mode string
		Type string
		Name string
		Line int
	}{
		{Mode: "resource", Type: "aws_s3_bucket", Name: "main", Line: 2},
		{Mode: "resource", Type: "aws_backup_vault", Name: "this", Line: 6},
		{Mode: "data", Type: "aws_iam_role", Name: "admin", Line: 10},
	}

	for i, exp := range expected {
		if i >= len(blocks) {
			t.Fatalf("missing expected block %d: %+v", i, exp)
		}
		got := blocks[i]
		if got.Mode != exp.Mode || got.Type != exp.Type || got.Name != exp.Name {
			t.Errorf("block[%d] = %+v, want mode=%s type=%s name=%s", i, got, exp.Mode, exp.Type, exp.Name)
		}
		if got.Filename != "main.tf" {
			t.Errorf("block[%d].Filename = %q, want main.tf", i, got.Filename)
		}
		if got.Line != exp.Line {
			t.Errorf("block[%d].Line = %d, want %d", i, got.Line, exp.Line)
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
	blocks, err := ParseFile("main.tf", src)
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
	blocks, err := ParseFile("main.tf", src)
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

func TestMapResources(t *testing.T) {
	dir := t.TempDir()

	// Create main.tf with two resources
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "my-cloudtrail"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
}
`), 0644); err != nil {
		t.Fatalf("write main.tf: %v", err)
	}

	// Create another file in a subdirectory
	subDir := filepath.Join(dir, "modules", "logging")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "log.tf"), []byte(`
resource "aws_cloudwatch_log_group" "api" {
  name = "api-logs"
}
`), 0644); err != nil {
		t.Fatalf("write log.tf: %v", err)
	}

	// Create .terraform directory with a .tf file — should be skipped
	dotTfDir := filepath.Join(dir, ".terraform", "modules")
	if err := os.MkdirAll(dotTfDir, 0755); err != nil {
		t.Fatalf("mkdir .terraform: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dotTfDir, "module.tf"), []byte(`
resource "aws_iam_role" "hidden" {
  name = "should-be-skipped"
}
`), 0644); err != nil {
		t.Fatalf("write .terraform/module.tf: %v", err)
	}

	// Create a data source — should NOT appear in MapResources (only resources)
	if err := os.WriteFile(filepath.Join(dir, "data.tf"), []byte(`
data "aws_iam_role" "admin" {
  name = "admin"
}
`), 0644); err != nil {
		t.Fatalf("write data.tf: %v", err)
	}

	locations, err := MapResources(dir)
	if err != nil {
		t.Fatalf("MapResources failed: %v", err)
	}

	// Should have 3 resource entries (not the data source, not the .terraform content)
	if len(locations) != 3 {
		t.Fatalf("expected 3 locations, got %d: %+v", len(locations), locations)
	}

	// Check main.tf resources
	loc, ok := locations["aws_s3_bucket.cloudtrail"]
	if !ok {
		t.Error("missing aws_s3_bucket.cloudtrail")
	} else {
		if loc.Path != "main.tf" {
			t.Errorf("aws_s3_bucket.cloudtrail path = %q, want main.tf", loc.Path)
		}
		if loc.Line != 2 {
			t.Errorf("aws_s3_bucket.cloudtrail line = %d, want 2", loc.Line)
		}
	}

	loc, ok = locations["aws_s3_bucket_public_access_block.cloudtrail"]
	if !ok {
		t.Error("missing aws_s3_bucket_public_access_block.cloudtrail")
	} else {
		if loc.Path != "main.tf" {
			t.Errorf("aws_s3_bucket_public_access_block.cloudtrail path = %q, want main.tf", loc.Path)
		}
		if loc.Line != 6 {
			t.Errorf("aws_s3_bucket_public_access_block.cloudtrail line = %d, want 6", loc.Line)
		}
	}

	// Check subdirectory resource
	loc, ok = locations["aws_cloudwatch_log_group.api"]
	if !ok {
		t.Error("missing aws_cloudwatch_log_group.api")
	} else {
		// Path should be relative to the root
		if !strings.HasSuffix(loc.Path, "log.tf") {
			t.Errorf("aws_cloudwatch_log_group.api path = %q, want .../log.tf", loc.Path)
		}
		if loc.Line != 2 {
			t.Errorf("aws_cloudwatch_log_group.api line = %d, want 2", loc.Line)
		}
	}

	// Data source should NOT be present
	if _, ok := locations["aws_iam_role.admin"]; ok {
		t.Error("data source should not appear in MapResources")
	}

	// Hidden directory content should NOT be present
	if _, ok := locations["aws_iam_role.hidden"]; ok {
		t.Error(".terraform content should be skipped")
	}
}

func TestParseFile_Attributes(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		wantType string
		wantName string
		wantAttr []string
	}{
		{
			name: "simple attributes",
			src: `resource "aws_s3_bucket" "logs" {
  bucket = "my-bucket"
  force_destroy = true
}
`,
			wantType: "aws_s3_bucket",
			wantName: "logs",
			wantAttr: []string{"bucket", "force_destroy"},
		},
		{
			name: "nested block not extracted",
			src: `resource "aws_s3_bucket" "web" {
  bucket = "www"
  website {
    index_document = "index.html"
    error_document = "error.html"
  }
  force_destroy = true
}
`,
			wantType: "aws_s3_bucket",
			wantName: "web",
			wantAttr: []string{"bucket", "force_destroy"}, // website is a block, not an attribute
		},
		{
			name: "backup vault with access policy",
			src: `resource "aws_backup_vault" "this" {
  name = "my-vault"
  access_policy = jsonencode({...})
}
`,
			wantType: "aws_backup_vault",
			wantName: "this",
			wantAttr: []string{"name", "access_policy"},
		},
		{
			name: "string with braces",
			src: `resource "aws_s3_bucket" "docs" {
  bucket = "my-{bucket}"
  policy = jsonencode({Version = "2012-10-17"})
}
`,
			wantType: "aws_s3_bucket",
			wantName: "docs",
			wantAttr: []string{"bucket", "policy"},
		},
		{
			name: "no attributes",
			src: `resource "aws_backup_vault" "empty" {
}
`,
			wantType: "aws_backup_vault",
			wantName: "empty",
			wantAttr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks, err := ParseFile("test.tf", tt.src)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			if len(blocks) != 1 {
				t.Fatalf("expected 1 block, got %d", len(blocks))
			}
			b := blocks[0]
			if b.Type != tt.wantType || b.Name != tt.wantName {
				t.Fatalf("resource = %s.%s, want %s.%s", b.Type, b.Name, tt.wantType, tt.wantName)
			}

			if len(b.Attributes) != len(tt.wantAttr) {
				t.Fatalf("attributes = %v (len=%d), want %v (len=%d)",
					b.Attributes, len(b.Attributes), tt.wantAttr, len(tt.wantAttr))
			}
			for i, want := range tt.wantAttr {
				got := b.Attributes[i]
				if got != want {
					t.Errorf("attribute[%d] = %q, want %q", i, got, want)
				}
			}
		})
	}
}

func TestParseFile_TwoResourcesAttributes(t *testing.T) {
	src := `resource "aws_s3_bucket" "a" {
  bucket = "bucket-a"
}

resource "aws_s3_bucket" "b" {
  bucket = "bucket-b"
  website {
    index_document = "index.html"
  }
}
`
	blocks, err := ParseFile("test.tf", src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(blocks))
	}

	// First bucket: no website block
	if len(blocks[0].Attributes) != 1 || blocks[0].Attributes[0] != "bucket" {
		t.Errorf("bucket a attributes = %v, want [bucket]", blocks[0].Attributes)
	}

	// Second bucket: website is a block, not an attribute — only bucket listed
	if len(blocks[1].Attributes) != 1 || blocks[1].Attributes[0] != "bucket" {
		t.Errorf("bucket b attributes = %v, want [bucket]", blocks[1].Attributes)
	}
}
