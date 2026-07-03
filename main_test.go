package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn while capturing everything written to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

// TestVersionCommand ensures the `version` subcommand prints the binary name
// that `go install github.com/elecnix/terraform-permcheck@latest` actually
// produces (the module's last path element), not a mismatched short name.
func TestVersionCommand(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run([]string{"version"}); err != nil {
			t.Fatalf("run(version): %v", err)
		}
	})

	want := "terraform-permcheck v0.3.0"
	if got := strings.TrimSpace(out); got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

// TestValidate_ExitZero ensures --exit-zero makes the command return nil
// instead of errGapsFound when permission gaps exist.
func TestValidate_ExitZero(t *testing.T) {
	err := run([]string{"validate",
		"--plan-file", "testdata/plan.json",
		"--policy-file", "testdata/policy_partial.json",
		"--cloud", "aws",
		"--exit-zero",
	})
	if err != nil {
		t.Fatalf("run(validate --exit-zero): expected nil, got %v", err)
	}
}

// TestValidate_GapsReturnsErrGapsFound ensures that without --exit-zero,
// permission gaps return errGapsFound.
func TestValidate_GapsReturnsErrGapsFound(t *testing.T) {
	err := run([]string{"validate",
		"--plan-file", "testdata/plan.json",
		"--policy-file", "testdata/policy_partial.json",
		"--cloud", "aws",
	})
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("run(validate): expected errGapsFound, got %v", err)
	}
}

// TestValidate_GitHubAnnotationsFormat ensures --format github-annotations
// produces ::warning:: workflow commands.
func TestValidate_GitHubAnnotationsFormat(t *testing.T) {
	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan.json",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
			"--format", "github-annotations",
		})
		// errGapsFound is expected; we're testing the output, not the exit
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("expected errGapsFound, got %v", err)
		}
	})

	if !strings.Contains(out, "::warning title=Missing IAM permission::") {
		t.Errorf("expected ::warning lines in output, got:\n%s", out)
	}
}

// TestValidate_GitHubAnnotationsWithExitZero combines both flags.
func TestValidate_GitHubAnnotationsWithExitZero(t *testing.T) {
	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan.json",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
			"--format", "github-annotations",
			"--exit-zero",
		})
		if err != nil {
			t.Fatalf("run(validate --exit-zero): expected nil, got %v", err)
		}
	})

	if !strings.Contains(out, "::warning title=Missing IAM permission::") {
		t.Errorf("expected ::warning lines in output, got:\n%s", out)
	}
}

// TestStaticHCL_ConditionalPermissionFiltering verifies that static HCL mode
// filters conditional permissions based on parsed HCL attributes. A DynamoDB
// table without tags should NOT report dynamodb:TagResource as missing.
func TestStaticHCL_ConditionalPermissionFiltering(t *testing.T) {
	root := t.TempDir()

	// DynamoDB table WITHOUT tags.
	if err := os.WriteFile(root+"/table.tf", []byte(`
resource "aws_dynamodb_table" "items" {
  name         = "items"
  hash_key     = "id"
  attribute    { name = "id"; type = "S" }
  billing_mode = "PAY_PER_REQUEST"
}
`), 0644); err != nil {
		t.Fatalf("write table.tf: %v", err)
	}

	// Partial policy missing dynamodb:TagResource and dynamodb:UntagResource.
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:CreateTable","dynamodb:DeleteTable","dynamodb:DescribeTable","dynamodb:ListTables","dynamodb:DescribeContinuousBackups","dynamodb:DescribeTimeToLive","dynamodb:ListTagsOfResource"],"Resource":"*"}]}`
	policyPath := root + "/policy.json"
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// Use github-annotations format so output goes to stdout.
	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--terraform-root", root,
			"--policy-file", policyPath,
			"--cloud", "aws",
			"--format", "github-annotations",
		})
		if err != nil && !errors.Is(err, errGapsFound) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// tags is NOT set (only name, hash_key, attribute, billing_mode are
	// top-level attributes), so dynamodb:TagResource should be filtered.
	if strings.Contains(out, "dynamodb:TagResource") {
		t.Errorf("dynamodb:TagResource should be filtered (no tags configured)\ngot: %s", out)
	}
}

// TestStaticHCL_ConditionalPermissionPresent verifies that when a gating
// attribute (tags) IS configured, the corresponding conditional permission
// (dynamodb:TagResource) IS reported as missing.
func TestStaticHCL_ConditionalPermissionPresent(t *testing.T) {
	root := t.TempDir()

	// DynamoDB table WITH tags.
	if err := os.WriteFile(root+"/table.tf", []byte(`
resource "aws_dynamodb_table" "items" {
  name         = "items"
  hash_key     = "id"
  attribute    { name = "id"; type = "S" }
  billing_mode = "PAY_PER_REQUEST"
  tags = {
    Environment = "test"
  }
}
`), 0644); err != nil {
		t.Fatalf("write table.tf: %v", err)
	}

	// Same partial policy missing dynamodb:TagResource.
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:CreateTable","dynamodb:DeleteTable","dynamodb:DescribeTable","dynamodb:ListTables","dynamodb:DescribeContinuousBackups","dynamodb:DescribeTimeToLive","dynamodb:ListTagsOfResource"],"Resource":"*"}]}`
	policyPath := root + "/policy.json"
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--terraform-root", root,
			"--policy-file", policyPath,
			"--cloud", "aws",
			"--format", "github-annotations",
		})
		if err != nil && !errors.Is(err, errGapsFound) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// tags IS set, so dynamodb:TagResource should be reported as missing.
	if !strings.Contains(out, "dynamodb:TagResource") {
		t.Errorf("dynamodb:TagResource should be reported (tags configured)\ngot: %s", out)
	}
}

// TestValidate_InvalidFormat returns an error for unsupported format values.
func TestValidate_InvalidFormat(t *testing.T) {
	err := run([]string{"validate",
		"--plan-file", "testdata/plan.json",
		"--policy-file", "testdata/policy_partial.json",
		"--cloud", "aws",
		"--format", "invalid",
	})
	if err == nil {
		t.Fatal("expected error for invalid format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected 'unsupported format' error, got: %v", err)
	}
}
