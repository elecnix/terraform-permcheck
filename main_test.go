package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/report"

	"github.com/elecnix/terraform-permcheck/internal/permdata"
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

	want := "terraform-permcheck " + version
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

// --- v0.5.0 tests ---

// TestValidate_JSONFormat ensures --format json produces valid JSON with the
// expected structure and status fields.
func TestValidate_JSONFormat(t *testing.T) {
	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan.json",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
			"--format", "json",
		})
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("expected errGapsFound, got %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\ngot: %s", err, out)
	}

	status, ok := result["status"].(string)
	if !ok || status != "gaps_found" {
		t.Errorf("expected status=gaps_found, got %v", result["status"])
	}

	checked, ok := result["checked"].(float64)
	if !ok || checked < 1 {
		t.Errorf("expected checked >= 1, got %v", result["checked"])
	}

	missing, ok := result["missing"].([]interface{})
	if !ok || len(missing) == 0 {
		t.Errorf("expected non-empty missing array, got %v", result["missing"])
	}
}

// TestValidate_JSONFormatSuccess ensures --format json produces status=ok when
// all permissions are covered. Uses an IAM-only plan (iam:* covers everything).
func TestValidate_JSONFormatSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	iamOnlyPlan := `{"resource_changes":[{"type":"aws_iam_role","name":"test","change":{"actions":["create"]}}]}`
	planPath := tmpDir + "/plan.json"
	if err := os.WriteFile(planPath, []byte(iamOnlyPlan), 0644); err != nil {
		t.Fatalf("write plan: %v", err)
	}

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", planPath,
			"--policy-file", "testdata/policy_full.json",
			"--cloud", "aws",
			"--format", "json",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\ngot: %s", err, out)
	}

	status, ok := result["status"].(string)
	if !ok || status != "ok" {
		t.Errorf("expected status=ok, got %v", result["status"])
	}
}

// TestValidate_JSONWithExitZero ensures --format json with --exit-zero returns
// nil and produces valid JSON.
func TestValidate_JSONWithExitZero(t *testing.T) {
	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan.json",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
			"--format", "json",
			"--exit-zero",
		})
		if err != nil {
			t.Fatalf("run(validate --exit-zero): expected nil, got %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\ngot: %s", err, out)
	}

	if result["status"] != "gaps_found" {
		t.Errorf("expected status=gaps_found, got %v", result["status"])
	}
}

// TestValidate_TerraformRootWithPlanFile verifies that --terraform-root is no
// longer mutually exclusive with --plan-file. It should run in plan mode with
// location annotations enabled.
func TestValidate_TerraformRootWithPlanFile(t *testing.T) {
	err := run([]string{"validate",
		"--plan-file", "testdata/plan.json",
		"--policy-file", "testdata/policy_partial.json",
		"--cloud", "aws",
		"--terraform-root", "testdata",
		"--exit-zero",
	})
	if err != nil {
		t.Fatalf("run(validate --terraform-root --plan-file): expected nil, got %v", err)
	}
}

// TestValidate_TerraformRootWithPolicyFromPlanOutput verifies the core fix:
// --terraform-root can now coexist with --policy-from-plan-output in plan mode.
// This was the combination that caused CI to silently skip validation since
// v0.4.0.
func TestValidate_TerraformRootWithPolicyFromPlanOutput(t *testing.T) {
	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan_with_output.json",
			"--policy-from-plan-output", "deploy_policy_json",
			"--cloud", "aws",
			"--terraform-root", "testdata",
			"--format", "json",
			"--exit-zero",
		})
		if err != nil {
			t.Fatalf("run(validate --terraform-root --policy-from-plan-output): expected nil, got %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\ngot: %s", err, out)
	}

	// With policy_full (wrapped in the plan output's deploy_policy_json),
	// the wildcard "*" action should cover all permissions, giving status=ok.
	if result["status"] != "ok" {
		t.Errorf("expected status=ok (policy covers all), got %v", result["status"])
	}
}

// TestValidate_NoPlanInputWithoutTerraformRoot ensures a clear error message
// when there's no plan input and no --terraform-root.
func TestValidate_NoPlanInputWithoutTerraformRoot(t *testing.T) {
	// We can't easily test "no stdin" in unit tests since the test harness
	// itself has stdin. Instead, verify the error message format by passing
	// only --policy-file without --plan-file when stdin is a pipe. But since
	// the test runner has a real stdin, we test the empty-plan scenario via
	// an empty plan file.
	tmpFile := t.TempDir() + "/empty.json"
	if err := os.WriteFile(tmpFile, []byte(`{"resource_changes":[]}`), 0644); err != nil {
		t.Fatalf("write empty plan: %v", err)
	}

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", tmpFile,
			"--policy-file", "testdata/policy_full.json",
			"--cloud", "aws",
			"--format", "json",
		})
		if err != nil {
			t.Fatalf("unexpected error for empty plan: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status=ok for empty plan, got %v", result["status"])
	}
}

// TestStaticHCL_JSONFormat verifies that --format json works in static HCL mode.
// Uses a policy that's missing dynamodb:ListTables so we get a gap.
func TestStaticHCL_JSONFormat(t *testing.T) {
	root := t.TempDir()

	if err := os.WriteFile(root+"/table.tf", []byte(`
resource "aws_dynamodb_table" "items" {
  name         = "items"
  hash_key     = "id"
  billing_mode = "PAY_PER_REQUEST"
}
`), 0644); err != nil {
		t.Fatalf("write table.tf: %v", err)
	}

	// Missing dynamodb:ListTables — deliberately incomplete.
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:CreateTable","dynamodb:DeleteTable","dynamodb:DescribeTable"],"Resource":"*"}]}`
	policyPath := root + "/policy.json"
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--terraform-root", root,
			"--policy-file", policyPath,
			"--cloud", "aws",
			"--format", "json",
			"--exit-zero",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["status"] != "gaps_found" {
		t.Errorf("expected status=gaps_found, got %v", result["status"])
	}

	missing, ok := result["missing"].([]interface{})
	if !ok || len(missing) == 0 {
		t.Errorf("expected non-empty missing array, got %v", result["missing"])
	}
}

// TestValidate_TerraformRootPlanMutualExclusionRemoved verifies that
// --terraform-root and --plan-file can coexist (no longer mutually exclusive).
func TestValidate_TerraformRootPlanMutualExclusionRemoved(t *testing.T) {
	err := run([]string{"validate",
		"--plan-file", "testdata/plan.json",
		"--terraform-root", "testdata",
		"--policy-file", "testdata/policy_full.json",
		"--cloud", "aws",
		"--exit-zero",
	})
	if err != nil {
		t.Fatalf("expected nil (mutual exclusion removed), got %v", err)
	}
}

// --- config-based permission exclusion (issue #43) ---

// captureStderr runs fn while capturing everything written to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()

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

// writeConfig writes a permcheck config file into dir and returns its path.
func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	p := dir + "/permcheck.json"
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// TestValidate_ExcludeSuppressesGap verifies an excluded permission drops out of
// the missing set while unrelated gaps still fail the run.
func TestValidate_ExcludeSuppressesGap(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), `{"exclude":[{"permission":"iam:GetRolePolicy","reason":"managed elsewhere"}]}`)

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan.json",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
			"--config", cfg,
			"--format", "json",
		})
		// dynamodb gaps remain, so the run still reports gaps.
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("expected errGapsFound, got %v", err)
		}
	})

	if strings.Contains(out, "iam:GetRolePolicy") {
		t.Errorf("excluded permission iam:GetRolePolicy should not appear in missing output:\n%s", out)
	}
	// By default (no --show-excluded) there is no excluded section in JSON.
	if strings.Contains(out, "\"excluded\"") {
		t.Errorf("excluded section should be omitted without --show-excluded:\n%s", out)
	}
}

// allGapsConfig excludes every gap testdata/plan.json has against
// policy_partial.json. The dynamodb table read also looks up the account's
// default DynamoDB KMS key, but it ignores a failed lookup, so kms:DescribeKey
// is no gap.
const allGapsConfig = `{"exclude":[{"permission":"dynamodb:*"},{"permission":"iam:*"}]}`

// TestValidate_ExcludeAllClearsExit verifies that when every gap is excluded the
// run exits 0 even without --exit-zero.
func TestValidate_ExcludeAllClearsExit(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), allGapsConfig)

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan.json",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
			"--config", cfg,
			"--format", "json",
		})
		if err != nil {
			t.Fatalf("expected nil (all gaps excluded), got %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status=ok (all excluded), got %v", result["status"])
	}
}

// TestValidate_ShowExcludedJSON verifies --show-excluded surfaces excluded
// findings in JSON output with their reason.
func TestValidate_ShowExcludedJSON(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), `{"exclude":[{"permission":"iam:GetRolePolicy","reason":"managed elsewhere"}]}`)

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan.json",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
			"--config", cfg,
			"--show-excluded",
			"--format", "json",
		})
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("expected errGapsFound, got %v", err)
		}
	})

	var result FormatJSONResultShape
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(result.Excluded) != 1 {
		t.Fatalf("expected 1 excluded entry, got %d\n%s", len(result.Excluded), out)
	}
	if result.Excluded[0].ExcludedAction != "iam:GetRolePolicy" || result.Excluded[0].Reason != "managed elsewhere" {
		t.Errorf("unexpected excluded entry: %+v", result.Excluded[0])
	}
}

// FormatJSONResultShape mirrors the excluded section of the JSON output for
// assertion purposes.
type FormatJSONResultShape struct {
	Status   string `json:"status"`
	Excluded []struct {
		ExcludedAction string `json:"excluded_action"`
		Reason         string `json:"reason"`
	} `json:"excluded"`
}

// TestValidate_ShowExcludedText verifies --show-excluded prints an "Excluded
// (per config)" block to stderr in text mode.
func TestValidate_ShowExcludedText(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), `{"exclude":[{"permission":"iam:GetRolePolicy","reason":"managed elsewhere"}]}`)

	stderr := captureStderr(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan.json",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
			"--config", cfg,
			"--show-excluded",
		})
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("expected errGapsFound, got %v", err)
		}
	})

	for _, want := range []string{"Excluded (per config)", "iam:GetRolePolicy", "reason: managed elsewhere"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

// TestValidate_ConfigNotFound verifies an explicit --config path that can't be
// read is a fatal error.
func TestValidate_ConfigNotFound(t *testing.T) {
	err := run([]string{"validate",
		"--plan-file", "testdata/plan.json",
		"--policy-file", "testdata/policy_partial.json",
		"--cloud", "aws",
		"--config", "testdata/does-not-exist.json",
	})
	if err == nil || !strings.Contains(err.Error(), "load config") {
		t.Fatalf("expected 'load config' error, got %v", err)
	}
}

// TestValidate_AutoDiscoverConfig verifies ./permcheck.json is picked up
// automatically from the working directory when --config is not given.
func TestValidate_AutoDiscoverConfig(t *testing.T) {
	planAbs, err := filepath.Abs("testdata/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	policyAbs, err := filepath.Abs("testdata/policy_partial.json")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	writeConfig(t, dir, allGapsConfig)

	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", planAbs,
			"--policy-file", policyAbs,
			"--cloud", "aws",
			"--format", "json",
		})
		if err != nil {
			t.Fatalf("expected nil (auto-discovered config excludes all gaps), got %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status=ok via auto-discovered config, got %v", result["status"])
	}
}

// TestStaticHCL_ValidatesDeletePermissions verifies that static HCL mode
// (--terraform-root) validates delete and update operations, not just create.
// A policy missing kms:ScheduleKeyDeletion (delete-only permission) should
// be flagged, since the deploy role may need to destroy KMS keys.
func TestStaticHCL_ValidatesDeletePermissions(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(root+"/main.tf", []byte(`
resource "aws_kms_key" "example" {
  description = "test"
}
`), 0644); err != nil {
		t.Fatalf("write main.tf: %v", err)
	}

	// policy_create_only.json is a minimal policy that only covers
	// KMS create operations — intentionally missing delete and update perms.
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kms:CreateKey","kms:TagResource","kms:UntagResource","kms:CreateAlias","kms:DescribeKey","kms:GetKeyPolicy","kms:GetKeyRotationStatus","kms:ListResourceTags"],"Resource":"*"}]}`
	policyPath := root + "/policy.json"
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// Use --format github-annotations so output goes to stdout (capturable).
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

	// Verify the delete-specific permission is flagged.
	if !strings.Contains(out, "kms:ScheduleKeyDeletion") {
		t.Errorf("expected kms:ScheduleKeyDeletion (delete-only) to be flagged as missing\ngot: %s", out)
	}
	// Verify it's correctly classified as a delete operation.
	if !strings.Contains(out, "(delete)") {
		t.Errorf("expected (delete) operation in output\ngot: %s", out)
	}
}

// TestStaticHCL_EmptyRootSkipsPolicy verifies that static HCL mode prints the
// all-clear line for a root with no resources before it reads the policy, so
// a missing policy file is not an error there.
func TestStaticHCL_EmptyRootSkipsPolicy(t *testing.T) {
	root := t.TempDir()

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--terraform-root", root,
			"--policy-file", root + "/does-not-exist.json",
			"--cloud", "aws",
		})
		if err != nil {
			t.Fatalf("expected nil for an empty root, got %v", err)
		}
	})

	if want := "All required permissions covered (0 resource types (static HCL mode) checked).\n"; out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

// strictArgs validates the strict fixture: a queue whose ARN the plan shows
// and a table whose ARN it does not, against grants scoped to both.
func strictArgs(extra ...string) []string {
	return append([]string{"validate",
		"--plan-file", "testdata/plan_strict.json",
		"--policy-file", "testdata/policy_strict.json",
		"--cloud", "aws",
	}, extra...)
}

// TestValidate_StrictResourcesReportsUnverified verifies --strict-resources
// reports the table's scoped grant as unverified and fails the run, while the
// queue's grant, checked against its derived ARN, stays covered.
func TestValidate_StrictResourcesReportsUnverified(t *testing.T) {
	args := strictArgs("--format", "json", "--strict-resources")

	var runErr error
	out := captureStdout(t, func() { runErr = run(args) })
	if !errors.Is(runErr, errGapsFound) {
		t.Fatalf("expected errGapsFound, got %v", runErr)
	}

	var result report.JSONResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if result.Status != "gaps_found" || len(result.Missing) == 0 {
		t.Fatalf("expected unverified gaps, got %+v", result)
	}
	for _, m := range result.Missing {
		if m.ResourceType != "aws_dynamodb_table" || m.Unverified != "resource_scope" {
			t.Errorf("want only unverified dynamodb findings, got %+v", m)
		}
	}
}

// TestValidate_StrictResourcesOffByDefault verifies the same plan passes
// without the flag, since an action-only match counts as coverage.
func TestValidate_StrictResourcesOffByDefault(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run(strictArgs()); err != nil {
			t.Fatalf("expected nil without --strict-resources, got %v", err)
		}
	})
	if !strings.Contains(out, "All required permissions covered") {
		t.Errorf("expected all-clear, got %s", out)
	}
}

// TestValidate_StrictResourcesFromConfig verifies strict_resources in the
// config file turns the check on, and --strict-resources=false turns it off.
func TestValidate_StrictResourcesFromConfig(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), `{"strict_resources": true}`)
	args := strictArgs("--format", "github-annotations", "--config", cfg)

	var runErr error
	out := captureStdout(t, func() { runErr = run(args) })
	if !errors.Is(runErr, errGapsFound) {
		t.Fatalf("expected errGapsFound from config strict_resources, got %v", runErr)
	}
	if !strings.Contains(out, "::warning title=Unverified IAM permission::dynamodb:") ||
		!strings.Contains(out, "[unverified: resource scope]") {
		t.Errorf("expected unverified annotations, got %s", out)
	}
	if !strings.Contains(out, "unverified (resource scope)") {
		t.Errorf("expected the summary to count unverified findings, got %s", out)
	}

	captureStdout(t, func() { runErr = run(append(args, "--strict-resources=false")) })
	if runErr != nil {
		t.Errorf("--strict-resources=false must override the config, got %v", runErr)
	}
}

// TestStaticHCL_StrictResources verifies static HCL mode, which has no ARNs,
// reports every scoped grant as unverified under --strict-resources.
func TestStaticHCL_StrictResources(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(root+"/main.tf", []byte(`
resource "aws_sqs_queue" "orders" {
  name = "orders"
}
`), 0644); err != nil {
		t.Fatal(err)
	}
	policy, err := filepath.Abs("testdata/policy_strict.json")
	if err != nil {
		t.Fatal(err)
	}

	var runErr error
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			runErr = run([]string{"validate",
				"--terraform-root", root,
				"--policy-file", policy,
				"--cloud", "aws",
				"--strict-resources",
			})
		})
	})
	if !errors.Is(runErr, errGapsFound) {
		t.Fatalf("expected errGapsFound, got %v", runErr)
	}
	if !strings.Contains(stderr, "Unverified IAM permissions") || !strings.Contains(stderr, "sqs:DeleteQueue [required] [unverified: resource scope]") {
		t.Errorf("expected sqs:DeleteQueue unverified, got %s", stderr)
	}
	if strings.Contains(stderr, "Missing IAM permissions") {
		t.Errorf("every finding should be unverified, got %s", stderr)
	}
}

// TestValidate_APIGatewayV2ByHTTPVerb runs the plan from issue #56. API
// Gateway v2 authorizes by HTTP verb under the apigateway prefix, so a policy
// that grants the verbs covers a domain name and its API mapping.
func TestValidate_APIGatewayV2ByHTTPVerb(t *testing.T) {
	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/apigatewayv2_plan.json",
			"--policy-file", "testdata/apigatewayv2_policy.json",
			"--cloud", "aws",
			"--format", "json",
		})
		if err != nil {
			t.Errorf("expected no gaps, got %v", err)
		}
	})
	if strings.Contains(out, "apigatewayv2:") || strings.Contains(out, "CreateDomainName") {
		t.Errorf("report names an action AWS does not evaluate:\n%s", out)
	}
}

// TestValidate_CloudWatchLogsScopedGrants runs the plan from issue #54. The
// policy omits logs:CreateLogStream and grants the log-group actions on two
// other prefixes only, so both resources have a gap.
func TestValidate_CloudWatchLogsScopedGrants(t *testing.T) {
	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/logs_plan.json",
			"--policy-file", "testdata/logs_policy.json",
			"--cloud", "aws",
			"--format", "json",
		})
		if !errors.Is(err, errGapsFound) {
			t.Errorf("expected errGapsFound, got %v", err)
		}
	})

	var result struct {
		Missing []struct {
			ResourceType string `json:"resource_type"`
			Action       string `json:"missing_action"`
		} `json:"missing"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\ngot: %s", err, out)
	}
	found := map[string]bool{}
	for _, m := range result.Missing {
		found[m.ResourceType+" "+m.Action] = true
	}
	for _, want := range []string{
		"aws_cloudwatch_log_group logs:CreateLogGroup",
		"aws_cloudwatch_log_stream logs:CreateLogStream",
	} {
		if !found[want] {
			t.Errorf("expected finding %q, got:\n%s", want, out)
		}
	}
}

// needsConfig declares one need the full policy grants, one for the deploy
// principal it does not grant, and one for another principal.
const needsConfig = `{"needs":[
	{"sid":"Tables","actions":["dynamodb:DescribeTable"]},
	{"sid":"EcrImageVerification","principal":"deploy","actions":["ecr:DescribeImages"],
	 "resources":["arn:aws:ecr:us-east-1:111111111111:repository/app"],"reason":"CI verifies images"},
	{"sid":"FetchSecrets","principal":"task","actions":["secretsmanager:GetSecretValue"]}
]}`

// needsArgs validates a plan with no resource changes, so every finding
// comes from a declared need, and the policy still loads for the needs.
func needsArgs(t *testing.T, extra ...string) []string {
	dir := t.TempDir()
	planPath := dir + "/plan.json"
	if err := os.WriteFile(planPath, []byte(`{"resource_changes":[]}`), 0644); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	return append([]string{"validate",
		"--plan-file", planPath,
		"--policy-file", "testdata/policy_full.json",
		"--cloud", "aws",
		"--config", writeConfig(t, dir, needsConfig),
	}, extra...)
}

// TestValidate_NeedsReportMissing verifies a need the policy does not grant
// fails the run and is named as the source in every format.
func TestValidate_NeedsReportMissing(t *testing.T) {
	var runErr error
	out := captureStdout(t, func() { runErr = run(needsArgs(t, "--principal", "deploy", "--format", "json")) })
	if !errors.Is(runErr, errGapsFound) {
		t.Fatalf("expected errGapsFound, got %v", runErr)
	}
	var result report.JSONResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	want := report.JSONMissing{
		Need:          "EcrImageVerification",
		NeedResource:  "arn:aws:ecr:us-east-1:111111111111:repository/app",
		MissingAction: "ecr:DescribeImages",
		Class:         "[required]",
	}
	if len(result.Missing) != 1 || result.Missing[0] != want {
		t.Errorf("missing = %+v, want [%+v]", result.Missing, want)
	}

	out = captureStdout(t, func() { runErr = run(needsArgs(t, "--principal", "deploy", "--format", "github-annotations")) })
	if !strings.Contains(out, `::warning title=Missing IAM permission::ecr:DescribeImages needed by: needs "EcrImageVerification" on arn:aws:ecr:`) {
		t.Errorf("annotation does not name the need:\n%s", out)
	}
	if !strings.Contains(out, "2 declared needs") {
		t.Errorf("summary does not count the needs:\n%s", out)
	}

	stderr := captureStderr(t, func() { runErr = run(needsArgs(t, "--principal", "deploy")) })
	if !strings.Contains(stderr, `→ needs "EcrImageVerification" on arn:aws:ecr:`) {
		t.Errorf("text report does not name the need:\n%s", stderr)
	}
}

// TestValidate_NeedsWithoutPrincipal verifies only the needs without a
// principal apply when --principal is not given.
func TestValidate_NeedsWithoutPrincipal(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run(needsArgs(t)); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})
	if !strings.Contains(out, "All required permissions covered") || !strings.Contains(out, "0 resource changes, 1 declared need checked") {
		t.Errorf("unexpected output: %s", out)
	}
}

// TestValidate_NeedsUnknownPrincipal verifies a --principal no need names is
// a usage error, not a pass.
func TestValidate_NeedsUnknownPrincipal(t *testing.T) {
	err := run(needsArgs(t, "--principal", "deploi"))
	if err == nil || errors.Is(err, errGapsFound) || !strings.Contains(err.Error(), `"deploi"`) {
		t.Errorf("want an unknown principal error, got %v", err)
	}
}

// TestGeneratePermissions_FromProviderDir generates a table from a small
// provider tree twice. Both runs must write the same bytes, and the table
// must hold the tree's resource type.
func TestGeneratePermissions_FromProviderDir(t *testing.T) {
	dir := t.TempDir()
	var outs [2][]byte
	for i := range outs {
		out := filepath.Join(dir, fmt.Sprintf("permissions-%d.json", i))
		err := run([]string{"generate-permissions",
			"--provider-dir", "internal/check/testdata/provider",
			"--out", out,
		})
		if err != nil {
			t.Fatalf("run(generate-permissions): %v", err)
		}
		if outs[i], err = os.ReadFile(out); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(outs[0], outs[1]) {
		t.Error("two runs wrote different bytes")
	}
	tbl, err := permdata.Decode(outs[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tbl.Schemas["aws_backup_vault"]; !ok || len(tbl.Schemas) != 1 {
		t.Errorf("table types = %v, want only aws_backup_vault", tbl.Schemas)
	}
}

// TestGeneratePermissions_EmptyDir fails rather than writing an empty table.
func TestGeneratePermissions_EmptyDir(t *testing.T) {
	out := filepath.Join(t.TempDir(), "permissions.json")
	err := run([]string{"generate-permissions", "--provider-dir", t.TempDir(), "--out", out})
	if err == nil {
		t.Fatal("want an error for a tree with no resources")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("an output file was written despite the error")
	}
}

// unresolvedArgs validates a plan holding aws_permcheckwidget, a type no
// schema source knows. Its name has no service part, so the registry
// adapter derives no key and makes no request: the test needs no network.
func unresolvedArgs(extra ...string) []string {
	return append([]string{"validate",
		"--plan-file", "testdata/plan_unresolved.json",
		"--policy-file", "testdata/policy_full.json",
		"--cloud", "aws",
	}, extra...)
}

// TestValidate_UnresolvedTypeFails verifies that a resource type the tool
// cannot resolve fails the run and is named in the report, instead of the
// run printing the all-clear line.
func TestValidate_UnresolvedTypeFails(t *testing.T) {
	var runErr error
	stdout, stderr := captureStreams(t, func() { runErr = run(unresolvedArgs("--config", writeConfig(t, t.TempDir(), `{}`))) })
	if !errors.Is(runErr, errGapsFound) {
		t.Fatalf("expected errGapsFound, got %v", runErr)
	}
	if strings.Contains(stdout, "All required permissions covered") {
		t.Errorf("all-clear printed with an unresolved type:\n%s", stdout)
	}
	if !strings.Contains(stderr, "Unresolved resource types (1)") || !strings.Contains(stderr, "aws_permcheckwidget.w (create)") {
		t.Errorf("stderr does not name the unresolved type:\n%s", stderr)
	}
}

// TestValidate_AllowUnresolvedTypes verifies the flag and the config key let
// the run pass, that the flag overrides the config, and that the report
// still says the type was not checked.
func TestValidate_AllowUnresolvedTypes(t *testing.T) {
	allowCfg := writeConfig(t, t.TempDir(), `{"allow_unresolved_types": true}`)
	emptyCfg := writeConfig(t, t.TempDir(), `{}`)
	excludeCfg := writeConfig(t, t.TempDir(), `{"exclude":[{"permission":"*","resource":"aws_permcheckwidget","reason":"reviewed by hand"}]}`)
	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"flag", []string{"--config", emptyCfg, "--allow-unresolved-types"}, false},
		{"config", []string{"--config", allowCfg}, false},
		{"flag overrides config", []string{"--config", allowCfg, "--allow-unresolved-types=false"}, true},
		{"exclusion", []string{"--config", excludeCfg}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var runErr error
			stdout, stderr := captureStreams(t, func() { runErr = run(unresolvedArgs(tc.args...)) })
			if got := errors.Is(runErr, errGapsFound); got != tc.wantErr || (runErr != nil && !got) {
				t.Fatalf("run err = %v, want gaps %v", runErr, tc.wantErr)
			}
			if strings.Contains(stdout, "All required permissions covered") {
				t.Errorf("all-clear printed with an unresolved type:\n%s", stdout)
			}
			if !tc.wantErr && !strings.Contains(stderr, "1 resource type unresolved (allowed)") {
				t.Errorf("summary does not count the allowed type:\n%s", stderr)
			}
		})
	}
}

// TestStaticHCL_UnresolvedTypeFails verifies static HCL mode reports a type
// it cannot resolve instead of skipping it.
func TestStaticHCL_UnresolvedTypeFails(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("resource \"aws_permcheckwidget\" \"w\" {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var runErr error
	stdout := captureStdout(t, func() {
		runErr = run([]string{"validate",
			"--terraform-root", root,
			"--policy-file", "testdata/policy_full.json",
			"--cloud", "aws",
			"--config", writeConfig(t, t.TempDir(), `{}`),
			"--format", "json",
		})
	})
	if !errors.Is(runErr, errGapsFound) {
		t.Fatalf("expected errGapsFound, got %v", runErr)
	}
	var result report.JSONResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if result.Status != "gaps_found" || len(result.UnresolvedTypes) != 1 || result.UnresolvedTypes[0].ResourceType != "aws_permcheckwidget" {
		t.Errorf("result = %+v, want aws_permcheckwidget unresolved", result)
	}
	if r := result.UnresolvedTypes[0].Resources; len(r) != 1 || r[0].File != "main.tf" || r[0].Line != 1 {
		t.Errorf("resources = %+v, want main.tf:1", r)
	}
}

// TestValidate_ModuleFindingHasNoRootLocation checks that a finding in a
// module does not take the file and line of a root block that shares its
// type and name. The parser cannot tell which module call a subdirectory
// belongs to, so the module finding has no location.
func TestValidate_ModuleFindingHasNoRootLocation(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "modules", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	queue := "resource \"aws_sqs_queue\" \"q\" {\n  name = \"q\"\n}\n"
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("\n"+queue), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "modules", "app", "main.tf"), []byte(queue), 0o644); err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(root, "plan.json")
	plan := `{"resource_changes":[
		{"address":"module.app.aws_sqs_queue.q","module_address":"module.app","mode":"managed","type":"aws_sqs_queue","name":"q","change":{"actions":["create"]}}]}`
	if err := os.WriteFile(planPath, []byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"Version":"2012-10-17","Statement":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", planPath,
			"--terraform-root", root,
			"--policy-file", policyPath,
			"--cloud", "aws",
			"--format", "github-annotations",
		})
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("want errGapsFound, got %v", err)
		}
	})
	if !strings.Contains(out, "module.app.aws_sqs_queue.q (create)") {
		t.Fatalf("want a finding on the module queue, got:\n%s", out)
	}
	if strings.Contains(out, "file=") {
		t.Errorf("a module finding must have no file location, got:\n%s", out)
	}
}
