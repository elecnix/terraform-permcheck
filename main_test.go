package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
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

// TestValidate_ExcludeAllClearsExit verifies that when every gap is excluded the
// run exits 0 even without --exit-zero.
func TestValidate_ExcludeAllClearsExit(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), `{"exclude":[{"permission":"dynamodb:*"},{"permission":"iam:*"}]}`)

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
	writeConfig(t, dir, `{"exclude":[{"permission":"dynamodb:*"},{"permission":"iam:*"}]}`)

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
