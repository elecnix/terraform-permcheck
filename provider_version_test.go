package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// providerVersionNotice is the start of the line validate prints when nothing
// names the AWS provider version, so it checks against the newest one.
const providerVersionNotice = "terraform-permcheck: no AWS provider version found"

// TestValidate_ProviderVersionRepros runs the reproducer of each issue about
// the provider version the table was generated from, once with a lock file
// that pins provider 5.x and once with one that pins 6.x. The lock file sits
// in the --terraform-root directory.
func TestValidate_ProviderVersionRepros(t *testing.T) {
	const dir = "testdata/provider-version/"
	args := func(name, policy, lock string) []string {
		return []string{"validate",
			"--plan-file", dir + name + "_plan.json",
			"--policy-file", dir + policy + "_policy.json",
			"--terraform-root", dir + "lock-" + lock,
			"--cloud", "aws",
		}
	}
	cases := []planVerdictCase{
		// #198: provider 6.x reads the reserved concurrency through
		// GetFunctionConcurrency. Provider 5.x never calls it.
		{
			name: "lambda function on 5.x",
			args: args("lambda", "lambda", "v5"),
			want: []string{"All required permissions covered"},
		},
		{
			name: "lambda function on 6.x",
			args: args("lambda", "lambda", "v6"),
			gaps: true,
			want: []string{"lambda:GetFunctionConcurrency [required]", "1 distinct missing permission found."},
		},
		// #195: provider 6.x tries s3:TagResource on create and falls back
		// to PutBucketTagging when it is denied. Provider 5.x never calls
		// it. The issue's policy grants PutBucketTagging, so it passes on
		// both.
		{
			name: "tagged bucket on 5.x",
			args: args("s3", "s3", "v5"),
			want: []string{"All required permissions covered"},
		},
		{
			name: "tagged bucket on 6.x",
			args: args("s3", "s3", "v6"),
			want: []string{"All required permissions covered"},
		},
		// Without either tagging action the bucket is still short of the
		// fallback, and the report names the fallback.
		{
			name:     "tagged bucket without PutBucketTagging on 6.x",
			args:     args("s3", "s3_no_tagging", "v6"),
			gaps:     true,
			want:     []string{"s3:PutBucketTagging"},
			wantNone: []string{"s3:TagResource"},
		},
		// #196: ListSecretVersionIds is update-only in 5.x and a fallback
		// for write-only or undecryptable versions in 6.x.
		{
			name: "secret version on 5.x",
			args: args("secret", "secret", "v5"),
			want: []string{"All required permissions covered"},
		},
		{
			name: "secret version on 6.x",
			args: args("secret", "secret", "v6"),
			want: []string{"All required permissions covered"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var runErr error
			stdout, stderr := captureStreams(t, func() { runErr = run(tc.args) })
			out := stdout + stderr
			if tc.gaps != errors.Is(runErr, errGapsFound) {
				t.Fatalf("run error = %v, want gaps=%v\n%s", runErr, tc.gaps, out)
			}
			if !tc.gaps && runErr != nil {
				t.Fatalf("run error = %v\n%s", runErr, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("report lacks %q:\n%s", w, out)
				}
			}
			for _, w := range tc.wantNone {
				if strings.Contains(out, w) {
					t.Errorf("report holds %q:\n%s", w, out)
				}
			}
			if strings.Contains(out, providerVersionNotice) {
				t.Errorf("the lock file names the version, but the run printed the notice:\n%s", out)
			}
		})
	}
}

// TestValidate_ProviderVersionUnknownUsesNewest checks that a plan with no
// version information is checked against the newest provider version, and
// that the run says so once on stderr.
func TestValidate_ProviderVersionUnknownUsesNewest(t *testing.T) {
	var runErr error
	stdout, stderr := captureStreams(t, func() {
		runErr = run([]string{"validate",
			"--plan-file", "testdata/provider-version/lambda_plan.json",
			"--policy-file", "testdata/provider-version/lambda_policy.json",
			"--cloud", "aws",
		})
	})
	if !errors.Is(runErr, errGapsFound) {
		t.Fatalf("run error = %v, want gaps\n%s%s", runErr, stdout, stderr)
	}
	if !strings.Contains(stdout+stderr, "lambda:GetFunctionConcurrency") {
		t.Errorf("the newest provider calls GetFunctionConcurrency, report lacks it:\n%s%s", stdout, stderr)
	}
	if n := strings.Count(stderr, providerVersionNotice); n != 1 {
		t.Errorf("stderr holds the notice %d times, want once:\n%s", n, stderr)
	}
	if !strings.Contains(stderr, "v6.72.0") {
		t.Errorf("the notice does not name the version it used:\n%s", stderr)
	}
}

// TestValidate_ProviderVersionFromPlanConstraint checks that a plan whose
// configuration constrains the provider to one major version is checked
// against that version, without the notice.
func TestValidate_ProviderVersionFromPlanConstraint(t *testing.T) {
	var runErr error
	stdout, stderr := captureStreams(t, func() {
		runErr = run([]string{"validate",
			"--plan-file", "testdata/provider-version/lambda_constraint_plan.json",
			"--policy-file", "testdata/provider-version/lambda_policy.json",
			"--cloud", "aws",
		})
	})
	if runErr != nil {
		t.Fatalf("run error = %v, want a pass on 5.x\n%s%s", runErr, stdout, stderr)
	}
	if strings.Contains(stderr, providerVersionNotice) {
		t.Errorf("the constraint names the major version, but the run printed the notice:\n%s", stderr)
	}
}

// TestValidate_ProviderVersionStaticMode checks that static HCL mode reads the
// lock file of the root it parses.
func TestValidate_ProviderVersionStaticMode(t *testing.T) {
	for lock, want := range map[string]bool{"v5": false, "v6": true} {
		t.Run(lock, func(t *testing.T) {
			var runErr error
			stdout, stderr := captureStreams(t, func() {
				runErr = run([]string{"validate",
					"--terraform-root", "testdata/provider-version/static-" + lock,
					"--policy-file", "testdata/provider-version/lambda_policy.json",
					"--cloud", "aws",
				})
			})
			if !errors.Is(runErr, errGapsFound) {
				t.Fatalf("run error = %v, want gaps: static mode checks every operation\n%s%s", runErr, stdout, stderr)
			}
			if got := strings.Contains(stdout+stderr, "lambda:GetFunctionConcurrency"); got != want {
				t.Errorf("report holds lambda:GetFunctionConcurrency = %v, want %v:\n%s%s", got, want, stdout, stderr)
			}
			if strings.Contains(stderr, providerVersionNotice) {
				t.Errorf("the lock file names the version, but the run printed the notice:\n%s", stderr)
			}
		})
	}
}

// TestValidate_ProviderVersionFlagAndConfig checks that --aws-provider-version
// and the aws_provider_version config key choose the version, and that the
// flag overrides both the config and the lock file.
func TestValidate_ProviderVersionFlagAndConfig(t *testing.T) {
	base := []string{"validate",
		"--plan-file", "testdata/provider-version/lambda_plan.json",
		"--policy-file", "testdata/provider-version/lambda_policy.json",
		"--cloud", "aws",
	}
	config := filepath.Join(t.TempDir(), "permcheck.json")
	if err := os.WriteFile(config, []byte(`{"aws_provider_version": "5.100.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		extra []string
		gaps  bool
	}{
		{"flag picks 5.x", []string{"--aws-provider-version", "5"}, false},
		{"flag picks 6.x", []string{"--aws-provider-version", "v6.72.0"}, true},
		{"config picks 5.x", []string{"--config", config}, false},
		{"flag overrides config", []string{"--config", config, "--aws-provider-version", "6"}, true},
		{"flag overrides lock file", []string{"--terraform-root", "testdata/provider-version/lock-v6", "--aws-provider-version", "5.100.0"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var runErr error
			stdout, stderr := captureStreams(t, func() { runErr = run(append(append([]string{}, base...), tc.extra...)) })
			if errors.Is(runErr, errGapsFound) != tc.gaps || (!tc.gaps && runErr != nil) {
				t.Fatalf("run error = %v, want gaps=%v\n%s%s", runErr, tc.gaps, stdout, stderr)
			}
			if strings.Contains(stderr, providerVersionNotice) {
				t.Errorf("the version was given, but the run printed the notice:\n%s", stderr)
			}
		})
	}
}

// TestValidate_ProviderVersionFlagRejectsBadValue checks that a value that
// names no major version is a usage error.
func TestValidate_ProviderVersionFlagRejectsBadValue(t *testing.T) {
	err := run([]string{"validate",
		"--plan-file", "testdata/provider-version/lambda_plan.json",
		"--policy-file", "testdata/provider-version/lambda_policy.json",
		"--cloud", "aws",
		"--aws-provider-version", "latest",
	})
	if err == nil || errors.Is(err, errGapsFound) || !strings.Contains(err.Error(), "aws-provider-version") {
		t.Errorf("run error = %v, want a usage error naming the flag", err)
	}
}

// providerVersionLine is the start of the line validate prints to say which
// provider version it checks against and where that version came from.
const providerVersionLine = "terraform-permcheck: checking against AWS provider "

// runFrom runs validate with dir as the working directory and the plan on
// stdin, as `terraform show -json plan.tfplan | terraform-permcheck validate`
// does from a root module directory. The plan and policy paths are resolved
// before the directory changes.
func runFrom(t *testing.T, dir, plan, policy string, extra ...string) (stdout, stderr string, err error) {
	t.Helper()
	raw, readErr := os.ReadFile(plan)
	if readErr != nil {
		t.Fatal(readErr)
	}
	absPolicy, absErr := filepath.Abs(policy)
	if absErr != nil {
		t.Fatal(absErr)
	}
	t.Chdir(dir)
	args := append([]string{"validate", "--policy-file", absPolicy, "--cloud", "aws"}, extra...)
	withStdin(t, string(raw), func() {
		stdout, stderr = captureStreams(t, func() { err = run(args) })
	})
	return stdout, stderr, err
}

// TestValidate_ProviderVersionFromWorkingDirectoryLock checks a plan piped
// from a root module directory, with no flags: the lock file in the working
// directory names the version, since terraform show runs there.
func TestValidate_ProviderVersionFromWorkingDirectoryLock(t *testing.T) {
	const dir = "testdata/provider-version/"
	lockDir, err := filepath.Abs(dir + "lock-v5")
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, runErr := runFrom(t, lockDir, dir+"lambda_plan.json", dir+"lambda_policy.json")
	if runErr != nil {
		t.Fatalf("run error = %v, want a pass on 5.x\n%s%s", runErr, stdout, stderr)
	}
	if want := providerVersionLine + "v5.100.0: .terraform.lock.hcl pins 5.100.0"; !strings.Contains(stderr, want) {
		t.Errorf("stderr lacks %q:\n%s", want, stderr)
	}
}

// TestValidate_ProviderVersionRootAtRepoLockInSubdirectory checks a
// --terraform-root that names the repository root while the lock file sits
// in the root module's subdirectory. The plan JSON does not name its root
// module's directory, so the lock file of the working directory decides.
func TestValidate_ProviderVersionRootAtRepoLockInSubdirectory(t *testing.T) {
	const dir = "testdata/provider-version/"
	repo, err := filepath.Abs(dir + "repo")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("run from the root module directory", func(t *testing.T) {
		stdout, stderr, runErr := runFrom(t, filepath.Join(repo, "envs", "app"), dir+"lambda_plan.json", dir+"lambda_policy.json",
			"--plan-file", "-", "--terraform-root", repo)
		if runErr != nil {
			t.Fatalf("run error = %v, want a pass on 5.x\n%s%s", runErr, stdout, stderr)
		}
		if want := providerVersionLine + "v5.100.0: .terraform.lock.hcl pins 5.100.0"; !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	})
	t.Run("run from elsewhere", func(t *testing.T) {
		stdout, stderr, runErr := runFrom(t, t.TempDir(), dir+"lambda_plan.json", dir+"lambda_policy.json",
			"--plan-file", "-", "--terraform-root", repo)
		if !errors.Is(runErr, errGapsFound) {
			t.Fatalf("run error = %v, want the 6.x gap\n%s%s", runErr, stdout, stderr)
		}
		if !strings.Contains(stderr, providerVersionNotice) {
			t.Errorf("no lock file was found, but the run printed no notice:\n%s", stderr)
		}
	})
}

// TestValidate_ProviderVersionSourceLine checks that the run names where the
// version came from: the flag, the config, or the lock file of
// --terraform-root.
func TestValidate_ProviderVersionSourceLine(t *testing.T) {
	const dir = "testdata/provider-version/"
	config := filepath.Join(t.TempDir(), "permcheck.json")
	if err := os.WriteFile(config, []byte(`{"aws_provider_version": "5"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	base := []string{"validate", "--plan-file", dir + "lambda_plan.json", "--policy-file", dir + "lambda_policy.json", "--cloud", "aws"}
	for _, tc := range []struct {
		name  string
		extra []string
		want  string
	}{
		{"flag", []string{"--aws-provider-version", "5.100.0"}, "v5.100.0: --aws-provider-version 5.100.0"},
		{"config", []string{"--config", config}, `v5.100.0: aws_provider_version "5" in the config`},
		{"lock file under --terraform-root", []string{"--terraform-root", dir + "lock-v6"}, "v6.72.0: " + filepath.Join(dir+"lock-v6", ".terraform.lock.hcl") + " pins 6.72.0"},
		{"plan constraint", []string{"--plan-file", dir + "lambda_constraint_plan.json"}, `v5.100.0: the plan's constraint "~> 5.0"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr := captureStreams(t, func() { _ = run(append(append([]string{}, base...), tc.extra...)) })
			if n := strings.Count(stderr, providerVersionLine); n != 1 {
				t.Errorf("stderr holds the version line %d times, want once:\n%s", n, stderr)
			}
			if !strings.Contains(stderr, providerVersionLine+tc.want) {
				t.Errorf("stderr lacks %q:\n%s", providerVersionLine+tc.want, stderr)
			}
		})
	}
}
