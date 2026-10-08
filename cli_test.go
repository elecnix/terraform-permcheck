package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withStdin runs fn with os.Stdin reading content from a pipe, as when a CI
// runner or a parent process hands the tool a pipe it may never write to.
func withStdin(t *testing.T, content string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	go func() {
		_, _ = w.WriteString(content)
		_ = w.Close()
	}()
	orig := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = orig
		_ = r.Close()
	}()
	fn()
}

// TestValidate_TerraformRootIgnoresEmptyStdinPipe checks that
// --terraform-root without --plan-file runs static HCL mode even when stdin
// is a pipe, as it is under GitLab, Jenkins and `docker run -i`.
func TestValidate_TerraformRootIgnoresEmptyStdinPipe(t *testing.T) {
	root := t.TempDir()
	out := captureStdout(t, func() {
		withStdin(t, "", func() {
			err := run([]string{"validate",
				"--terraform-root", root,
				"--policy-file", "testdata/policy_full.json",
				"--cloud", "aws",
			})
			if err != nil {
				t.Fatalf("run: %v", err)
			}
		})
	})
	// Plan mode would fail on the empty pipe, so a report means static mode.
	if out != "No resources to check.\n" {
		t.Errorf("output = %q, want the static report of an empty root", out)
	}
}

// TestValidate_PlanFileDashReadsStdin checks that --plan-file - reads the
// plan from stdin, also next to --terraform-root.
func TestValidate_PlanFileDashReadsStdin(t *testing.T) {
	plan, err := os.ReadFile("testdata/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	withStdin(t, string(plan), func() {
		err := run([]string{"validate",
			"--plan-file", "-",
			"--terraform-root", t.TempDir(),
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
		})
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("run = %v, want errGapsFound from the piped plan", err)
		}
	})
}

// TestValidate_PipedPlanWithoutFlags keeps the documented
// `terraform show -json | terraform-permcheck validate` form working.
func TestValidate_PipedPlanWithoutFlags(t *testing.T) {
	plan, err := os.ReadFile("testdata/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	withStdin(t, string(plan), func() {
		err := run([]string{"validate",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
		})
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("run = %v, want errGapsFound from the piped plan", err)
		}
	})
}

// TestValidate_EmptyStdinIsNoPlanInput checks that an empty stdin pipe with
// no other plan source fails with a message that names the plan sources,
// not a JSON parse error.
func TestValidate_EmptyStdinIsNoPlanInput(t *testing.T) {
	withStdin(t, "", func() {
		err := run([]string{"validate",
			"--policy-file", "testdata/policy_full.json",
			"--cloud", "aws",
		})
		if err == nil || !strings.Contains(err.Error(), "no plan input") {
			t.Fatalf("run = %v, want a no plan input error", err)
		}
		if exitCode(err) != 2 {
			t.Errorf("exit code = %d, want 2", exitCode(err))
		}
	})
}

// TestValidate_PlanAndStateBothFromStdin checks that the plan and the state
// cannot both come from stdin, since the second read would see nothing.
func TestValidate_PlanAndStateBothFromStdin(t *testing.T) {
	withStdin(t, "{}", func() {
		err := run([]string{"validate",
			"--plan-file", "-",
			"--policy-from-state-output", "deploy_policy_json",
			"--cloud", "aws",
		})
		if err == nil || !strings.Contains(err.Error(), "stdin") {
			t.Fatalf("run = %v, want an error about stdin", err)
		}
	})
}

// TestHelp checks that every way of asking for help prints the usage to
// stdout and exits 0.
func TestHelp(t *testing.T) {
	for _, args := range [][]string{
		{"help"}, {"-h"}, {"--help"}, {"-help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var err error
			out := captureStdout(t, func() { err = run(args) })
			if err != nil || exitCode(err) != 0 {
				t.Fatalf("run(%v) = %v, want nil", args, err)
			}
			for _, want := range []string{"Usage: terraform-permcheck", "validate", "generate-permissions", "version"} {
				if !strings.Contains(out, want) {
					t.Errorf("usage lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestSubcommandHelp checks that -h on a subcommand, or help with its name,
// prints its flags to stdout and exits 0.
func TestSubcommandHelp(t *testing.T) {
	for _, args := range [][]string{
		{"validate", "-h"}, {"validate", "--help"}, {"help", "validate"},
		{"generate-permissions", "-h"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var err error
			var stderr string
			out := captureStdout(t, func() {
				stderr = captureStderr(t, func() { err = run(args) })
			})
			if err != nil || exitCode(err) != 0 {
				t.Fatalf("run(%v) = %v, want nil", args, err)
			}
			if !strings.Contains(out, "Usage: terraform-permcheck "+args[len(args)-1]) && !strings.Contains(out, "Usage: terraform-permcheck "+args[0]) {
				t.Errorf("stdout lacks the usage line:\n%s", out)
			}
			if !strings.Contains(out, "-") {
				t.Errorf("stdout lists no flags:\n%s", out)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want empty", stderr)
			}
		})
	}
}

// TestVersionFlag checks that --version prints what the version command
// prints.
func TestVersionFlag(t *testing.T) {
	for _, arg := range []string{"--version", "-version"} {
		var err error
		out := captureStdout(t, func() { err = run([]string{arg}) })
		if err != nil {
			t.Fatalf("run(%s) = %v", arg, err)
		}
		if want := "terraform-permcheck " + version + "\n"; out != want {
			t.Errorf("run(%s) printed %q, want %q", arg, out, want)
		}
	}
}

// TestNoArgsIsUsageError checks that no command prints the usage to stderr
// and exits 2.
func TestNoArgsIsUsageError(t *testing.T) {
	var err error
	stderr := captureStderr(t, func() { err = run(nil) })
	if exitCode(err) != 2 {
		t.Fatalf("run() = %v, exit code %d; want 2", err, exitCode(err))
	}
	if !strings.Contains(stderr, "Usage: terraform-permcheck") {
		t.Errorf("stderr lacks the usage:\n%s", stderr)
	}
}

// TestUnknownCommandIsUsageError checks that an unknown command exits 2.
func TestUnknownCommandIsUsageError(t *testing.T) {
	var err error
	captureStderr(t, func() { err = run([]string{"valdiate"}) })
	if exitCode(err) != 2 || !strings.Contains(err.Error(), "valdiate") {
		t.Fatalf("run(valdiate) = %v, want a usage error naming it", err)
	}
}

// TestBadFlagIsUsageError checks that an undefined flag exits 2 with the
// usage on stderr and nothing on stdout.
func TestBadFlagIsUsageError(t *testing.T) {
	var err error
	var stderr string
	out := captureStdout(t, func() {
		stderr = captureStderr(t, func() { err = run([]string{"validate", "--no-such-flag"}) })
	})
	if exitCode(err) != 2 {
		t.Fatalf("run = %v, want exit code 2", err)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	if !strings.Contains(stderr, "Usage: terraform-permcheck validate") {
		t.Errorf("stderr lacks the usage:\n%s", stderr)
	}
}

// TestLeftoverArgsAreRejected checks that a positional argument fails the
// run. The flag package stops at the first one, so the flags after it would
// otherwise be dropped without a word.
func TestLeftoverArgsAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"validate", "testdata/plan.json", "--policy-file", "testdata/policy_full.json", "--cloud", "aws"},
		{"validate", "--plan-file", "testdata/plan.json", "--policy-file", "testdata/policy_full.json", "--cloud", "aws", "extra"},
		{"generate-permissions", "extra"},
		{"version", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var err error
			captureStderr(t, func() { err = run(args) })
			if exitCode(err) != 2 {
				t.Fatalf("run = %v, want exit code 2", err)
			}
			if !strings.Contains(err.Error(), "unexpected argument") {
				t.Errorf("error = %v, want it to name the unexpected argument", err)
			}
		})
	}
}

// TestExitCode pins the mapping from run's result to the process exit code.
func TestExitCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{nil, 0},
		{errGapsFound, 1},
		{errors.New("bad input"), 2},
	} {
		if got := exitCode(tc.err); got != tc.want {
			t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

// staticModeArgs runs static HCL mode on an empty root.
func staticModeArgs(t *testing.T) []string {
	return []string{"validate",
		"--terraform-root", t.TempDir(),
		"--policy-file", "testdata/policy_full.json",
		"--cloud", "aws",
	}
}

// TestValidate_TerraformRootWarnsOnPipedStdin checks that static HCL mode
// warns when stdin is a pipe, since a user may pipe a plan and expect it to
// be checked. The warning must not need a read of stdin, so an open pipe
// cannot hang the run.
func TestValidate_TerraformRootWarnsOnPipedStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() // left open: nobody writes to it
	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig; r.Close() }()

	var runErr error
	stderr := captureStderr(t, func() {
		captureStdout(t, func() { runErr = run(staticModeArgs(t)) })
	})
	if runErr != nil {
		t.Fatalf("run: %v", runErr)
	}
	if !strings.Contains(stderr, "stdin is ignored") || !strings.Contains(stderr, "--plan-file -") {
		t.Errorf("stderr = %q, want a warning that names --plan-file -", stderr)
	}
}

// TestValidate_TerraformRootQuietOnEmptyStdin checks that static HCL mode
// does not warn when stdin is /dev/null or an empty file, as in the action
// and on CI runners.
func TestValidate_TerraformRootQuietOnEmptyStdin(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{os.DevNull, empty} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			orig := os.Stdin
			os.Stdin = f
			defer func() { os.Stdin = orig; f.Close() }()

			var runErr error
			stderr := captureStderr(t, func() {
				captureStdout(t, func() { runErr = run(staticModeArgs(t)) })
			})
			if runErr != nil {
				t.Fatalf("run: %v", runErr)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want empty", stderr)
			}
		})
	}
}
