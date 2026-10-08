package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

// TestMain points the provider source cache at a directory owned by this
// test binary, so package main tests never touch the user's cache or race
// another process on it. A default validate reads the embedded table and
// clones nothing; a test that asks for the live source shares one clone. A
// cache directory already set in the environment is kept, so a developer
// can reuse one clone across runs.
func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	if os.Getenv(provideraws.CacheDirEnv) == "" {
		dir, err := os.MkdirTemp("", "permcheck-provider-cache-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "create provider cache dir:", err)
			return 1
		}
		defer os.RemoveAll(dir)
		if err := os.Setenv(provideraws.CacheDirEnv, dir); err != nil {
			fmt.Fprintln(os.Stderr, "set provider cache dir:", err)
			return 1
		}
	}
	return m.Run()
}

// TestMainValidate_UsesIsolatedCache checks that a default validate reads the
// embedded permissions table: it clones nothing into the provider cache, and
// writes nothing under the user's home or cache directory. The test uses its
// own empty cache, since a developer may point TestMain at a populated one.
func TestMainValidate_UsesIsolatedCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv(check.ProviderSourceEnv, "")
	base := t.TempDir()
	t.Setenv(provideraws.CacheDirEnv, base)

	_ = captureStdout(t, func() {
		err := run([]string{"validate",
			"--plan-file", "testdata/plan.json",
			"--policy-file", "testdata/policy_partial.json",
			"--cloud", "aws",
			"--exit-zero",
		})
		if err != nil {
			t.Fatalf("run(validate): %v", err)
		}
	})

	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("validate wrote %q under $HOME", e.Name())
	}
	cached, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cached {
		t.Errorf("validate wrote %q to the provider cache; the embedded table should answer", e.Name())
	}
}

// TestValidate_UnknownProviderSource rejects a provider source the tool does
// not know, from the flag or from the environment.
func TestValidate_UnknownProviderSource(t *testing.T) {
	args := []string{"validate", "--plan-file", "testdata/plan.json", "--policy-file", "testdata/policy_partial.json", "--cloud", "aws"}
	if err := run(append(args, "--provider-source", "git")); err == nil || !strings.Contains(err.Error(), "provider source") {
		t.Errorf("--provider-source git: err = %v, want an unknown provider source error", err)
	}
	t.Setenv(check.ProviderSourceEnv, "git")
	if err := run(args); err == nil || !strings.Contains(err.Error(), "provider source") {
		t.Errorf("%s=git: err = %v, want an unknown provider source error", check.ProviderSourceEnv, err)
	}
}

// TestValidate_LiveSourceMatchesEmbedded runs validate on the embedded table
// and on a live parse of the provider source. Both must report the same gaps.
// The live parse clones the provider, so the test skips in -short mode.
func TestValidate_LiveSourceMatchesEmbedded(t *testing.T) {
	if testing.Short() {
		t.Skip("clones the provider source")
	}
	report := func(source string) string {
		return captureStdout(t, func() {
			err := run([]string{"validate",
				"--plan-file", "testdata/plan.json",
				"--policy-file", "testdata/policy_partial.json",
				"--cloud", "aws",
				"--format", "json",
				"--exit-zero",
				"--provider-source", source,
			})
			if err != nil {
				t.Fatalf("run(validate --provider-source %s): %v", source, err)
			}
		})
	}
	embedded, live := report("embedded"), report("live")
	if embedded != live {
		t.Errorf("reports differ\nembedded: %s\nlive:     %s", embedded, live)
	}
	base := os.Getenv(provideraws.CacheDirEnv)
	if _, err := os.Stat(filepath.Join(base, provideraws.DefaultProviderRef, ".git")); err != nil {
		t.Errorf("live source did not clone into %s: %v", base, err)
	}
}
