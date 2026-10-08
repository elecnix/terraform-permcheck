package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

// TestMain points the provider source cache at a directory owned by this
// test binary, so package main tests never touch the user's cache or race
// another process on it. All tests in the run share that one clone. A
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

// TestMainValidate_UsesIsolatedCache checks that validate keeps the provider
// source in the cache directory TestMain chose, and writes nothing under the
// user's home or cache directory.
func TestMainValidate_UsesIsolatedCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

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
	base := os.Getenv(provideraws.CacheDirEnv)
	if base == "" {
		t.Fatalf("%s is not set for package main tests", provideraws.CacheDirEnv)
	}
	if _, err := os.Stat(filepath.Join(base, provideraws.DefaultProviderRef, ".git")); err != nil {
		t.Errorf("provider source not cached under %s: %v", base, err)
	}
}
