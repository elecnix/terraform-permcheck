package provideraws

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// git runs a git command in dir with a clean identity and no signing, so
// fixture setup does not depend on the developer's global git config.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{
		"-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
		"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
		"-c", "init.defaultBranch=main",
	}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// fixtureRemote builds a local repository with two annotated tags:
// "v0.0.1" on an older commit and DefaultProviderRef on a newer one. It
// returns a file:// URL (so shallow fetches work) and the commit each tag
// points at.
func fixtureRemote(t *testing.T) (url, oldCommit, newCommit string) {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "--quiet")
	svc := filepath.Join(dir, "internal", "service", "demo")
	if err := os.MkdirAll(svc, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(svc, "demo.go"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package demo\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "--quiet", "-m", "old")
	git(t, dir, "tag", "-a", "-m", "old", "v0.0.1")
	oldCommit = git(t, dir, "rev-parse", "HEAD")

	write("package demo\n\n// new\n")
	git(t, dir, "commit", "--quiet", "-am", "new")
	git(t, dir, "tag", "-a", "-m", "new", DefaultProviderRef)
	newCommit = git(t, dir, "rev-parse", "HEAD")
	return "file://" + dir, oldCommit, newCommit
}

// newFixtureProvider returns a cloning SourceProvider that fetches from url
// into the ref's directory under base.
func newFixtureProvider(base, url string) *SourceProvider {
	p := NewSourceProvider()
	p.repoPath = filepath.Join(base, DefaultProviderRef)
	p.remoteURL = url
	return p
}

func headOf(t *testing.T, dir string) string {
	t.Helper()
	return git(t, dir, "rev-parse", "HEAD")
}

func TestDefaultCacheDir_IncludesRef(t *testing.T) {
	t.Setenv(CacheDirEnv, "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	got := defaultCacheDir()
	if filepath.Base(got) != DefaultProviderRef {
		t.Fatalf("defaultCacheDir() = %q, want last element %q", got, DefaultProviderRef)
	}
}

func TestDefaultCacheDir_EnvOverride(t *testing.T) {
	base := t.TempDir()
	t.Setenv(CacheDirEnv, base)
	want := filepath.Join(base, DefaultProviderRef)
	if got := defaultCacheDir(); got != want {
		t.Fatalf("defaultCacheDir() = %q, want %q", got, want)
	}
	if got := NewSourceProvider().repoPath; got != want {
		t.Fatalf("NewSourceProvider().repoPath = %q, want %q", got, want)
	}
}

func TestEnsureRepo_ClonesAtRef(t *testing.T) {
	url, _, newCommit := fixtureRemote(t)
	base := t.TempDir()
	p := newFixtureProvider(base, url)
	if err := p.ensureRepo(); err != nil {
		t.Fatalf("ensureRepo: %v", err)
	}
	if got := headOf(t, p.repoPath); got != newCommit {
		t.Fatalf("HEAD = %s, want %s", got, newCommit)
	}
	// No temporary or backup directories are left next to the cache.
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != DefaultProviderRef && e.Name() != DefaultProviderRef+".lock" {
			t.Errorf("unexpected leftover %q in cache base", e.Name())
		}
	}
	// A second call accepts the checkout without fetching again: point
	// both the provider and the checkout's origin somewhere unreachable and
	// expect success.
	git(t, p.repoPath, "remote", "set-url", "origin", "file:///nonexistent/remote")
	p2 := newFixtureProvider(base, "file:///nonexistent/remote")
	if err := p2.ensureRepo(); err != nil {
		t.Fatalf("second ensureRepo should reuse the cache: %v", err)
	}
}

func TestEnsureRepo_RepairsWrongRef(t *testing.T) {
	url, oldCommit, newCommit := fixtureRemote(t)
	base := t.TempDir()
	p := newFixtureProvider(base, url)
	if err := p.ensureRepo(); err != nil {
		t.Fatalf("ensureRepo: %v", err)
	}
	// Move HEAD to an older commit while the ref exists locally, as in a
	// cache cloned with tags.
	git(t, p.repoPath, "fetch", "--quiet", "origin", "+refs/tags/*:refs/tags/*")
	git(t, p.repoPath, "-c", "advice.detachedHead=false", "checkout", "--quiet", oldCommit)

	if err := newFixtureProvider(base, url).ensureRepo(); err != nil {
		t.Fatalf("ensureRepo: %v", err)
	}
	if got := headOf(t, p.repoPath); got != newCommit {
		t.Fatalf("HEAD = %s, want %s (wrong ref not repaired)", got, newCommit)
	}
}

func TestEnsureRepo_RepairsPartialCheckout(t *testing.T) {
	url, _, newCommit := fixtureRemote(t)
	base := t.TempDir()
	p := newFixtureProvider(base, url)
	if err := p.ensureRepo(); err != nil {
		t.Fatalf("ensureRepo: %v", err)
	}
	// Keep .git but delete the working tree, as an interrupted run would.
	if err := os.RemoveAll(filepath.Join(p.repoPath, "internal")); err != nil {
		t.Fatal(err)
	}

	if err := newFixtureProvider(base, url).ensureRepo(); err != nil {
		t.Fatalf("ensureRepo: %v", err)
	}
	if got := headOf(t, p.repoPath); got != newCommit {
		t.Fatalf("HEAD = %s, want %s", got, newCommit)
	}
	if _, err := os.Stat(filepath.Join(p.repoPath, "internal", "service", "demo", "demo.go")); err != nil {
		t.Fatalf("working tree not repaired: %v", err)
	}
}

func TestEnsureRepo_RepairsDirWithoutGit(t *testing.T) {
	url, _, newCommit := fixtureRemote(t)
	base := t.TempDir()
	p := newFixtureProvider(base, url)
	if err := os.MkdirAll(filepath.Join(p.repoPath, "junk"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := p.ensureRepo(); err != nil {
		t.Fatalf("ensureRepo: %v", err)
	}
	if got := headOf(t, p.repoPath); got != newCommit {
		t.Fatalf("HEAD = %s, want %s", got, newCommit)
	}
}

func TestEnsureRepo_FailedFetchLeavesNoCache(t *testing.T) {
	base := t.TempDir()
	p := newFixtureProvider(base, "file:///nonexistent/remote")
	if err := p.ensureRepo(); err == nil {
		t.Fatal("expected an error for an unreachable remote")
	}
	if _, err := os.Stat(p.repoPath); !os.IsNotExist(err) {
		t.Fatalf("cache dir should not exist after a failed fetch, stat err = %v", err)
	}
}

// helperEnv names the variables that make TestHelperEnsureRepo act as a
// child process for TestEnsureRepo_ConcurrentProcessesDoNotCorrupt.
const (
	helperEnvBase = "PERMCHECK_TEST_HELPER_BASE"
	helperEnvURL  = "PERMCHECK_TEST_HELPER_URL"
)

// TestHelperEnsureRepo is not a real test. It runs ensureRepo once when
// started as a child process, and does nothing otherwise.
func TestHelperEnsureRepo(t *testing.T) {
	base := os.Getenv(helperEnvBase)
	if base == "" {
		t.Skip("helper process only")
	}
	if err := newFixtureProvider(base, os.Getenv(helperEnvURL)).ensureRepo(); err != nil {
		fmt.Fprintln(os.Stderr, "ensureRepo:", err)
		os.Exit(3)
	}
}

func TestEnsureRepo_ConcurrentProcessesDoNotCorrupt(t *testing.T) {
	url, _, newCommit := fixtureRemote(t)
	base := t.TempDir()

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	outs := make([][]byte, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperEnsureRepo$", "-test.count=1")
			cmd.Env = append(os.Environ(), helperEnvBase+"="+base, helperEnvURL+"="+url)
			outs[i], errs[i] = cmd.CombinedOutput()
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Errorf("process %d: %v\n%s", i, errs[i], outs[i])
		}
	}
	dir := filepath.Join(base, DefaultProviderRef)
	if got := headOf(t, dir); got != newCommit {
		t.Fatalf("HEAD = %s, want %s", got, newCommit)
	}
	if status := git(t, dir, "status", "--porcelain"); status != "" {
		t.Fatalf("checkout is not clean:\n%s", status)
	}
}

// TestInstallCheckout_RestoresPreviousOnFailure reproduces the cache-loss path
// by execution: the swap is made to fail, and the previous checkout must still
// be where it was. The earlier implementation moved dir aside and removed it
// from a deferred cleanup regardless of the outcome, so this case left the
// cache empty and the next run re-cloned the provider.
func TestInstallCheckout_RestoresPreviousOnFailure(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "provider-aws")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "REVISION")
	if err := os.WriteFile(marker, []byte("previous checkout"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A tmp that does not exist makes os.Rename(tmp, dir) fail, which is the
	// step that used to strand the cache.
	missingTmp := filepath.Join(parent, "provider-aws.tmp-gone")

	if err := installCheckout(missingTmp, dir); err == nil {
		t.Fatal("expected the swap to fail when tmp does not exist")
	}

	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("previous checkout was lost after a failed swap: %v", err)
	}
	if string(got) != "previous checkout" {
		t.Errorf("previous checkout content = %q, want it restored intact", got)
	}
	if _, err := os.Lstat(missingTmp + ".old"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale directory left behind next to the cache: %v", err)
	}
}
