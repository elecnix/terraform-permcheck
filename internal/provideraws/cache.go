package provideraws

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CacheDirEnv names the environment variable that overrides the base
// directory of the provider source cache. The checkout for each ref lives in
// a subdirectory named after the ref.
const CacheDirEnv = "PERMCHECK_PROVIDER_CACHE_DIR"

// upstreamURL is the repository NewSourceProvider fetches from.
const upstreamURL = "https://github.com/hashicorp/terraform-provider-aws.git"

// cacheBaseDir returns the directory that holds one checkout per ref:
// $PERMCHECK_PROVIDER_CACHE_DIR when set, otherwise
// <user cache dir>/terraform-permcheck/provider-aws. The user cache dir is
// $XDG_CACHE_HOME or ~/.cache on Linux, and ~/Library/Caches on macOS.
func cacheBaseDir() (string, error) {
	if dir := os.Getenv(CacheDirEnv); dir != "" {
		return dir, nil
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "terraform-permcheck", "provider-aws"), nil
}

// defaultCacheDir is where the provider source for DefaultProviderRef is
// cloned. The ref is part of the path, so two refs never share a checkout.
// It returns "" when no cache directory can be found.
func defaultCacheDir() string {
	base, err := cacheBaseDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, DefaultProviderRef)
}

// ensureRepo makes sure p.repoPath holds a complete checkout of
// DefaultProviderRef.
//
// Several processes may share one cache, so the whole check-and-populate
// sequence runs under an inter-process lock on a file next to the checkout.
// A missing, partial or wrong-ref checkout is replaced by a fresh clone. The
// clone is built in a temporary sibling directory and renamed into place
// only once it is complete, so the checkout path never holds a half-written
// tree.
func (p *SourceProvider) ensureRepo() error {
	if p.skipClone {
		return nil
	}
	dir := p.repoPath
	if dir == "" {
		return fmt.Errorf("no cache directory for provider source; set %s", CacheDirEnv)
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}

	unlock, err := lockFile(dir + ".lock")
	if err != nil {
		return fmt.Errorf("lock provider cache: %w", err)
	}
	defer unlock()

	if checkoutAtRef(dir, DefaultProviderRef) {
		return nil
	}
	return p.populate(dir)
}

// checkoutAtRef reports whether dir is a git checkout whose HEAD is the
// commit that ref names and whose tracked files are all present and
// unmodified. ref is peeled with ^{commit}, because an annotated tag
// resolves to a tag object, never to the commit HEAD points at.
func checkoutAtRef(dir, ref string) bool {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return false
	}
	want, err := gitOutput(dir, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil || want == "" {
		return false
	}
	have, err := gitOutput(dir, "rev-parse", "--verify", "--quiet", "HEAD")
	if err != nil || have != want {
		return false
	}
	status, err := gitOutput(dir, "status", "--porcelain", "--untracked-files=no")
	return err == nil && status == ""
}

// populate clones DefaultProviderRef into a temporary sibling of dir, then
// swaps it into place. The caller must hold the cache lock.
func (p *SourceProvider) populate(dir string) error {
	parent, name := filepath.Dir(dir), filepath.Base(dir)

	// Under the lock no other process is populating this ref, so any
	// temporary directory left next to it comes from an interrupted run.
	leftovers, _ := filepath.Glob(filepath.Join(parent, name+".tmp-*"))
	for _, d := range leftovers {
		_ = os.RemoveAll(d)
	}

	tmp, err := os.MkdirTemp(parent, name+".tmp-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp) // no-op once tmp has been renamed into place

	// Use git init + fetch + checkout instead of git clone so we can
	// buffer each command's stderr and only show it on failure. git clone
	// --branch <annotated-tag> leaks detached HEAD advice and
	// tag-not-a-commit warnings that neither --quiet nor
	// -c advice.detachedHead=false suppresses.
	steps := [][]string{
		{"-c", "init.defaultBranch=main", "init", "--quiet"},
		{"remote", "add", "origin", p.remoteURL},
		{"fetch", "--depth", "1", "--no-tags", "--quiet", "origin", DefaultProviderRef},
		// Record the ref locally so checkoutAtRef can resolve it later.
		{"update-ref", "refs/tags/" + DefaultProviderRef, "FETCH_HEAD"},
		{"-c", "advice.detachedHead=false", "checkout", "--quiet", "FETCH_HEAD"},
	}
	for _, args := range steps {
		if err := runGit(tmp, nil, args...); err != nil {
			return err
		}
	}
	if !checkoutAtRef(tmp, DefaultProviderRef) {
		return fmt.Errorf("provider checkout in %s is not at %s", tmp, DefaultProviderRef)
	}

	// Move any stale checkout aside first: rename cannot replace a
	// non-empty directory.
	if _, err := os.Lstat(dir); err == nil {
		stale := tmp + ".old"
		if err := os.Rename(dir, stale); err != nil {
			return fmt.Errorf("move stale provider checkout aside: %w", err)
		}
		defer os.RemoveAll(stale)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(tmp, dir)
}

// gitOutput runs git in dir and returns its trimmed stdout. stderr is
// discarded: callers use it for checks whose failure is an answer, not an
// error to report.
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}
