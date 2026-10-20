package hcl

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeTF writes a .tf file into dir, creating parent directories as needed.
func writeTF(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// countingReadFile replaces readFile for the duration of the test and records
// every path that is actually read from disk.
func countingReadFile(t *testing.T) *[]string {
	t.Helper()
	var reads []string
	original := os.ReadFile
	restore := swapReadFile(func(path string) ([]byte, error) {
		reads = append(reads, filepath.Base(path))
		return original(path)
	})
	t.Cleanup(restore)
	return &reads
}

// TestMapResources_ReadsEachFileOnce pins the invariant the duplicated walk
// was hiding: MapResources is a projection over one parse, so each .tf file is
// read from disk exactly once per run. Hidden directories and non-.tf files
// must not be read at all.
func TestMapResources_ReadsEachFileOnce(t *testing.T) {
	dir := t.TempDir()

	writeTF(t, dir, "main.tf", `
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "my-cloudtrail"
}
`)
	writeTF(t, dir, filepath.Join("modules", "logging", "log.tf"), `
resource "aws_cloudwatch_log_group" "api" {
  name = "api-logs"
}
`)
	writeTF(t, dir, filepath.Join(".terraform", "modules", "mod", "module.tf"), `
resource "aws_iam_role" "hidden" {
  name = "should-be-skipped"
}
`)
	writeTF(t, dir, "README.md", "not terraform\n")

	reads := countingReadFile(t)

	locations, err := MapResources(dir, dir)
	if err != nil {
		t.Fatalf("MapResources failed: %v", err)
	}
	if len(locations) != 2 {
		t.Fatalf("expected 2 locations, got %d: %+v", len(locations), locations)
	}

	got := append([]string(nil), *reads...)
	sort.Strings(got)
	want := []string{"log.tf", "main.tf"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("files read = %v, want %v (each .tf file exactly once; hidden dirs and non-.tf files never read)", got, want)
	}
}

// TestMapResources_DuplicatesAgreeWithParseDir pins the other half of the
// invariant: for a tree containing duplicate type+name pairs across two files,
// the location map and the parsed blocks are views of one parse. Every entry
// in the map must come from the first matching resource block ParseDir
// produced, and nothing else may appear.
func TestMapResources_DuplicatesAgreeWithParseDir(t *testing.T) {
	dir := t.TempDir()

	// "a.tf" sorts before "b.tf", so the duplicate pair resolves to a.tf.
	writeTF(t, dir, "a.tf", `
# a shared resource name, declared twice across two files
resource "aws_s3_bucket" "dup" {
  bucket = "first"
}

data "aws_iam_role" "admin" {
  name = "admin"
}
`)
	writeTF(t, dir, "b.tf", `
resource "aws_s3_bucket" "dup" {
  bucket = "second"
}

resource "aws_s3_bucket" "unique" {
  bucket = "only-here"
}
`)

	blocks, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("ParseDir failed: %v", err)
	}
	if len(blocks) != 4 {
		t.Fatalf("ParseDir returned %d blocks, want 4: %+v", len(blocks), blocks)
	}

	// Build the expected map independently: first resource block wins.
	want := make(map[string]Location)
	for _, b := range blocks {
		if b.Mode != "resource" {
			continue
		}
		key := b.Type + "." + b.Name
		if _, exists := want[key]; exists {
			continue
		}
		rel, err := filepath.Rel(dir, b.Filename)
		if err != nil {
			t.Fatalf("rel %s: %v", b.Filename, err)
		}
		want[key] = Location{Path: rel, Line: b.Line}
	}

	locations, err := MapResources(dir, dir)
	if err != nil {
		t.Fatalf("MapResources failed: %v", err)
	}

	if len(locations) != len(want) {
		t.Fatalf("MapResources returned %d locations, want %d: %+v", len(locations), len(want), locations)
	}
	for key, wantLoc := range want {
		gotLoc, ok := locations[key]
		if !ok {
			t.Errorf("missing location for %s", key)
			continue
		}
		if gotLoc != wantLoc {
			t.Errorf("location[%s] = %+v, want %+v", key, gotLoc, wantLoc)
		}
	}

	// First-wins specifically: the duplicate resolves to a.tf line 3.
	dup, ok := locations["aws_s3_bucket.dup"]
	if !ok {
		t.Fatal("missing location for aws_s3_bucket.dup")
	}
	if dup.Path != "a.tf" || dup.Line != 3 {
		t.Errorf("duplicate aws_s3_bucket.dup = %+v, want a.tf:3 (first block wins)", dup)
	}

	// Data blocks are resources-only filtered out of the map but still parsed.
	if _, ok := locations["aws_iam_role.admin"]; ok {
		t.Error("data source must not appear in the location map")
	}
}

// TestResourceLocations_Projection checks the pure projection directly,
// including the relative-filename case.
func TestResourceLocations_Projection(t *testing.T) {
	absDir := "/root"
	blocks := []ResourceBlock{
		{Mode: "resource", Type: "aws_s3_bucket", Name: "dup", Filename: "/root/a.tf", Line: 3},
		{Mode: "resource", Type: "aws_s3_bucket", Name: "dup", Filename: "/root/b.tf", Line: 7},
		{Mode: "data", Type: "aws_iam_role", Name: "admin", Filename: "/root/a.tf", Line: 9},
		{Mode: "resource", Type: "aws_s3_bucket", Name: "nested", Filename: "/root/modules/x/x.tf", Line: 1},
	}

	locations := resourceLocations(absDir, absDir, blocks)

	want := map[string]Location{
		"aws_s3_bucket.dup":    {Path: "a.tf", Line: 3},
		"aws_s3_bucket.nested": {Path: filepath.Join("modules", "x", "x.tf"), Line: 1},
	}
	if len(locations) != len(want) {
		t.Fatalf("got %d locations, want %d: %+v", len(locations), len(want), locations)
	}
	for key, wantLoc := range want {
		if got := locations[key]; got != wantLoc {
			t.Errorf("location[%s] = %+v, want %+v", key, got, wantLoc)
		}
	}

	// Relative filenames are anchored at the walk root.
	rel := resourceLocations(absDir, absDir, []ResourceBlock{
		{Mode: "resource", Type: "aws_s3_bucket", Name: "rel", Filename: filepath.Join("a.tf"), Line: 2},
	})
	if got := rel["aws_s3_bucket.rel"]; got.Path != "a.tf" || got.Line != 2 {
		t.Errorf("relative filename projection = %+v, want a.tf:2", got)
	}

	// Empty input yields an empty, non-nil map (callers range over it).
	if empty := resourceLocations(absDir, absDir, nil); empty == nil || len(empty) != 0 {
		t.Errorf("resourceLocations(nil) = %+v, want empty non-nil map", empty)
	}
}

// TestMapResources_MissingRoot checks the error path still surfaces when the
// terraform root does not exist.
func TestMapResources_MissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := MapResources(missing, missing); err == nil {
		t.Fatal("expected an error for a missing terraform root")
	}
}

// TestMapResources_AnchorAboveRoot pins the case from issue #137: the
// terraform root is a subdirectory of the repository, so a path relative to
// the terraform root alone names a file the repository does not have. The
// anchor is the repository root, and the path is relative to it.
func TestMapResources_AnchorAboveRoot(t *testing.T) {
	repo := t.TempDir()
	root := filepath.Join(repo, "infra", "envs", "prod")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTF(t, root, "main.tf", `
resource "aws_sqs_queue" "q" {
  name = "q"
}
`)

	locations, err := MapResources(root, repo)
	if err != nil {
		t.Fatalf("MapResources failed: %v", err)
	}
	loc, ok := locations["aws_sqs_queue.q"]
	if !ok {
		t.Fatalf("no location for aws_sqs_queue.q: %+v", locations)
	}
	want := filepath.Join("infra", "envs", "prod", "main.tf")
	if loc.Path != want {
		t.Errorf("path = %q, want %q (relative to the anchor, not the terraform root)", loc.Path, want)
	}
}

// TestMapResources_AnchorEqualToRoot pins the unchanged case: the anchor is
// the terraform root, so the paths are relative to it, as they were before
// the anchor existed.
func TestMapResources_AnchorEqualToRoot(t *testing.T) {
	root := t.TempDir()
	writeTF(t, root, "main.tf", `
resource "aws_sqs_queue" "q" {
  name = "q"
}
`)

	locations, err := MapResources(root, root)
	if err != nil {
		t.Fatalf("MapResources failed: %v", err)
	}
	loc, ok := locations["aws_sqs_queue.q"]
	if !ok {
		t.Fatalf("no location for aws_sqs_queue.q: %+v", locations)
	}
	if loc.Path != "main.tf" {
		t.Errorf("path = %q, want main.tf", loc.Path)
	}
}

// TestMapResources_EmptyAnchorUsesRoot pins that a caller with no anchor
// gets the paths relative to the terraform root, as before.
func TestMapResources_EmptyAnchorUsesRoot(t *testing.T) {
	root := t.TempDir()
	writeTF(t, root, "main.tf", `
resource "aws_sqs_queue" "q" {
  name = "q"
}
`)

	locations, err := MapResources(root, "")
	if err != nil {
		t.Fatalf("MapResources failed: %v", err)
	}
	loc, ok := locations["aws_sqs_queue.q"]
	if !ok {
		t.Fatalf("no location for aws_sqs_queue.q: %+v", locations)
	}
	if loc.Path != "main.tf" {
		t.Errorf("path = %q, want main.tf (no anchor means the terraform root is the anchor)", loc.Path)
	}
}

// TestMapResources_UnrelatableAnchorFallsBack pins the fallback: when the
// anchor cannot contain the file, the path relative to the terraform root
// is used, because a ".." path cannot be resolved by a consumer that
// resolves the path against the anchor.
func TestMapResources_UnrelatableAnchorFallsBack(t *testing.T) {
	root := t.TempDir()
	writeTF(t, root, "main.tf", `
resource "aws_sqs_queue" "q" {
  name = "q"
}
`)

	// An anchor on a different tree: the root is not under it, so the
	// relative path would climb out of the anchor.
	elsewhere := filepath.Join(t.TempDir(), "other-repo")

	locations, err := MapResources(root, elsewhere)
	if err != nil {
		t.Fatalf("MapResources failed: %v", err)
	}
	loc, ok := locations["aws_sqs_queue.q"]
	if !ok {
		t.Fatalf("no location for aws_sqs_queue.q: %+v", locations)
	}
	if loc.Path != "main.tf" {
		t.Errorf("path = %q, want main.tf (the root-relative fallback)", loc.Path)
	}
	if strings.HasPrefix(loc.Path, "..") {
		t.Errorf("path = %q, want no .. segments: a consumer cannot resolve them", loc.Path)
	}
}

// TestMapRootResources_AnchorAboveRoot pins that the root-module filter
// keeps using the terraform root, whatever the anchor is, and that the paths
// use the anchor. A block in a subdirectory of the terraform root belongs to
// a module, so it is excluded no matter where the paths are anchored.
func TestMapRootResources_AnchorAboveRoot(t *testing.T) {
	repo := t.TempDir()
	root := filepath.Join(repo, "infra", "envs", "prod")
	if err := os.MkdirAll(filepath.Join(root, "modules", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTF(t, root, "main.tf", `
resource "aws_sqs_queue" "q" {
  name = "q"
}
`)
	writeTF(t, root, filepath.Join("modules", "app", "main.tf"), `
resource "aws_sqs_queue" "q" {
  name = "q"
}
`)

	locations, err := MapRootResources(root, repo)
	if err != nil {
		t.Fatalf("MapRootResources failed: %v", err)
	}
	loc, ok := locations["aws_sqs_queue.q"]
	if !ok {
		t.Fatalf("no location for aws_sqs_queue.q: %+v", locations)
	}
	// The module block must not win: the filter asks which blocks belong to
	// the root module, and that question is about the terraform root, not
	// about the anchor. The root block wins, so its path is the one the
	// anchor gives.
	want := filepath.Join("infra", "envs", "prod", "main.tf")
	if loc.Path != want {
		t.Errorf("path = %q, want %q (the root block, anchored to the repository root)", loc.Path, want)
	}
	if strings.Contains(loc.Path, "modules") {
		t.Errorf("path = %q, want the root block: a module block must be excluded", loc.Path)
	}
}

// TestRootResourceLocations_AnchorDoesNotChangeTheFilter pins the subtle
// case: the module filter is about the terraform root, so an anchor that
// makes the module block look like a root block must not let it in.
func TestRootResourceLocations_AnchorDoesNotChangeTheFilter(t *testing.T) {
	absDir := "/repo/infra/envs/prod"
	blocks := []ResourceBlock{
		// A module block, in a subdirectory of the terraform root.
		{Mode: "resource", Type: "aws_sqs_queue", Name: "q", Filename: "/repo/infra/envs/prod/modules/app/main.tf", Line: 1},
		// A root block.
		{Mode: "resource", Type: "aws_sqs_queue", Name: "root", Filename: "/repo/infra/envs/prod/main.tf", Line: 5},
	}

	// The anchor is the repository root, so the module block's path relative
	// to it is "infra/envs/prod/modules/app/main.tf" and the root block's is
	// "infra/envs/prod/main.tf". The filter must still keep only the root
	// block, so the module block is excluded.
	got := rootResourceLocations(absDir, "/repo", blocks)

	if _, ok := got["aws_sqs_queue.q"]; ok {
		t.Errorf("the module block must not be in the map: %+v", got)
	}
	loc, ok := got["aws_sqs_queue.root"]
	if !ok {
		t.Fatalf("no location for aws_sqs_queue.root: %+v", got)
	}
	want := filepath.Join("infra", "envs", "prod", "main.tf")
	if loc.Path != want {
		t.Errorf("path = %q, want %q", loc.Path, want)
	}
}

// TestRelPath pins the documented fallback: when a filename cannot be related
// to the root, relPath returns the filename it was given, not the absolute
// path built while trying. A review comment claimed the fallback returned the
// joined absolute path, so this pins which of the two it is.
func TestRelPath(t *testing.T) {
	absDir := filepath.Join(string(filepath.Separator), "repo", "infra")

	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{
			name:     "absolute path under the root becomes relative",
			filename: filepath.Join(absDir, "main.tf"),
			want:     "main.tf",
		},
		{
			name:     "absolute path in a subdirectory keeps the relative subpath",
			filename: filepath.Join(absDir, "modules", "vpc.tf"),
			want:     filepath.Join("modules", "vpc.tf"),
		},
		{
			name:     "relative path is resolved against the root, not returned verbatim",
			filename: "main.tf",
			want:     "main.tf",
		},
		{
			name:     "relative path in a subdirectory stays relative",
			filename: filepath.Join("modules", "vpc.tf"),
			want:     filepath.Join("modules", "vpc.tf"),
		},
		{
			name:     "path outside the root keeps its .. segments",
			filename: filepath.Join(string(filepath.Separator), "elsewhere", "main.tf"),
			want:     filepath.Join("..", "..", "elsewhere", "main.tf"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := relPath(absDir, tt.filename); got != tt.want {
				t.Errorf("relPath(%q, %q) = %q, want %q", absDir, tt.filename, got, tt.want)
			}
		})
	}
}

// TestRelPath_FallbackReturnsGivenFilename pins the fallback branch and the
// reachability condition that goes with it.
//
// A review comment claimed the fallback returned the absolute path relPath
// builds while trying, rather than the filename as supplied. The two are only
// distinguishable when `original != joined`, which happens solely for a
// relative filename. But a relative filename is joined onto the root first,
// which makes both operands relative, so filepath.Rel succeeds and the
// fallback is never reached. The converse holds too: the fallback is only
// reachable when the filename is already absolute, and then original == joined
// by construction. The two conditions are mutually exclusive, so the claimed
// behaviour cannot be observed.
func TestRelPath_FallbackReturnsGivenFilename(t *testing.T) {
	// Reachable fallback: a relative base cannot be related to an absolute
	// target. The filename is returned exactly as supplied.
	absFile := filepath.Join(string(filepath.Separator), "elsewhere", "vpc.tf")
	if got := relPath("relative-root", absFile); got != absFile {
		t.Errorf("fallback returned %q, want the filename as given (%q)", got, absFile)
	}

	// The case the comment named: a relative filename must come back as the
	// raw filename, never as the absolute path built while relating it. Here
	// Rel succeeds, so this exercises the success branch, not the fallback.
	relGiven := filepath.Join("modules", "vpc.tf")
	root := filepath.Join(string(filepath.Separator), "repo")
	got := relPath(root, relGiven)
	if got != relGiven {
		t.Errorf("relPath returned %q, want the raw filename %q", got, relGiven)
	}
	if filepath.IsAbs(got) {
		t.Errorf("relPath returned an absolute path %q; the doc comment promises the raw filename", got)
	}

	// Guard the premise: for the two to differ, the filename must be relative.
	// If a future change made the fallback reachable with a differing value,
	// this assertion would need revisiting, and the test above would then have
	// real teeth.
	original := relGiven
	joined := filepath.Join(root, original)
	if original == joined {
		t.Error("premise broken: relative and joined paths are identical, so the test above cannot distinguish the branches")
	}
}

// TestMapResources_MissingRootErrorContract pins the error MapResources
// returns for a root that does not exist.
//
// MapResources used to do its own walk and returned that walk's error verbatim.
// It is now a projection over ParseDir, so this guards that delegation did not
// change the error a caller sees. A review comment claimed the error text had
// changed; it had not. The expected string below was captured from the
// pre-refactor implementation.
func TestMapResources_MissingRootErrorContract(t *testing.T) {
	const missing = "/definitely/not/here"

	_, err := MapResources(missing, missing)
	if err == nil {
		t.Fatal("MapResources: expected an error for a missing root")
	}
	const want = "lstat /definitely/not/here: no such file or directory"
	if err.Error() != want {
		t.Errorf("MapResources error = %q, want %q (unchanged from the pre-refactor walk)", err.Error(), want)
	}

	// The projection must surface ParseDir's error unmodified, since that is
	// what the old walk used to return.
	_, parseErr := ParseDir(missing)
	if parseErr == nil {
		t.Fatal("ParseDir: expected an error for a missing directory")
	}
	if err.Error() != parseErr.Error() {
		t.Errorf("MapResources error %q differs from ParseDir's %q; the delegation should not rewrite it",
			err.Error(), parseErr.Error())
	}
}

// TestSwapReadFile_RestoreAlwaysReturnsToDefault pins what a restore does:
// it returns the package default reader, never the reader a previous swap had
// installed. That is the whole contract, and it is why no generation counter
// is needed — every restore has the same target, so no sequence of restores
// can leave a reader in place that the caller did not ask for.
func TestSwapReadFile_RestoreAlwaysReturnsToDefault(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "probe.tf")
	if err := os.WriteFile(probe, []byte("real contents"), 0644); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	readsReal := func() string {
		b, err := readFileAt(probe)
		if err != nil {
			t.Fatalf("readFileAt: %v", err)
		}
		return string(b)
	}

	restore := swapReadFile(func(string) ([]byte, error) { return []byte("first"), nil })
	if got := readsReal(); got != "first" {
		t.Fatalf("under the swap, reader = %q, want \"first\"", got)
	}

	// A second swap over the top, then restore the first. Violating the
	// precondition is a caller error, but the end state must still be the
	// package default and never the other swap's fake reader.
	swapReadFile(func(string) ([]byte, error) { return []byte("second"), nil })
	restore()

	if got := readsReal(); got != "real contents" {
		t.Errorf("after restore, reader = %q, want the real file contents", got)
	}

	// Restoring twice must be harmless.
	restore()
	if got := readsReal(); got != "real contents" {
		t.Errorf("after a second restore, reader = %q, want the real file contents", got)
	}
}

// TestReadFileAt_UsesTheInstalledReader is the positive control: with no
// overlapping swap the restore does put the original reader back, so a real
// file reads normally afterwards.
func TestReadFileAt_UsesTheInstalledReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.tf")
	if err := os.WriteFile(path, []byte("real contents"), 0644); err != nil {
		t.Fatalf("write probe: %v", err)
	}

	restore := swapReadFile(func(path string) ([]byte, error) { return []byte("swapped"), nil })

	got, err := readFileAt(path)
	if err != nil {
		t.Fatalf("readFileAt under the swap: %v", err)
	}
	if string(got) != "swapped" {
		t.Errorf("reader = %q, want the swapped reader", got)
	}

	restore()

	got, err = readFileAt(path)
	if err != nil {
		t.Fatalf("readFileAt after restore: %v", err)
	}
	if string(got) != "real contents" {
		t.Errorf("after restore, reader = %q, want the real file contents back", got)
	}
}

// TestRootResourceLocations keeps only the blocks of .tf files directly in
// the root, the root module. A block in a subdirectory belongs to a module
// whose address the parser cannot know.
func TestRootResourceLocations(t *testing.T) {
	absDir := "/root"
	blocks := []ResourceBlock{
		{Mode: "resource", Type: "aws_s3_bucket", Name: "a", Filename: "/root/modules/x/x.tf", Line: 1},
		{Mode: "resource", Type: "aws_s3_bucket", Name: "a", Filename: "/root/main.tf", Line: 5},
		{Mode: "resource", Type: "aws_s3_bucket", Name: "nested", Filename: "/root/modules/x/x.tf", Line: 9},
	}
	got := rootResourceLocations(absDir, absDir, blocks)
	want := map[string]Location{"aws_s3_bucket.a": {Path: "main.tf", Line: 5}}
	if len(got) != len(want) || got["aws_s3_bucket.a"] != want["aws_s3_bucket.a"] {
		t.Errorf("rootResourceLocations = %+v, want %+v", got, want)
	}
}
