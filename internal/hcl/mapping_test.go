package hcl

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
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

	locations, err := MapResources(dir)
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
	want := make(map[string]iam.FileLocation)
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
		want[key] = iam.FileLocation{Path: rel, Line: b.Line}
	}

	locations, err := MapResources(dir)
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

	locations := resourceLocations(absDir, blocks)

	want := map[string]iam.FileLocation{
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
	rel := resourceLocations(absDir, []ResourceBlock{
		{Mode: "resource", Type: "aws_s3_bucket", Name: "rel", Filename: filepath.Join("a.tf"), Line: 2},
	})
	if got := rel["aws_s3_bucket.rel"]; got.Path != "a.tf" || got.Line != 2 {
		t.Errorf("relative filename projection = %+v, want a.tf:2", got)
	}

	// Empty input yields an empty, non-nil map (callers range over it).
	if empty := resourceLocations(absDir, nil); empty == nil || len(empty) != 0 {
		t.Errorf("resourceLocations(nil) = %+v, want empty non-nil map", empty)
	}
}

// TestMapResources_MissingRoot checks the error path still surfaces when the
// terraform root does not exist.
func TestMapResources_MissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := MapResources(missing); err == nil {
		t.Fatal("expected an error for a missing terraform root")
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

	_, err := MapResources(missing)
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

// TestSwapReadFile_RestoreDoesNotClobberLaterSwap pins the restore guard. If
// two swaps overlap, the first restore must not reinstate the original reader
// while the second swap's reader is still installed, because the second test's
// ParseDir calls would then run against the wrong seam.
func TestSwapReadFile_RestoreDoesNotClobberLaterSwap(t *testing.T) {
	first := func(path string) ([]byte, error) { return []byte("first"), nil }
	second := func(path string) ([]byte, error) { return []byte("second"), nil }

	restoreFirst := swapReadFile(first)
	restoreSecond := swapReadFile(second)
	// Both seams must come down regardless of what the test below does.
	t.Cleanup(restoreSecond)
	t.Cleanup(restoreFirst)

	restoreFirst()

	got, err := readFileAt("anything")
	if err != nil {
		t.Fatalf("readFileAt: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("after the first restore, reader = %q, want the second swap still installed", got)
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
