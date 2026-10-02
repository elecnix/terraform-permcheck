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
	original := readFile
	readFile = func(path string) ([]byte, error) {
		reads = append(reads, filepath.Base(path))
		return original(path)
	}
	t.Cleanup(func() { readFile = original })
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
