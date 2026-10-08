package hcl

import (
	"fmt"
	"path/filepath"
)

// Location is where a resource block is declared.
type Location struct {
	Path string // file path relative to the terraform root
	Line int    // 1-based line number of the block
}

// MapResources walks a terraform root directory, parses all .tf files, and
// returns the file path and line number of each resource declaration, keyed
// by its type and name (e.g. "aws_s3_bucket.cloudtrail"). Only "resource"
// blocks are included (not "data" blocks). Files inside hidden directories
// (including .terraform) are skipped. When multiple resources share the same
// key (e.g. two files with identical type+name), the first one encountered
// wins. The returned paths are relative to the walk root.
//
// This is a projection over ParseDir's result, not a second walk: the tree is
// read and parsed exactly once per run, and the location map is derived from
// the same ResourceBlocks the plan-mode and static views use.
func MapResources(dir string) (map[string]Location, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve terraform root %q: %w", dir, err)
	}

	blocks, err := ParseDir(absDir)
	if err != nil {
		return nil, err
	}

	return resourceLocations(absDir, blocks), nil
}

// resourceLocations projects parsed resource blocks into the type.name →
// Location view. Blocks whose Mode is not "resource" are skipped, and
// when several blocks share a key the first one (in ParseDir's walk order)
// wins. Paths are made relative to absDir, the root ParseDir walked.
//
// It is a pure function over blocks, so it can be tested without touching
// the filesystem.
func resourceLocations(absDir string, blocks []ResourceBlock) map[string]Location {
	locations := make(map[string]Location)

	for _, b := range blocks {
		if b.Mode != "resource" {
			continue
		}
		// A block label carries no index. Readers strip the index of a plan
		// address before they look it up.
		key := b.Type + "." + b.Name
		if _, exists := locations[key]; exists {
			continue
		}
		locations[key] = Location{Path: relPath(absDir, b.Filename), Line: b.Line}
	}

	return locations
}

// MapRootResources is MapResources for the root module only: the blocks of
// the .tf files directly in dir. A block in a subdirectory belongs to a
// module, and the parser does not know which module call, and so which
// address, it has. A plan names its resources by address, so plan mode uses
// this map: a module finding then has no location rather than the location
// of a root block that shares its type and name.
func MapRootResources(dir string) (map[string]Location, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve terraform root %q: %w", dir, err)
	}
	blocks, err := ParseDir(absDir)
	if err != nil {
		return nil, err
	}
	return rootResourceLocations(absDir, blocks), nil
}

// rootResourceLocations is resourceLocations over the blocks of the files
// directly in absDir.
func rootResourceLocations(absDir string, blocks []ResourceBlock) map[string]Location {
	var root []ResourceBlock
	for _, b := range blocks {
		if filepath.Dir(relPath(absDir, b.Filename)) == "." {
			root = append(root, b)
		}
	}
	return resourceLocations(absDir, root)
}

// relPath returns filename relative to absDir, falling back to filename when
// the two cannot be related. ParseDir's block filenames come from a walk
// rooted at absDir, so they are absolute in normal use; the relative case is
// handled so the projection stays correct for any input.
func relPath(absDir, filename string) string {
	original := filename
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(absDir, filename)
	}
	rel, err := filepath.Rel(absDir, filename)
	if err != nil {
		return original
	}
	return rel
}
