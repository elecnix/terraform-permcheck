package hcl

import (
	"fmt"
	"path/filepath"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// MapResources walks a terraform root directory, parses all .tf files, and
// returns the file path and line number of each resource declaration, keyed
// by iam.KeyOf (e.g. "aws_s3_bucket.cloudtrail"). Only "resource"
// blocks are included (not "data" blocks). Files inside hidden directories
// (including .terraform) are skipped. When multiple resources share the same
// key (e.g. two files with identical type+name), the first one encountered
// wins. The returned paths are relative to the walk root.
//
// This is a projection over ParseDir's result, not a second walk: the tree is
// read and parsed exactly once per run, and the location map is derived from
// the same ResourceBlocks the plan-mode and static views use.
func MapResources(dir string) (iam.Locations, error) {
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

// resourceLocations projects parsed resource blocks into the ResourceKey →
// FileLocation view. Blocks whose Mode is not "resource" are skipped, and
// when several blocks share a key the first one (in ParseDir's walk order)
// wins. Paths are made relative to absDir, the root ParseDir walked.
//
// It is a pure function over blocks, so it can be tested without touching
// the filesystem.
func resourceLocations(absDir string, blocks []ResourceBlock) iam.Locations {
	locations := make(iam.Locations)

	for _, b := range blocks {
		if b.Mode != "resource" {
			continue
		}
		// A block label carries no index, so KeyOf leaves the name as it is.
		// Readers call KeyOf on plan addresses, which may carry one.
		key := iam.KeyOf(b.Type, b.Name)
		if _, exists := locations[key]; exists {
			continue
		}
		locations[key] = iam.FileLocation{Path: relPath(absDir, b.Filename), Line: b.Line}
	}

	return locations
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
