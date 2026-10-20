package hcl

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Location is where a resource block is declared.
type Location struct {
	// Path is the path of the file that declares the block, relative to the
	// anchor the location map was built with. The anchor is the directory
	// a consumer resolves the path against: the repository root in CI, so
	// a GitHub annotation lands on the file it names. It is separate from
	// the terraform root that gets walked, because the terraform root is
	// often a subdirectory of the repository. When the anchor cannot
	// contain the file, the path is relative to the terraform root
	// instead.
	Path string
	Line int // 1-based line number of the block
}

// MapResources walks a terraform root directory, parses all .tf files, and
// returns the file path and line number of each resource declaration, keyed
// by its type and name (e.g. "aws_s3_bucket.cloudtrail"). Only "resource"
// blocks are included (not "data" blocks). Files inside hidden directories
// (including .terraform) are skipped. When multiple resources share the same
// key (e.g. two files with identical type+name), the first one encountered
// wins.
//
// The returned paths are relative to anchor, the directory the paths are
// anchored to, which is not the directory that gets walked. The terraform
// root dir is often a subdirectory of the repository, and a path relative to
// it alone does not resolve against the repository root, which is where a
// GitHub annotation looks. An empty anchor means the terraform root is the
// anchor, and the paths are relative to it.
//
// This is a projection over ParseDir's result, not a second walk: the tree is
// read and parsed exactly once per run, and the location map is derived from
// the same ResourceBlocks the plan-mode and static views use.
func MapResources(dir, anchor string) (map[string]Location, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve terraform root %q: %w", dir, err)
	}
	absAnchor, err := resolveAnchor(dir, anchor)
	if err != nil {
		return nil, err
	}

	blocks, err := ParseDir(absDir)
	if err != nil {
		return nil, err
	}

	return resourceLocations(absDir, absAnchor, blocks), nil
}

// resourceLocations projects parsed resource blocks into the type.name →
// Location view. Blocks whose Mode is not "resource" are skipped, and
// when several blocks share a key the first one (in ParseDir's walk order)
// wins. Paths are made relative to anchor, the directory the paths are
// anchored to, and fall back to absDir, the terraform root, when the anchor
// cannot contain the file.
//
// It is a pure function over blocks, so it can be tested without touching
// the filesystem.
func resourceLocations(absDir, anchor string, blocks []ResourceBlock) map[string]Location {
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
		locations[key] = Location{Path: anchoredPath(anchor, absDir, b.Filename), Line: b.Line}
	}

	return locations
}

// MapRootResources is MapResources for the root module only: the blocks of
// the .tf files directly in dir. A block in a subdirectory belongs to a
// module, and the parser does not know which module call, and so which
// address, it has. A plan names its resources by address, so plan mode uses
// this map: a module finding then has no location rather than the location
// of a root block that shares its type and name.
//
// The anchor decides the paths, not which blocks belong to the root module:
// the module structure belongs to the terraform configuration, so the filter
// uses the terraform root whatever the anchor is.
func MapRootResources(dir, anchor string) (map[string]Location, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve terraform root %q: %w", dir, err)
	}
	absAnchor, err := resolveAnchor(dir, anchor)
	if err != nil {
		return nil, err
	}
	blocks, err := ParseDir(absDir)
	if err != nil {
		return nil, err
	}
	return rootResourceLocations(absDir, absAnchor, blocks), nil
}

// rootResourceLocations is resourceLocations over the blocks of the files
// directly in absDir, the terraform root. The filter uses the terraform
// root, not the anchor: it asks which blocks belong to the root module, and
// the anchor only says where the paths are anchored.
func rootResourceLocations(absDir, anchor string, blocks []ResourceBlock) map[string]Location {
	var root []ResourceBlock
	for _, b := range blocks {
		if filepath.Dir(relPath(absDir, b.Filename)) == "." {
			root = append(root, b)
		}
	}
	return resourceLocations(absDir, anchor, root)
}

// resolveAnchor resolves the directory the paths are anchored to. An empty
// anchor means the caller has none, so the terraform root is the anchor and
// the paths are relative to it.
func resolveAnchor(dir, anchor string) (string, error) {
	if anchor == "" {
		anchor = dir
	}
	abs, err := filepath.Abs(anchor)
	if err != nil {
		return "", fmt.Errorf("resolve path anchor %q: %w", anchor, err)
	}
	return abs, nil
}

// anchoredPath returns filename relative to anchor, the directory the paths
// are anchored to. A path that leaves the anchor carries ".." segments that
// a consumer resolving it against the anchor cannot follow, so the path
// relative to rootDir, the terraform root, is used instead.
//
// A relative filename is resolved against the terraform root, which is where
// the file it names lives.
func anchoredPath(anchor, rootDir, filename string) string {
	abs := filename
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(rootDir, abs)
	}
	rel, err := filepath.Rel(anchor, abs)
	if err != nil || leavesAnchor(rel) {
		return relPath(rootDir, filename)
	}
	return rel
}

// leavesAnchor reports whether a relative path points outside the directory
// it is relative to.
func leavesAnchor(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// relPath returns filename relative to base, falling back to filename when
// the two cannot be related. The base is the directory the result is
// relative to: the terraform root, for the root-module filter and for the
// fallback when the anchor cannot contain the file. ParseDir's block
// filenames come from a walk rooted at the terraform root, so they are
// absolute in normal use; the relative case is handled so the projection
// stays correct for any input.
func relPath(base, filename string) string {
	original := filename
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(base, filename)
	}
	rel, err := filepath.Rel(base, filename)
	if err != nil {
		return original
	}
	return rel
}
