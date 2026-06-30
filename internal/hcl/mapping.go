package hcl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// MapResources walks a terraform root directory, parses all .tf files, and
// returns a map from "type.name" (e.g. "aws_s3_bucket.cloudtrail") to the
// file path and line number of the resource declaration. Only "resource"
// blocks are included (not "data" blocks). Files inside hidden directories
// (including .terraform) are skipped. When multiple resources share the same
// key (e.g. two files with identical type+name), the first one encountered
// wins. The returned paths are relative to the walk root.
func MapResources(dir string) (map[string]iam.FileLocation, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve terraform root %q: %w", dir, err)
	}

	locations := make(map[string]iam.FileLocation)

	err = filepath.WalkDir(absDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".tf") {
			return nil
		}

		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		blocks, err := ParseFile(path, string(src))
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		// Compute relative path for the annotation.
		relPath, err := filepath.Rel(absDir, path)
		if err != nil {
			relPath = path
		}

		for _, b := range blocks {
			if b.Mode != "resource" {
				continue
			}
			key := b.Type + "." + b.Name
			if _, exists := locations[key]; !exists {
				locations[key] = iam.FileLocation{Path: relPath, Line: b.Line}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return locations, nil
}
