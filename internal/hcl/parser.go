// Package hcl provides a static HCL parser that extracts resource and data
// block types from terraform configuration files without running terraform
// plan. This enables permission validation in environments without AWS
// credentials (fork PRs, cold-check, etc.).
//
// The parser deliberately over-approximates: it includes every resource type
// referenced in the code regardless of count, for_each, or whether the
// resource would actually be created. For IAM validation this is the correct
// default — the deploy role's policy should cover everything it *could*
// manage, not just everything it happens to be changing right now.
package hcl

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ResourceBlock is a single resource or data block extracted from a .tf file.
type ResourceBlock struct {
	Type string // terraform resource type, e.g. "aws_backup_vault"
	Name string // terraform resource name, e.g. "this"
	Mode string // "resource" or "data"
}

// resourceRE matches resource and data block declarations in terraform .tf files.
// Captures: resource "aws_backup_vault" "this" { ... }
var resourceRE = regexp.MustCompile(`(resource|data)\s+"(aws_[^"]+)"\s+"([^"]+)"`)

// ParseDir walks a directory recursively, parses all .tf files, and extracts
// every resource and data block of known cloud types (aws_*). No module
// resolution or variable evaluation is performed — this is an intentional
// over-approximation.
func ParseDir(dir string) ([]ResourceBlock, error) {
	var blocks []ResourceBlock

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip hidden directories
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

		fileBlocks, err := ParseFile(string(src))
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		blocks = append(blocks, fileBlocks...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return blocks, nil
}

// ParseFile extracts resource and data block types from a single .tf file's
// content. It strips comments and then matches resource/data declarations.
func ParseFile(src string) ([]ResourceBlock, error) {
	clean := stripComments(src)
	matches := resourceRE.FindAllStringSubmatch(clean, -1)

	var blocks []ResourceBlock
	for _, m := range matches {
		if len(m) < 4 {
			continue
		}
		blocks = append(blocks, ResourceBlock{
			Mode: m[1],
			Type: m[2],
			Name: m[3],
		})
	}

	return blocks, nil
}

// stripComments removes terraform comments from source to prevent
// commented-out resource blocks from being matched.
func stripComments(src string) string {
	// Remove line comments: // ... and # ...
	lines := strings.Split(src, "\n")
	var out []string
	for _, line := range lines {
		// Remove # comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		// Remove // comments
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		out = append(out, line)
	}
	result := strings.Join(out, "\n")

	// Remove block comments: /* ... */
	for {
		start := strings.Index(result, "/*")
		if start < 0 {
			break
		}
		end := strings.Index(result[start+2:], "*/")
		if end < 0 {
			break
		}
		result = result[:start] + result[start+2+end+2:]
	}

	return result
}
