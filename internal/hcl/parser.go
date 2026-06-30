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
	Type     string // terraform resource type, e.g. "aws_backup_vault"
	Name     string // terraform resource name, e.g. "this"
	Mode     string // "resource" or "data"
	Filename string // path to the .tf file (populated by ParseDir)
	Line     int    // 1-based line number of the resource declaration
}

// resourceRE matches resource and data block declarations in terraform .tf files.
// Captures: resource "aws_backup_vault" "this" { ... }
var resourceRE = regexp.MustCompile(`(resource|data)\s+"(aws_[^"]+)"\s+"([^"]+)"`)

// ParseDir walks a directory recursively, parses all .tf files, and extracts
// every resource and data block of known cloud types (aws_*). No module
// resolution or variable evaluation is performed — this is an intentional
// over-approximation. Skips hidden directories (including .terraform).
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

		fileBlocks, err := ParseFile(path, string(src))
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
// content. It strips comments and then matches resource/data declarations
// line-by-line to capture accurate line numbers. The filename parameter is
// stored on every ResourceBlock so clients can correlate resources to sources.
func ParseFile(filename, src string) ([]ResourceBlock, error) {
	lines := strings.Split(src, "\n")
	inBlockComment := false

	var blocks []ResourceBlock
	for i, line := range lines {
		// Track block comments (/* ... */) which can span lines.
		// We still do line-level matching for resource declarations, so
		// block-commented resources are skipped correctly.
		if inBlockComment {
			if idx := strings.Index(line, "*/"); idx >= 0 {
				inBlockComment = false
			}
			continue
		}
		if idx := strings.Index(line, "/*"); idx >= 0 {
			// Block comment starts on this line; only skip if it doesn't end same line.
			if endIdx := strings.Index(line, "*/"); endIdx < 0 || endIdx < idx {
				// Check if there's content before the comment
				// (unlikely for resource blocks, but handle it)
				if endIdx := strings.Index(line, "*/"); endIdx < 0 {
					inBlockComment = true
					continue
				}
			}
		}

		// Strip line comments to avoid matching commented-out resources.
		clean := stripLineComments(line)

		matches := resourceRE.FindStringSubmatch(clean)
		if len(matches) >= 4 {
			blocks = append(blocks, ResourceBlock{
				Mode:     matches[1],
				Type:     matches[2],
				Name:     matches[3],
				Filename: filename,
				Line:     i + 1,
			})
		}
	}

	return blocks, nil
}

// stripLineComments removes line comments (// and #) from a single line.
func stripLineComments(line string) string {
	for _, marker := range []string{"//", "#"} {
		if idx := strings.Index(line, marker); idx >= 0 {
			return line[:idx]
		}
	}
	return line
}

// stripComments removes terraform comments from source to prevent
// commented-out resource blocks from being matched. This is the original
// all-at-once approach (used when line numbers aren't needed).
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
