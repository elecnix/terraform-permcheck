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
	"sync"
)

// ResourceBlock is a single resource or data block extracted from a .tf file.
type ResourceBlock struct {
	Type       string   // terraform resource type, e.g. "aws_backup_vault"
	Name       string   // terraform resource name, e.g. "this"
	Mode       string   // "resource" or "data"
	Filename   string   // path to the .tf file (populated by ParseDir)
	Line       int      // 1-based line number of the resource declaration
	Attributes []string // top-level attribute names set in the resource body
}

// readFile is the single place ParseDir reads a .tf file from disk. It is a
// variable so tests can observe the read: every view derived from a parse
// must come from this one read, never from a second walk over the same tree.
//
// The swap is guarded because a test that replaces this function would
// otherwise write it while another test's ParseDir reads it. No test in this
// package runs in parallel today, so the race is latent rather than active,
// but it is one t.Parallel() away from being real. Production reads go
// through readFileAt, which takes the read lock.
var (
	readFileMu sync.RWMutex
	readFile   = os.ReadFile
)

// baseReadFile is what every swap restores. It is deliberately the package
// default rather than the reader that happened to be installed at swap time:
// unwinding into another swap's fake reader would leave a test running against
// a seam it did not install, which is never what a caller wants.
var baseReadFile = os.ReadFile

// swapReadFile installs fn as the reader and returns a function that restores
// the original. Intended for tests.
//
// Precondition: a swap must not be installed while another swap is still in
// force. Overlapping swaps are a caller error, not something this seam papers
// over — the second swap replaces the first reader, and the first restore then
// returns the package default out from under it. Every caller swaps once and
// restores once, and no test in this package runs in parallel, so the
// precondition holds. Callers that need nesting should coordinate at their own
// level rather than rely on this seam.
//
// The restore is unconditional. An earlier version tracked a generation
// counter so that an out-of-order restore would leave a newer swap installed.
// Since every restore targets the same package default, that counter guarded
// nothing: it could only ever be defeated by another restore, which would leave
// the package default installed anyway. Restoring straight to the default is
// the same end state with none of the bookkeeping, and it means no sequence of
// restores can leave a reader installed that the caller did not ask for.
func swapReadFile(fn func(string) ([]byte, error)) func() {
	readFileMu.Lock()
	readFile = fn
	readFileMu.Unlock()

	return func() {
		readFileMu.Lock()
		defer readFileMu.Unlock()
		readFile = baseReadFile
	}
}

// readFileAt reads path through the current seam. The reader is copied out
// under the lock and then called, so the swap can never change the function
// midway through a read.
func readFileAt(path string) ([]byte, error) {
	readFileMu.RLock()
	read := readFile
	readFileMu.RUnlock()
	return read(path)
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

		src, err := readFileAt(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		fileBlocks, err := parseFile(path, string(src))
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

// parseFile extracts resource and data block types from a single .tf file's
// content. It strips comments and then matches resource/data declarations
// line-by-line to capture accurate line numbers. The filename parameter is
// stored on every ResourceBlock so clients can correlate resources to sources.
func parseFile(filename, src string) ([]ResourceBlock, error) {
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
			attrs := parseAttributes(lines, i)
			blocks = append(blocks, ResourceBlock{
				Mode:       matches[1],
				Type:       matches[2],
				Name:       matches[3],
				Filename:   filename,
				Line:       i + 1,
				Attributes: attrs,
			})
		}
	}

	return blocks, nil
}

// parseAttributes extracts top-level attribute names from a resource block
// body. It scans lines starting from the block declaration line, tracking
// brace depth, and collects identifiers followed by = at depth 1 (the
// top level of the resource body). Sub-blocks (e.g. website { ... }) are
// at higher depth and their attribute keys are excluded.
//
// String contents are tracked to avoid counting braces inside JSON or
// heredoc expressions as block delimiters. This is a heuristic — fully
// correct HCL parsing requires a lexer/parser — but handles the vast
// majority of real-world terraform configurations.
func parseAttributes(lines []string, blockStartIdx int) []string {
	if blockStartIdx >= len(lines) {
		return nil
	}

	// Find the opening brace for this block.
	openIdx := -1
	for i := blockStartIdx; i < len(lines); i++ {
		clean := stripLineComments(lines[i])
		if strings.Contains(clean, "{") {
			openIdx = i
			break
		}
	}
	if openIdx < 0 {
		return nil
	}

	depth := 0
	inString := false
	var attrs []string

	for i := openIdx; i < len(lines); i++ {
		clean := stripLineComments(lines[i])
		prevDepth := depth

		for _, ch := range clean {
			if ch == '"' {
				inString = !inString
				continue
			}
			if inString {
				continue
			}
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
				if depth <= 0 {
					return attrs
				}
			}
		}

		if prevDepth == 1 {
			// At top level of resource body — look for attribute assignments.
			// An attribute has the form: ident = <value>
			// We need to find = that is not inside a nested block.
			eqIdx := strings.Index(clean, "=")
			if eqIdx > 0 {
				openBraceIdx := strings.Index(clean[:eqIdx], "{")
				if openBraceIdx < 0 {
					name := strings.TrimSpace(clean[:eqIdx])
					if isIdent(name) {
						attrs = append(attrs, name)
					}
				}
			}
		}
	}

	return attrs
}

// isIdent reports whether s is a valid terraform identifier (letters,
// digits, underscores, hyphens) and non-empty.
func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
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
