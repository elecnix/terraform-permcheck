package provideraws

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
)

// DefaultProviderRef is the pinned provider version used for parsing.
// This is the framework-refactored codebase (v5+).
const DefaultProviderRef = "v5.90.0"

// defaultCacheDir is where the provider source is cloned.
func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "terraform-permcheck", "provider-aws")
}

// SourceProvider resolves AWS resource types by parsing the terraform-provider-aws
// Go source code to extract the exact SDK API calls made by each resource.
//
// This provides more precise permissions than the CloudFormation schema approach
// because it captures only the calls the provider actually makes.
type SourceProvider struct {
	mu        sync.RWMutex
	repoPath  string
	schemas   map[string]*cloud.Schema // tfType -> schema
	parsed    bool
	skipClone bool // true when repoPath already has provider source
}

// NewSourceProvider creates a new SourceProvider that clones the terraform-provider-aws
// repository and extracts permissions from the source code.
func NewSourceProvider() *SourceProvider {
	return &SourceProvider{
		repoPath: defaultCacheDir(),
		schemas:  make(map[string]*cloud.Schema),
	}
}

// NewSourceProviderWithPath creates a SourceProvider that uses an existing
// terraform-provider-aws checkout at repoPath (skip clone).
func NewSourceProviderWithPath(repoPath string) *SourceProvider {
	return &SourceProvider{
		repoPath:  repoPath,
		schemas:   make(map[string]*cloud.Schema),
		skipClone: true,
	}
}

// Name returns "aws".
func (p *SourceProvider) Name() string { return "aws" }

// Ensure checks that the provider repo is available and parses all resource
// files. If the repo can't be cloned or located, returns an error so callers
// can fall back to another resolver. Subsequent calls will retry.
func (p *SourceProvider) Ensure() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.parsed {
		return nil
	}

	if err := p.ensureRepo(); err != nil {
		// Repo not available — don't mark parsed, allow retry
		return err
	}

	if err := p.parseAll(); err != nil {
		p.parsed = true
		return nil
	}

	p.parsed = true
	return nil
}

// Resolve maps a terraform resource type to its required IAM permissions.
// Returns an error if the provider source is unavailable (allowing fallback).
func (p *SourceProvider) Resolve(tfType string) (*cloud.Schema, error) {
	if err := p.Ensure(); err != nil {
		return nil, err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	schema, ok := p.schemas[tfType]
	if !ok {
		return nil, fmt.Errorf("%q: not found in provider source", tfType)
	}

	return schema, nil
}

// Has checks if the provider has a schema for the given terraform type.
func (p *SourceProvider) Has(tfType string) bool {
	_ = p.Ensure()
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.schemas[tfType]
	return ok
}

// ensureRepo clones or verifies the terraform-provider-aws checkout.
func (p *SourceProvider) ensureRepo() error {
	if p.skipClone {
		return nil
	}
	dir := p.repoPath
	gitDir := filepath.Join(dir, ".git")

	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		// Clone
		if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
			return err
		}
		cmd := exec.Command("git", "clone", "--depth", "1",
			"--branch", DefaultProviderRef,
			"https://github.com/hashicorp/terraform-provider-aws.git", dir)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	// Verify at right ref
	cmd := exec.Command("git", "-C", dir, "rev-parse", DefaultProviderRef)
	out, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		return nil // already at the right branch/tag
	}

	// Fetch and checkout
	cmdFetch := exec.Command("git", "-C", dir, "fetch", "--depth", "1", "origin", DefaultProviderRef)
	cmdFetch.Stdout = os.Stderr
	cmdFetch.Stderr = os.Stderr
	if err := cmdFetch.Run(); err != nil {
		return fmt.Errorf("fetch %s: %w", DefaultProviderRef, err)
	}

	cmdCO := exec.Command("git", "-C", dir, "checkout", DefaultProviderRef)
	cmdCO.Stdout = os.Stderr
	cmdCO.Stderr = os.Stderr
	return cmdCO.Run()
}

// parseAll discovers all AWS resource Go files and extracts permissions.
func (p *SourceProvider) parseAll() error {
	serviceDir := filepath.Join(p.repoPath, "internal", "service")
	if _, err := os.Stat(serviceDir); err != nil {
		return fmt.Errorf("service directory not found at %s: %w", serviceDir, err)
	}

	entries, err := os.ReadDir(serviceDir)
	if err != nil {
		return fmt.Errorf("read service directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		svcDir := filepath.Join(serviceDir, entry.Name())
		files, err := os.ReadDir(svcDir)
		if err != nil {
			continue
		}

		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") {
				continue
			}
			// Skip test files and non-resource files
			if strings.HasSuffix(file.Name(), "_test.go") {
				continue
			}

			filePath := filepath.Join(svcDir, file.Name())
			p.parseFile(filePath, entry.Name(), file.Name())
		}
	}

	return nil
}

// parseFile parses a single Go source file and extracts resource permissions.
func (p *SourceProvider) parseFile(filePath, serviceName, fileName string) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	// Determine the terraform resource type from the file.
	// Convention: internal/service/backup/vault.go -> aws_backup_vault
	// We can get the resource name from the @SDKResource annotation or
	// from the function names in the file.
	tfType := resourceTypeFromFile(serviceName, fileName)
	if tfType == "" {
		return
	}

	// Determine the resource name from function names in the file
	resourceName := resourceNameFromSource(src)
	if resourceName == "" {
		return
	}

	actions, err := ParseResourceFileStructured(string(src), tfType, resourceName)
	if err != nil {
		return
	}

	// Build the cloud.Schema with both Permissions and Conditional metadata
	schema := &cloud.Schema{
		TypeName:    tfType,
		Permissions: make(map[string][]string),
		Conditional: make(map[string]map[string]string),
	}

	for op, eas := range actions {
		perms := make([]string, 0, len(eas))
		conds := make(map[string]string, len(eas))
		for _, ea := range eas {
			perms = append(perms, ea.Action)
			if ea.Conditional && ea.Condition != "" {
				conds[ea.Action] = ea.Condition
			}
		}
		schema.Permissions[op] = perms
		if len(conds) > 0 {
			schema.Conditional[op] = conds
		}
	}

	p.schemas[tfType] = schema
}

// resourceTypeFromFile derives the terraform resource type from the file path.
// Convention: internal/service/<service>/<resource>.go -> aws_<service>_<resource>
func resourceTypeFromFile(serviceName, fileName string) string {
	resourceName := strings.TrimSuffix(fileName, ".go")
	return "aws_" + serviceName + "_" + resourceName
}

// resourceNameFromSource extracts the resource name from the Go source by
// finding resource function names like resourceVaultCreate, resourceTableRead, etc.
func resourceNameFromSource(src []byte) string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "source.go", src, parser.ParseComments)
	if err != nil {
		return ""
	}

	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if strings.HasPrefix(name, "resource") && strings.HasSuffix(name, "Create") {
			// e.g., "resourceVaultCreate" -> "Vault"
			// e.g., "resourceTableCreate" -> "Table"
			trimmed := strings.TrimPrefix(name, "resource")
			trimmed = strings.TrimSuffix(trimmed, "Create")
			return trimmed
		}
		// Also check CreateWithoutTimeout etc.
		if strings.HasPrefix(name, "resource") && strings.HasSuffix(name, "Delete") {
			trimmed := strings.TrimPrefix(name, "resource")
			trimmed = strings.TrimSuffix(trimmed, "Delete")
			return trimmed
		}
	}
	return ""
}
