package provideraws

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
)

// sdkResourceAnnotationRE matches the @SDKResource annotation in provider source.
// Format: // @SDKResource("aws_instance", name="Instance")
var sdkResourceAnnotationRE = regexp.MustCompile(`@SDKResource\("(aws_[^",]+)[",]`)

// DefaultProviderRef is the pinned provider version used for parsing.
// This is the framework-refactored codebase (v5+).
const DefaultProviderRef = "v5.90.0"

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
	skipClone bool   // true when repoPath already has provider source
	remoteURL string // where ensureRepo fetches DefaultProviderRef from
}

// NewSourceProvider creates a new SourceProvider that clones the terraform-provider-aws
// repository at DefaultProviderRef into the cache (see defaultCacheDir) and
// extracts permissions from the source code.
func NewSourceProvider() *SourceProvider {
	return &SourceProvider{
		repoPath:  defaultCacheDir(),
		schemas:   make(map[string]*cloud.Schema),
		remoteURL: upstreamURL,
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

// runGit runs a git command in the given directory. If buf is nil, stderr is
// buffered and only printed when the command fails — so the caller gets a
// clean, silent run on success and the full git error on failure. The buffer
// is returned for callers that need to inspect output.
func runGit(dir string, buf *bytes.Buffer, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	if buf == nil {
		var b bytes.Buffer
		cmd.Stderr = &b
		if err := cmd.Run(); err != nil {
			// Print whatever stderr we captured, then return the error.
			if b.Len() > 0 {
				fmt.Fprintf(os.Stderr, "%s", b.String())
			}
			return fmt.Errorf("git %v: %w", args, err)
		}
		return nil
	}
	cmd.Stderr = buf
	return cmd.Run()
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

	// Pass 1 indexes each service package and records its resource files.
	// Only the indexes survive a package, not its syntax trees.
	indexes := make(map[string]*pkgIndex)
	var resources []resourceFile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		svcDir := filepath.Join(serviceDir, entry.Name())
		pkg, found := indexService(svcDir, entry.Name())
		if pkg == nil {
			continue
		}
		indexes[entry.Name()] = pkg.idx
		resources = append(resources, found...)
	}

	// Pass 2 links the packages, so a call such as tfiam.FindRoleByName
	// resolves, and builds each resource's schema.
	for _, idx := range indexes {
		idx.others = indexes
	}
	for _, r := range resources {
		p.schemas[r.tfType] = r.schema()
	}
	return nil
}

// resourceFile is one resource found in a service package, with what pass 2
// needs to build its schema.
type resourceFile struct {
	pkg        *Package
	tfType     string
	funcs      map[string][]string // operation → bound functions
	tagged     bool                // the file carries a @Tags annotation
	tagActions TagActions          // the service's transparent tagging actions
}

// indexService parses every non-test Go file of one service directory as a
// package, so a resource's helpers resolve whichever file they live in, and
// returns the package with the resources its files declare.
func indexService(svcDir, serviceName string) (*Package, []resourceFile) {
	files, err := os.ReadDir(svcDir)
	if err != nil {
		return nil, nil
	}
	fset := token.NewFileSet()
	parsed := make(map[string]*ast.File)
	sources := make(map[string][]byte)
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(svcDir, file.Name()))
		if err != nil {
			continue
		}
		f, err := parser.ParseFile(fset, file.Name(), src, parser.ParseComments)
		if err != nil {
			continue
		}
		parsed[file.Name()] = f
		sources[file.Name()] = src
	}
	if len(parsed) == 0 {
		return nil, nil
	}
	pkg := newPackage(parsed)

	// Transparent tagging actions (e.g. kms:TagResource) live in the
	// service's generated tags_gen.go, not in each resource's CRUD
	// functions. Parse them once per service and attach to taggable
	// resources.
	tagActions := tagActionsForService(svcDir)

	names := make([]string, 0, len(parsed))
	for name := range parsed {
		names = append(names, name)
	}
	sort.Strings(names)
	var found []resourceFile
	for _, name := range names {
		src := sources[name]
		// Prefer the @SDKResource annotation (canonical), fall back to
		// file-path derivation.
		tfType := resourceTypeFromAnnotation(src)
		if tfType == "" {
			tfType = resourceTypeFromFile(serviceName, name)
		}
		resourceName := resourceNameFromFile(parsed[name])
		if tfType == "" || resourceName == "" {
			continue
		}
		found = append(found, resourceFile{
			pkg:        pkg,
			tfType:     tfType,
			funcs:      pkg.resourceFuncs(name, resourceName),
			tagged:     hasTagsAnnotation(src),
			tagActions: tagActions,
		})
	}
	pkg.files = nil
	return pkg, found
}

// tagActionsForService reads a service directory's generated tags_gen.go (if
// present) and extracts its transparent-tagging SDK actions. Returns an empty
// TagActions when the file is absent or yields no tagging calls.
func tagActionsForService(svcDir string) TagActions {
	src, err := os.ReadFile(filepath.Join(svcDir, "tags_gen.go"))
	if err != nil {
		return TagActions{}
	}
	ta, err := ExtractTagActions(string(src))
	if err != nil {
		return TagActions{}
	}
	return ta
}

// schema builds the cloud.Schema of one resource.
func (r resourceFile) schema() *cloud.Schema {
	actions, bound := r.pkg.actionsFor(r.funcs), boundFuncs(r.funcs)

	// Build the cloud.Schema with permissions plus all three gate kinds:
	// presence (d.GetOk/d.Get), change (d.HasChange), and value guards (the
	// attribute's value is tested rather than its presence).
	schema := &cloud.Schema{
		TypeName:         r.tfType,
		Permissions:      make(map[string][]string),
		Conditional:      make(map[string]map[string]string),
		ChangeGated:      make(map[string]map[string]string),
		ValueConditional: make(map[string]map[string]bool),
	}

	for op, eas := range actions {
		perms := make([]string, 0, len(eas))
		conds := make(map[string]string, len(eas))
		changes := make(map[string]string, len(eas))
		valueConds := make(map[string]bool, len(eas))
		for _, ea := range eas {
			perms = append(perms, ea.Action)
			if !ea.Conditional || ea.Condition == "" {
				continue
			}
			switch ea.ConditionKind {
			case ConditionChange:
				changes[ea.Action] = ea.Condition
			default:
				conds[ea.Action] = ea.Condition
				if ea.ValueGuarded {
					valueConds[ea.Action] = true
				}
			}
		}
		schema.Permissions[op] = perms
		if len(conds) > 0 {
			schema.Conditional[op] = conds
		}
		if len(changes) > 0 {
			schema.ChangeGated[op] = changes
		}
		if len(valueConds) > 0 {
			schema.ValueConditional[op] = valueConds
		}
	}

	schema.Incomplete = incompleteOperations(actions, bound, r.pkg.idx.reachesClient)

	// If the resource opts into transparent tagging (@Tags annotation), the
	// provider makes additional SDK tagging calls when `tags` is set — calls
	// that don't appear in the resource's own CRUD functions. Add them as
	// permissions gated on the `tags` attribute.
	if r.tagged && !r.tagActions.Empty() {
		addTagActions(schema, "create", r.tagActions.Apply)
		addTagActions(schema, "update", r.tagActions.Apply)
		addTagActions(schema, "update", r.tagActions.Remove)

		// The list-tags SDK call (e.g. kms:ListResourceTags) is made
		// unconditionally on every resource Read for @Tags-annotated
		// resources, and Create returns Read — so it's needed on both
		// read and create without any attribute gating.
		addUnconditionalActions(schema, "read", r.tagActions.List)
		addUnconditionalActions(schema, "create", r.tagActions.List)
	}

	return schema
}

// addUnconditionalActions adds actions to the given operation without any
// conditional gating, skipping any already present for that operation.
func addUnconditionalActions(schema *cloud.Schema, op string, actions []string) {
	if len(actions) == 0 {
		return
	}
	existing := make(map[string]bool, len(schema.Permissions[op]))
	for _, a := range schema.Permissions[op] {
		existing[a] = true
	}
	// Ensure Conditional map exists even if no entries for this op.
	if schema.Conditional == nil {
		schema.Conditional = make(map[string]map[string]string)
	}
	if schema.ChangeGated == nil {
		schema.ChangeGated = make(map[string]map[string]string)
	}
	for _, action := range actions {
		if !existing[action] {
			schema.Permissions[op] = append(schema.Permissions[op], action)
			existing[action] = true
		}
	}
}

// addTagActions adds tagging actions to the given operation, gated on the
// `tags` attribute, skipping any already present for that operation.
func addTagActions(schema *cloud.Schema, op string, actions []string) {
	if len(actions) == 0 {
		return
	}
	existing := make(map[string]bool, len(schema.Permissions[op]))
	for _, a := range schema.Permissions[op] {
		existing[a] = true
	}
	if schema.Conditional[op] == nil {
		schema.Conditional[op] = make(map[string]string)
	}
	for _, action := range actions {
		if !existing[action] {
			schema.Permissions[op] = append(schema.Permissions[op], action)
			existing[action] = true
		}
		schema.Conditional[op][action] = "tags"
	}
}

// resourceTypeFromAnnotation extracts the terraform resource type from an
// @SDKResource annotation in the Go source code.
//
//	// @SDKResource("aws_instance", name="Instance")
//	// @SDKResource("aws_cloudwatch_log_group", name="Log Group")
//
// Returns empty string if no annotation is found.
func resourceTypeFromAnnotation(src []byte) string {
	matches := sdkResourceAnnotationRE.FindSubmatch(src)
	if len(matches) >= 2 {
		return string(matches[1])
	}
	return ""
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
	return resourceNameFromFile(f)
}

// resourceNameFromFile is resourceNameFromSource on an already parsed file.
func resourceNameFromFile(f *ast.File) string {
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

// incompleteOperations names the operations whose parse cannot be the whole
// story. The resource binds a function to the operation and that function
// uses an SDK client, yet the parse found no SDK call there, or, for a create
// or a delete, found only calls that read. A create or a delete that changes
// nothing in AWS means the parser missed the call that does, so the result
// must not be taken as the full permission set. An operation bound to a no-op
// such as schema.NoopContext, or to a function that never touches a client,
// is not incomplete.
func incompleteOperations(actions map[string][]ExtractedAction, bound map[string]string, usesClient func(string) bool) map[string]bool {
	var out map[string]bool
	for _, op := range []string{"create", "read", "delete"} {
		fn, ok := bound[op]
		if !ok || fn == "" || !usesClient(fn) {
			continue
		}
		complete := len(actions[op]) > 0
		if complete && op != "read" {
			complete = false
			for _, ea := range actions[op] {
				if !isReadOnlyAction(ea.Action) {
					complete = true
					break
				}
			}
		}
		if !complete {
			if out == nil {
				out = make(map[string]bool)
			}
			out[op] = true
		}
	}
	return out
}

// readOnlyVerbs are the IAM action prefixes of calls that only read.
var readOnlyVerbs = []string{"Describe", "Get", "List", "Head", "BatchGet", "Search", "Lookup"}

// isReadOnlyAction reports whether an IAM action only reads, judged by its
// verb, e.g. "s3:HeadBucket" or "logs:DescribeLogGroups".
func isReadOnlyAction(action string) bool {
	name := action[strings.Index(action, ":")+1:]
	for _, verb := range readOnlyVerbs {
		if strings.HasPrefix(name, verb) {
			return true
		}
	}
	return false
}
