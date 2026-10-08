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
	"github.com/elecnix/terraform-permcheck/internal/iam"
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
	parseErr  error  // the error of the one parse, returned by every later Ensure
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
// files. If the repo can't be cloned or located, it returns an error so
// callers can fall back to another resolver, and a later call retries. If the
// parse fails, Ensure returns the parse error, and every later call returns it
// too without parsing again.
func (p *SourceProvider) Ensure() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.parsed {
		return p.parseErr
	}

	if err := p.ensureRepo(); err != nil {
		// Repo not available — don't mark parsed, allow retry
		return err
	}

	p.parseErr = p.parseAll()
	p.parsed = true
	return p.parseErr
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

// Schemas parses the provider source and returns the schema of every resource
// type it found. The map is a copy; the schemas are the ones Resolve returns.
// It fails when the source holds no resources, so a generator never writes an
// empty table.
func (p *SourceProvider) Schemas() (map[string]*cloud.Schema, error) {
	if err := p.Ensure(); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.schemas) == 0 {
		return nil, fmt.Errorf("no resources found in provider source at %s", p.repoPath)
	}
	out := make(map[string]*cloud.Schema, len(p.schemas))
	for tfType, s := range p.schemas {
		out[tfType] = s
	}
	return out, nil
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
	resources, err := parseResources(p.repoPath)
	if err != nil {
		return err
	}
	for _, r := range resources {
		// A framework resource none of whose methods makes a call the
		// parser reads, such as aws_simpledb_domain on the v1 SDK, is left
		// to the next provider in the chain rather than reported as needing
		// nothing.
		if r.framework && len(r.pkg.actionsFor(r.funcs)) == 0 {
			continue
		}
		p.schemas[r.tfType] = r.schema()
	}
	return nil
}

// parseResources indexes every service package of the provider checkout at
// repoPath and returns the resources they declare, with the packages linked.
func parseResources(repoPath string) ([]resourceFile, error) {
	serviceDir := filepath.Join(repoPath, "internal", "service")
	if _, err := os.Stat(serviceDir); err != nil {
		return nil, fmt.Errorf("service directory not found at %s: %w", serviceDir, err)
	}

	entries, err := os.ReadDir(serviceDir)
	if err != nil {
		return nil, fmt.Errorf("read service directory: %w", err)
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
	// resolves when the caller builds each resource's schema.
	for _, idx := range indexes {
		idx.others = indexes
	}
	return resources, nil
}

// resourceFile is one resource found in a service package, with what pass 2
// needs to build its schema.
type resourceFile struct {
	pkg        *Package
	tfType     string
	funcs      map[string][]string // operation → bound functions
	tagged     bool                // the file carries a @Tags annotation
	tagActions TagActions          // the service's transparent tagging actions
	framework  bool                // a @FrameworkResource, whose operations are methods
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
		// A Terraform Plugin Framework resource implements its operations
		// as methods of the type its annotated constructor builds.
		if tfType := frameworkResourceType(string(src)); tfType != "" {
			if typeName := frameworkResourceStruct(parsed[name]); typeName != "" {
				found = append(found, resourceFile{
					pkg:        pkg,
					tfType:     tfType,
					funcs:      pkg.frameworkFuncs(typeName),
					tagged:     hasTagsAnnotation(src),
					tagActions: tagActions,
					framework:  true,
				})
			}
			continue
		}
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

	// Build the cloud.Schema: one requirement per path that reaches an
	// action, each carrying the path's gate: presence (d.GetOk/d.Get), change
	// (d.HasChange), a value guard (the attribute's value is tested rather
	// than its presence), and whether the provider ignores the call's failure.
	schema := &cloud.Schema{
		TypeName: r.tfType,
		Ops:      make(map[string][]iam.Requirement, len(actions)),
	}

	for op, eas := range actions {
		reqs := make([]iam.Requirement, 0, len(eas))
		for _, ea := range eas {
			for _, g := range ea.paths() {
				reqs = append(reqs, iam.Requirement{Action: ea.Action, Gate: g})
			}
		}
		schema.Ops[op] = reqs
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
	for _, action := range actions {
		gates := schema.Gates(op, action)
		switch len(gates) {
		case 0:
			schema.Ops[op] = append(schema.Ops[op], iam.Requirement{Action: action})
		case 1:
			// Transparent tagging checks this call's error, whatever the
			// resource's own functions do with theirs.
			g := gates[0]
			g.BestEffort = false
			setGates(schema, op, action, []iam.Gate{g})
		}
	}
}

// addTagActions adds tagging actions to the given operation, gated on the
// `tags` attribute. An action can already be present for that operation,
// because API Gateway authorizes calls by HTTP verb: CreateDomainName and
// TagResource are both apigateway:POST. The action is then reached on two
// paths and is needed when either gate holds, so the tags gate joins the
// gates the action already has.
func addTagActions(schema *cloud.Schema, op string, actions []string) {
	tags := iam.Gate{Attribute: "tags"}
	for _, action := range actions {
		setGates(schema, op, action, append(schema.Gates(op, action), tags))
	}
}

// setGates replaces the paths of an action with the given gates, without the
// paths another path subsumes. A path that always runs and whose failure
// counts leaves the action ungated. The action keeps its place among the
// operation's requirements, or goes last when it is new.
func setGates(schema *cloud.Schema, op, action string, gates []iam.Gate) {
	paths := make([]iam.Requirement, 0, len(gates))
	for _, g := range essentialGates(gates) {
		paths = append(paths, iam.Requirement{Action: action, Gate: g})
	}
	reqs := schema.Ops[op]
	out := make([]iam.Requirement, 0, len(reqs)+len(paths))
	placed := false
	for _, r := range reqs {
		if r.Action != action {
			out = append(out, r)
			continue
		}
		if !placed {
			out = append(out, paths...)
			placed = true
		}
	}
	if !placed {
		out = append(out, paths...)
	}
	schema.Ops[op] = out
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

// resourceNameFromFile extracts the resource name from a parsed file by
// finding resource function names like resourceVaultCreate.
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
// verb, e.g. "s3:HeadBucket" or "logs:DescribeLogGroups". The parser builds
// every action as "service:Name", so the verb follows the colon; a name
// without one is judged whole, which is also what a slice at Index+1 would
// give when Index is -1.
func isReadOnlyAction(action string) bool {
	name := action
	if i := strings.Index(action, ":"); i >= 0 {
		name = action[i+1:]
	}
	for _, verb := range readOnlyVerbs {
		if strings.HasPrefix(name, verb) {
			return true
		}
	}
	return false
}
