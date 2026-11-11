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

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// sdkResourceAnnotationRE matches the @SDKResource annotation in provider source.
// Format: // @SDKResource("aws_instance", name="Instance")
var sdkResourceAnnotationRE = regexp.MustCompile(`@SDKResource\("(aws_[^",]+)[",]`)

// DefaultProviderRef is the newest provider version the embedded table is
// generated from. A live parse uses it when the plan's provider version is
// unknown.
const DefaultProviderRef = "v6.72.0"

// TableProviderRefs lists the provider versions the embedded table is
// generated from, one per major version, oldest first. The table merges their
// requirements and marks the ones that only some of them have. The last one is
// DefaultProviderRef. CI keys its provider cache on this line.
var TableProviderRefs = []string{"v5.100.0", DefaultProviderRef}

// SourceProvider resolves AWS resource types by parsing the terraform-provider-aws
// Go source code to extract the exact SDK API calls made by each resource.
//
// This provides more precise permissions than the CloudFormation schema approach
// because it captures only the calls the provider actually makes.
type SourceProvider struct {
	mu        sync.RWMutex
	repoPath  string
	ref       string                 // the provider version ensureRepo checks out
	schemas   map[string]*iam.Schema // tfType -> schema
	parsed    bool
	parseErr  error  // the error of the one parse, returned by every later Ensure
	skipClone bool   // true when repoPath already has provider source
	remoteURL string // where ensureRepo fetches ref from
}

// NewSourceProvider creates a new SourceProvider that clones the terraform-provider-aws
// repository at DefaultProviderRef into the cache (see cacheDir) and
// extracts permissions from the source code.
func NewSourceProvider() *SourceProvider {
	return NewSourceProviderAt(DefaultProviderRef)
}

// NewSourceProviderAt is NewSourceProvider for the provider version ref, such
// as "v5.100.0". Each ref has its own checkout in the cache.
func NewSourceProviderAt(ref string) *SourceProvider {
	return &SourceProvider{
		repoPath:  cacheDir(ref),
		ref:       ref,
		schemas:   make(map[string]*iam.Schema),
		remoteURL: upstreamURL,
	}
}

// NewSourceProviderWithPath creates a SourceProvider that uses an existing
// terraform-provider-aws checkout at repoPath (skip clone).
func NewSourceProviderWithPath(repoPath string) *SourceProvider {
	return &SourceProvider{
		repoPath:  repoPath,
		schemas:   make(map[string]*iam.Schema),
		skipClone: true,
	}
}

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
func (p *SourceProvider) Resolve(tfType string) (*iam.Schema, error) {
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
func (p *SourceProvider) Schemas() (map[string]*iam.Schema, error) {
	if err := p.Ensure(); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.schemas) == 0 {
		return nil, fmt.Errorf("no resources found in provider source at %s", p.repoPath)
	}
	out := make(map[string]*iam.Schema, len(p.schemas))
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
	pkg       *Package
	tfType    string
	funcs     map[string][]string // operation → bound functions
	tagged    bool                // the file carries a @Tags annotation
	tags      tagEntries          // the functions that tag it, when tagged
	framework bool                // a @FrameworkResource, whose operations are methods
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
					pkg:       pkg,
					tfType:    tfType,
					funcs:     pkg.frameworkFuncs(typeName),
					tagged:    hasTagsAnnotation(src),
					tags:      pkg.tagEntriesFor(tagsResourceType(src)),
					framework: true,
				})
			}
			continue
		}
		// Prefer the @SDKResource annotations (canonical), fall back to
		// file-path derivation. A file that declares its resource under
		// several names, such as aws_alb_listener and aws_lb_listener,
		// yields one resource per name, all bound to the same functions.
		tfTypes := resourceTypesFromAnnotation(src)
		if len(tfTypes) == 0 {
			tfTypes = []string{resourceTypeFromFile(serviceName, name)}
		}
		// A resource names its operations by suffix (resourceVaultCreate)
		// or binds them in its schema.Resource literal. Only a literal that
		// binds a create function makes a file without a ...Create or
		// ...Delete function a resource; a data source binds only a read.
		// A create bound to a method of a handler type the package declares
		// (h.Upsert) resolves to that method. One that names nothing to
		// follow leaves the file unresolved rather than give it an empty
		// entry.
		resourceName := resourceNameFromFile(parsed[name])
		funcs := pkg.resourceFuncs(name, resourceName)
		if resourceName == "" {
			if create := funcs["create"]; len(create) == 0 || create[0] == "" {
				continue
			}
		}
		for _, tfType := range tfTypes {
			found = append(found, resourceFile{
				pkg:    pkg,
				tfType: tfType,
				funcs:  funcs,
				tagged: hasTagsAnnotation(src),
				tags:   pkg.tagEntriesFor(tagsResourceType(src)),
			})
		}
	}
	pkg.files = nil
	return pkg, found
}

// schema builds the iam.Schema of one resource.
func (r resourceFile) schema() *iam.Schema {
	actions, bound := r.pkg.actionsFor(r.funcs), boundFuncs(r.funcs)

	// Build the iam.Schema: one requirement per path that reaches an
	// action, each carrying the path's gate: presence (d.GetOk/d.Get), change
	// (d.HasChange), a value guard (the attribute's value is tested rather
	// than its presence), and whether the provider ignores the call's failure.
	schema := &iam.Schema{
		TypeName: r.tfType,
		Ops:      make(map[string][]iam.Requirement, len(actions)),
	}

	for op, reqs := range actions {
		schema.Ops[op] = append([]iam.Requirement(nil), reqs...)
	}

	schema.Incomplete = incompleteOperations(actions, bound, r.pkg.idx.reachesClient)

	// If the resource opts into transparent tagging (@Tags annotation), the
	// provider makes additional SDK tagging calls when `tags` is set — calls
	// that don't appear in the resource's own CRUD functions. Add them as
	// permissions gated on the `tags` attribute.
	// The tagging functions may live in any file of the package, such as a
	// hand-written tags.go, and call helpers such as a paging function in
	// list_pages.go.
	tagActions := TagActions{}
	if r.tagged {
		tagActions = r.pkg.tagActions(r.tags)
	}
	if !tagActions.Empty() {
		addTagActions(schema, "create", tagActions.Apply)
		addTagActions(schema, "update", tagActions.Apply)
		addTagActions(schema, "update", tagActions.Remove)

		// The list-tags SDK call (e.g. kms:ListResourceTags) is made
		// unconditionally on every resource Read for @Tags-annotated
		// resources, and Create returns Read — so it's needed on both
		// read and create without any attribute gating.
		//
		// The interceptor skips it when the operation's function sets the
		// tags itself, as a read that takes them from its API response does.
		for _, op := range []string{"read", "create"} {
			if !r.setsTagsOut(op) {
				addUnconditionalActions(schema, op, tagActions.List)
			}
		}
	}

	applyCorrections(schema)
	applySchemaGates(schema)
	return schema
}

// setsTagsOut reports whether the function bound to op sets the resource's
// tags from the service API on every run, so the tag interceptor does not list
// them.
func (r resourceFile) setsTagsOut(op string) bool {
	for _, fn := range r.funcs[op] {
		if r.pkg.idx.setsTagsOut(fn) {
			return true
		}
	}
	return false
}

// schemaCorrection records an action that the parser includes unconditionally
// but the provider reaches only under a runtime condition that plan-level data
// cannot express as a static attribute gate.
type schemaCorrection struct {
	tfType string
	op     string
	action string
}

// schemaCorrections is the list of parser over-inclusions. Each entry removes
// one action from one operation on one resource type. The implied-requirements
// layer in internal/iam/implied.go re-adds any action that can be detected
// from plan-level signals (for example, co-deleted resources that prove the
// condition holds).
var schemaCorrections = []schemaCorrection{
	// The provider calls RemoveRoleFromInstanceProfile only when
	// ListInstanceProfilesForRole returns a non-empty list. The aws_iam_role
	// resource schema has no attribute that captures instance-profile
	// membership, so the parser cannot express the condition as a gate.
	// internal/iam/implied.go adds it back when co-deleted
	// aws_iam_instance_profile resources reference this role.
	{tfType: "aws_iam_role", op: "delete", action: "iam:RemoveRoleFromInstanceProfile"},
}

// schemaGate records the gate of an action the parser lists ungated because
// the guard it sees tests a runtime result rather than a plan attribute.
//
// The parser emits a gate only for a named attribute, from the guard helpers
// in guards.go. When the provider fills a slice from a runtime List call and
// loops over the result, no attribute appears in the guard, so the parser
// records an ungated path. The plan does carry the attribute that decides the
// call, so the gate is written here instead.
type schemaGate struct {
	tfType string
	op     string
	action string
	gate   iam.Gate
}

// schemaGates is the list of parser under-specifications. The entries for one
// operation, action and resource type replace every path on which that
// operation reaches the action: each entry becomes one path, in the order
// listed. Several entries give an action that runs on any of several
// attributes. No entry re-adds an action the parser left out; that is what
// schemaCorrections does.
var schemaGates = []schemaGate{
	// resourceRoleCreate, resourceRoleUpdate and resourceRoleRead all end in
	// the role read, which calls GetRolePolicy once per name that
	// ListRolePolicies returned. A role with no inline policy yields no name,
	// so the call runs only when the role has one. The loop reads a runtime
	// list, so the parser cannot see the attribute that decides it; the role's
	// inline_policy attribute does, and iam:PutRolePolicy on the same path
	// already carries that guard.
	{tfType: "aws_iam_role", op: "create", action: "iam:GetRolePolicy", gate: iam.Gate{Attribute: "inline_policy", ValueGuarded: true}},
	{tfType: "aws_iam_role", op: "update", action: "iam:GetRolePolicy", gate: iam.Gate{Attribute: "inline_policy", ValueGuarded: true}},
	{tfType: "aws_iam_role", op: "read", action: "iam:GetRolePolicy", gate: iam.Gate{Attribute: "inline_policy", ValueGuarded: true}},

	// resourceCertificateCreate calls RequestCertificate when the
	// configuration sets domain_name, and ImportCertificate in the else
	// branch. Schema rules keep the two apart: domain_name conflicts with
	// certificate_body and private_key_wo. The else branch tests no
	// attribute, so the parser lists the import ungated and every requested
	// certificate reports it. The import runs when the author gives a
	// certificate_body. certificate_body is not sensitive, unlike private_key,
	// whose value the plan may withhold. private_key_wo is write-only, so a
	// certificate imported through it has no certificate_body to key on, and
	// its planned value is always null, so a presence gate on the plan state
	// would never hold. Both paths are value guards: a value guard holds when
	// the plan's configuration section sets the attribute, which a write-only
	// attribute does.
	{tfType: "aws_acm_certificate", op: "create", action: "acm:ImportCertificate", gate: iam.Gate{Attribute: "certificate_body", ValueGuarded: true}},
	{tfType: "aws_acm_certificate", op: "create", action: "acm:ImportCertificate", gate: iam.Gate{Attribute: "private_key_wo", ValueGuarded: true}},

	// From 6.x, resourceBucketCreate passes the tags to CreateBucket, which
	// needs s3:TagResource. When the call fails with "is not authorized to
	// perform: s3:TagResource", create calls CreateBucket again without
	// tags and tags the bucket through PutBucketTagging. The UpdateTags of
	// the s3 service package, which update and transparent tagging use, does
	// the same: it tries TagResource and UntagResource through s3control and
	// falls back to PutBucketTagging and DeleteBucketTagging when either is
	// denied. A denied TagResource or UntagResource never fails the apply,
	// so their paths are best-effort; the fallback keeps its own gates.
	// Provider 5.x makes neither call, so these entries change nothing there.
	{tfType: "aws_s3_bucket", op: "create", action: "s3:TagResource", gate: iam.Gate{Attribute: "tags", BestEffort: true}},
	{tfType: "aws_s3_bucket", op: "update", action: "s3:TagResource", gate: iam.Gate{Attribute: "tags", BestEffort: true}},
	{tfType: "aws_s3_bucket", op: "update", action: "s3:UntagResource", gate: iam.Gate{Attribute: "tags", BestEffort: true}},

	// From 6.x, create, read and delete reach ListSecretVersionIds through
	// findSecretVersionForExistence or the read's write-only branch. Both
	// list versions only when the version holds a write-only value
	// (secret_string_wo), whose GetSecretValue would return nothing, or when
	// GetSecretValue fails because the KMS key is unavailable. The plan
	// shows the first through the configured secret_string_wo. The second
	// is a runtime failure no plan attribute shows, so a readable version
	// does not need the permission. Update also lists versions to move
	// AWSCURRENT, which it does only when version_stages changes; in 5.x
	// that is the only call, and update runs only on that change, since
	// every other argument forces a replacement.
	{tfType: "aws_secretsmanager_secret_version", op: "create", action: "secretsmanager:ListSecretVersionIds", gate: iam.Gate{Attribute: "secret_string_wo", ValueGuarded: true}},
	{tfType: "aws_secretsmanager_secret_version", op: "read", action: "secretsmanager:ListSecretVersionIds", gate: iam.Gate{Attribute: "secret_string_wo", ValueGuarded: true}},
	{tfType: "aws_secretsmanager_secret_version", op: "delete", action: "secretsmanager:ListSecretVersionIds", gate: iam.Gate{Attribute: "secret_string_wo", ValueGuarded: true}},
	{tfType: "aws_secretsmanager_secret_version", op: "update", action: "secretsmanager:ListSecretVersionIds", gate: iam.Gate{Changed: "version_stages"}},
	{tfType: "aws_secretsmanager_secret_version", op: "update", action: "secretsmanager:ListSecretVersionIds", gate: iam.Gate{Attribute: "secret_string_wo", ValueGuarded: true}},
}

// applySchemaGates replaces the gate of the paths listed in schemaGates. Like
// applyCorrections it is called after all parser-derived and tag-derived
// requirements are assembled, so it takes effect whatever path added the
// action.
func applySchemaGates(schema *iam.Schema) {
	type target struct{ op, action string }
	gates := make(map[target][]iam.Gate)
	var order []target
	for _, g := range schemaGates {
		if g.tfType != schema.TypeName {
			continue
		}
		t := target{g.op, g.action}
		if _, seen := gates[t]; !seen {
			order = append(order, t)
		}
		gates[t] = append(gates[t], g.gate)
	}
	for _, t := range order {
		reqs, ok := schema.Ops[t.op]
		if !ok {
			continue
		}
		out := make([]iam.Requirement, 0, len(reqs)+len(gates[t]))
		emitted, changed := false, false
		for _, r := range reqs {
			if r.Action != t.action {
				out = append(out, r)
				continue
			}
			if emitted {
				changed = true
				continue
			}
			emitted = true
			for _, gate := range gates[t] {
				out = append(out, iam.Requirement{Action: t.action, Gate: gate})
			}
			changed = changed || len(gates[t]) != 1 || r.Gate != gates[t][0]
		}
		if changed {
			schema.Ops[t.op] = out
		}
	}
}

// applyCorrections removes the actions listed in schemaCorrections from the
// schema. It is called after all parser-derived and tag-derived requirements
// are assembled, so it takes effect regardless of the analysis path that added
// the action.
func applyCorrections(schema *iam.Schema) {
	for _, c := range schemaCorrections {
		if c.tfType != schema.TypeName {
			continue
		}
		reqs := schema.Ops[c.op]
		out := make([]iam.Requirement, 0, len(reqs))
		for _, r := range reqs {
			if r.Action != c.action {
				out = append(out, r)
			}
		}
		if len(out) != len(reqs) {
			schema.Ops[c.op] = out
		}
	}
}

// addUnconditionalActions adds actions to the given operation without any
// conditional gating, skipping any already present for that operation.
func addUnconditionalActions(schema *iam.Schema, op string, actions []string) {
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
func addTagActions(schema *iam.Schema, op string, actions []string) {
	tags := iam.Gate{Attribute: "tags"}
	for _, action := range actions {
		setGates(schema, op, action, append(schema.Gates(op, action), tags))
	}
}

// setGates replaces the paths of an action with the given gates, without the
// paths another path subsumes. A path that always runs and whose failure
// counts leaves the action ungated. The action keeps its place among the
// operation's requirements, or goes last when it is new.
func setGates(schema *iam.Schema, op, action string, gates []iam.Gate) {
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

// resourceTypesFromAnnotation extracts the terraform resource types from the
// @SDKResource annotations in the Go source code, in source order. A file
// may declare its resource under a deprecated name and its current one:
//
//	// @SDKResource("aws_alb_listener", name="Listener")
//	// @SDKResource("aws_lb_listener", name="Listener")
//
// Returns nil if no annotation is found.
func resourceTypesFromAnnotation(src []byte) []string {
	var types []string
	for _, m := range sdkResourceAnnotationRE.FindAllSubmatch(src, -1) {
		types = append(types, string(m[1]))
	}
	return types
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
func incompleteOperations(actions map[string][]iam.Requirement, bound map[string]string, usesClient func(string) bool) map[string]bool {
	var out map[string]bool
	for _, op := range []string{"create", "read", "delete"} {
		fn, ok := bound[op]
		if !ok || fn == "" || !usesClient(fn) {
			continue
		}
		complete := len(actions[op]) > 0
		if complete && op != "read" {
			complete = false
			for _, r := range actions[op] {
				if !isReadOnlyAction(r.Action) {
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
