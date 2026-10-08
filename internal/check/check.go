// Package check runs the validate pipeline once for both input modes: parse
// the policy, resolve each resource type's schema, validate the resource
// changes against the policy, check the declared needs, and apply config
// exclusions. The caller reads
// the input and renders the Result; check does neither.
package check

import (
	"fmt"
	"strings"
	"sync"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/permdata"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

// ProviderSource names where the default chain reads provider-source
// requirements from.
type ProviderSource string

const (
	// SourceEmbedded reads the table built into the binary. It needs no
	// clone and no parse. It is the default.
	SourceEmbedded ProviderSource = "embedded"
	// SourceLive clones terraform-provider-aws at DefaultProviderRef into
	// the provider cache and parses its Go source, as releases before the
	// embedded table did. It is for developing the parser.
	SourceLive ProviderSource = "live"
)

// ProviderSourceEnv names the environment variable that selects the provider
// source when --provider-source is not given.
const ProviderSourceEnv = "PERMCHECK_PROVIDER_SOURCE"

// ParseProviderSource reads a provider source name. The empty string means
// SourceEmbedded.
func ParseProviderSource(s string) (ProviderSource, error) {
	switch ProviderSource(strings.ToLower(s)) {
	case "", SourceEmbedded:
		return SourceEmbedded, nil
	case SourceLive:
		return SourceLive, nil
	}
	return "", fmt.Errorf("unknown provider source %q (supported: %s, %s)", s, SourceEmbedded, SourceLive)
}

// ResolverFor returns the resolver chain of a provider source. Each chain is
// built on the first call and shared for the life of the process, so the
// table is decoded, or the provider source parsed, once however many checks
// run. The live chain reads the provider cache directory when it is built.
func ResolverFor(src ProviderSource) iam.Resolver {
	r := &resolvers.embedded
	if src == SourceLive {
		r = &resolvers.live
	}
	r.once.Do(func() {
		r.resolver = cloud.NewChainProvider(providers(src)...)
	})
	return r.resolver
}

// providers lists the chain of a provider source, most precise first. The
// live parse replaces the embedded table rather than following it. Both list
// the same operations, so a live parse after the table would fill the
// table's incomplete operations with the same calls, mark them complete, and
// keep CloudFormation from filling them.
func providers(src ProviderSource) []iam.Resolver {
	var first iam.Resolver = permdata.Embedded()
	if src == SourceLive {
		first = provideraws.NewSourceProvider()
	}
	return []iam.Resolver{first, cloud.NewAWSProvider()}
}

type sharedResolver struct {
	once     sync.Once
	resolver iam.Resolver
}

var resolvers struct {
	embedded, live sharedResolver
}

// Filter holds the filter settings of the validate command.
type Filter struct {
	// NoFilter reports every permission class (--no-filter).
	NoFilter bool
	// OnlyRequired drops conditional permissions (--only-required).
	OnlyRequired bool
	// StrictResources reports a grant scoped to a target the tool cannot
	// derive as unverified (--strict-resources or the strict_resources
	// config key). Static mode has no ARNs, so there it checks every scoped
	// grant.
	StrictResources bool
}

// config maps the settings onto an iam.FilterConfig. OnlyRequired and
// StrictResources apply on top of NoFilter, so both flags together still
// drop conditional permissions.
func (f Filter) config() iam.FilterConfig {
	cfg := iam.DefaultFilter()
	if f.NoFilter {
		cfg = iam.FilterConfig{} // all zero values = no filtering
	}
	if f.OnlyRequired {
		cfg.ExcludeConditional = true
	}
	cfg.StrictResources = f.StrictResources
	return cfg
}

// Input is what a check runs over: the resource changes of a terraform plan,
// or the resource blocks of a terraform root in static HCL mode.
type Input struct {
	changes []*plan.ResourceChange
	blocks  []hcl.ResourceBlock
	static  bool
}

// FromPlan returns the input for plan mode.
func FromPlan(changes []*plan.ResourceChange) Input {
	return Input{changes: changes}
}

// FromHCL returns the input for static HCL mode. Static mode does not know
// count, for_each or what terraform would change, so it checks every
// resource type it finds.
func FromHCL(blocks []hcl.ResourceBlock) Input {
	return Input{blocks: blocks, static: true}
}

// label names what the input counts, for the report.
func (in Input) label() string {
	if in.static {
		return "resource types (static HCL mode)"
	}
	return "resource changes"
}

// empty reports whether the input has nothing to check. A plan of no-op
// changes has none.
func (in Input) empty() bool {
	return countResources(in.changes) == 0 && len(in.blocks) == 0
}

// countResources counts the resources whose changes need a check. A replace
// is checked as a delete and a create of one resource, so it counts once. A
// no-op is not checked and does not count.
func countResources(changes []*plan.ResourceChange) int {
	seen := make(map[string]bool, len(changes))
	n := 0
	for i, rc := range changes {
		if !rc.Checked() {
			continue
		}
		// A change without an address (a test, say) counts on its own.
		key := rc.Address
		if key == "" {
			key = fmt.Sprint(i)
		}
		if !seen[key] {
			seen[key] = true
			n++
		}
	}
	return n
}

// Options configure a check.
type Options struct {
	Filter Filter
	// Exclusions are the config exclusions. Matching gaps move from
	// Result.Missing to Result.Excluded.
	Exclusions []iam.Exclusion
	// Resolver supplies schemas. Nil means ResolverFor(SourceEmbedded): the
	// embedded provider-source table, then the CloudFormation schema registry.
	Resolver iam.Resolver
	// Needs are the declared needs from the config. Run checks the ones that
	// Principal selects (see iam.SelectNeeds).
	Needs []iam.Need
	// Principal selects the needs declared for one principal (--principal).
	Principal string
	// AllowUnresolvedTypes keeps unresolved resource types from failing the
	// run (--allow-unresolved-types or the allow_unresolved_types config
	// key). They are still reported.
	AllowUnresolvedTypes bool
}

// Result is the outcome of a check, ready for the report layer.
type Result struct {
	// Missing are the gaps that remain after exclusions.
	Missing []iam.MissingAction
	// Excluded are the gaps a config exclusion matched.
	Excluded []iam.ExcludedAction
	// Checked counts the resources with a change in plan mode and distinct
	// resource types in static mode. Neither count includes an unresolved type.
	Checked int
	// Label names what Checked counts.
	Label string
	// Needs counts the declared needs checked.
	Needs int
	// Unresolved are the resource changes whose type no schema source
	// knows, after exclusions. The tool has no permission data for them.
	Unresolved []iam.MissingAction
	// UnresolvedAllowed reports that unresolved types do not fail the run.
	UnresolvedAllowed bool
}

// HasGaps reports whether the result should fail the run: a missing or
// unverified permission remains, or a resource type is unresolved and not
// allowed.
func (r Result) HasGaps() bool {
	return len(r.Missing) > 0 || (len(r.Unresolved) > 0 && !r.UnresolvedAllowed)
}

// Run checks the input and the selected needs against the policy that
// loadPolicy returns. When there is nothing to check, Run returns an empty
// Result without loading the policy. Run returns loadPolicy's error unchanged
// and wraps a parse error. A schema lookup that fails (iam.ErrLookupFailed)
// is an error too, since the result would not say what was checked.
func Run(in Input, loadPolicy func() ([]byte, error), opts Options) (Result, error) {
	needs, err := iam.SelectNeeds(opts.Needs, opts.Principal)
	if err != nil {
		return Result{}, err
	}
	res := Result{Label: in.label(), Needs: len(needs), UnresolvedAllowed: opts.AllowUnresolvedTypes}
	if in.empty() && len(needs) == 0 {
		return res, nil
	}

	raw, err := loadPolicy()
	if err != nil {
		return Result{}, err
	}
	policy, err := iam.ParsePolicy(raw)
	if err != nil {
		return Result{}, fmt.Errorf("parse policy: %w", err)
	}

	resolver := opts.Resolver
	if resolver == nil {
		resolver = ResolverFor(SourceEmbedded)
	}
	resolver = newMemoResolver(resolver)

	changes := in.changes
	res.Checked = countResources(changes)
	if in.static {
		changes, res.Checked, err = staticChanges(in.blocks, resolver)
		if err != nil {
			return Result{}, err
		}
	}

	missing, err := iam.Validate(changes, policy, resolver, opts.Filter.config())
	if err != nil {
		return Result{}, err
	}
	if !in.static {
		// A resource whose type no source knows is not checked, as in static
		// mode, whether or not an exclusion hides it.
		unresolved := make(map[string]bool)
		for _, m := range missing {
			if m.Unresolved {
				unresolved[m.ResourceType] = true
			}
		}
		if len(unresolved) > 0 {
			var resolved []*plan.ResourceChange
			for _, rc := range changes {
				if !unresolved[rc.Type] {
					resolved = append(resolved, rc)
				}
			}
			res.Checked = countResources(resolved)
		}
	}
	missing = append(missing, iam.CheckNeeds(needs, policy, opts.Filter.StrictResources)...)
	kept, excluded := iam.ApplyExclusions(missing, opts.Exclusions)
	res.Excluded = excluded
	for _, m := range kept {
		if m.Unresolved {
			res.Unresolved = append(res.Unresolved, m)
		} else {
			res.Missing = append(res.Missing, m)
		}
	}
	return res, nil
}

// memoResolver remembers each lookup of a run, error included, so a type
// that many changes share is fetched once. Static mode resolves each type
// before validation and validation resolves it again, so an unknown type
// would otherwise query the CloudFormation registry twice.
type memoResolver struct {
	next  iam.Resolver
	cache map[string]memoEntry
}

type memoEntry struct {
	schema *iam.Schema
	err    error
}

func newMemoResolver(next iam.Resolver) *memoResolver {
	return &memoResolver{next: next, cache: make(map[string]memoEntry)}
}

func (m *memoResolver) Resolve(tfType string) (*iam.Schema, error) {
	if e, ok := m.cache[tfType]; ok {
		return e.schema, e.err
	}
	s, err := m.next.Resolve(tfType)
	m.cache[tfType] = memoEntry{s, err}
	return s, err
}
