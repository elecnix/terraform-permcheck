// Package check runs the validate pipeline once for both input modes: parse
// the policy, resolve each resource type's schema, validate the resource
// changes against the policy, check the declared needs, and apply config
// exclusions. The caller reads
// the input and renders the Result; check does neither.
package check

import (
	"fmt"
	"sync"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

// DefaultResolver resolves schemas from the terraform-provider-aws source and
// falls back to the CloudFormation schema registry. The resolver is built on
// the first call and shared for the life of the process, so the provider
// source is parsed once, however many checks run. It reads the provider
// cache directory when it is built.
func DefaultResolver() iam.Resolver {
	defaultOnce.Do(func() {
		defaultResolver = cloud.NewChainProvider(
			provideraws.NewSourceProvider(),
			cloud.NewAWSProvider(),
		)
	})
	return defaultResolver
}

var (
	defaultOnce     sync.Once
	defaultResolver iam.Resolver
)

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

// Config maps the settings onto an iam.FilterConfig. OnlyRequired and
// StrictResources apply on top of NoFilter, so both flags together still
// drop conditional permissions.
func (f Filter) Config() iam.FilterConfig {
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

func (in Input) empty() bool {
	return len(in.changes) == 0 && len(in.blocks) == 0
}

// Options configure a check.
type Options struct {
	Filter Filter
	// Exclusions are the config exclusions. Matching gaps move from
	// Result.Missing to Result.Excluded.
	Exclusions []iam.Exclusion
	// Resolver supplies schemas. Nil means DefaultResolver.
	Resolver iam.Resolver
	// Needs are the declared needs from the config. Run checks the ones that
	// Principal selects (see iam.SelectNeeds).
	Needs []iam.Need
	// Principal selects the needs declared for one principal (--principal).
	Principal string
}

// Result is the outcome of a check, ready for the report layer.
type Result struct {
	// Missing are the gaps that remain after exclusions.
	Missing []iam.MissingAction
	// Excluded are the gaps a config exclusion matched.
	Excluded []iam.ExcludedAction
	// Checked counts resource changes in plan mode and distinct resource
	// types in static mode.
	Checked int
	// Label names what Checked counts.
	Label string
	// Needs counts the declared needs checked.
	Needs int
}

// Run checks the input and the selected needs against the policy that
// loadPolicy returns. When there is nothing to check, Run returns an empty
// Result without loading the policy. Run returns loadPolicy's error unchanged
// and wraps a parse error.
func Run(in Input, loadPolicy func() ([]byte, error), opts Options) (Result, error) {
	needs, err := iam.SelectNeeds(opts.Needs, opts.Principal)
	if err != nil {
		return Result{}, err
	}
	res := Result{Label: in.label(), Needs: len(needs)}
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
		resolver = DefaultResolver()
	}

	changes := in.changes
	res.Checked = len(changes)
	if in.static {
		changes, res.Checked = staticChanges(in.blocks, resolver)
	}

	missing, err := iam.Validate(changes, policy, resolver, opts.Filter.Config())
	if err != nil {
		return Result{}, err
	}
	missing = append(missing, iam.CheckNeeds(needs, policy, opts.Filter.StrictResources)...)
	res.Missing, res.Excluded = iam.ApplyExclusions(missing, opts.Exclusions)
	return res, nil
}
