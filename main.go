// terraform-permcheck validates that a terraform deploy role has sufficient IAM
// permissions for every resource in a terraform plan.
//
// Usage:
//
//	terraform show -json plan.tfplan | terraform-permcheck validate --policy-file deploy_policy.json --cloud aws
//
//	terraform-permcheck validate --plan-file plan.json --policy-file deploy_policy.json --cloud aws
//
//	terraform show -json plan.tfplan | terraform-permcheck validate --policy-from-plan-output deploy_policy_json --cloud aws
//
//	terraform-permcheck validate --plan-file plan.json --policy-from-state-output deploy_policy_json --state-file state.json --cloud aws
//	terraform-permcheck validate --terraform-root ./terraform --policy-file deploy_policy.json --cloud aws
//
// Regenerate the embedded permissions table and the IAM service tables after
// bumping DefaultProviderRef:
//
//	go run . generate-permissions --out internal/permdata/permissions.json
//	go run internal/provideraws/gen_iam_services.go -provider <checkout>
//
// GitHub Actions annotations (warn, don't fail):
//
//	terraform show -json plan.tfplan | terraform-permcheck validate \
//	  --policy-file deploy_policy.json --cloud aws \
//	  --format github-annotations --exit-zero
//
//	# With file/line annotations (inline in the PR "Files changed" tab).
//	# --terraform-root without --plan-file is static HCL mode, so pass
//	# --plan-file - to read the plan from stdin:
//	terraform show -json plan.tfplan | terraform-permcheck validate \
//	  --plan-file - --policy-file deploy_policy.json --cloud aws \
//	  --format github-annotations --terraform-root . --exit-zero
//
// JSON output (machine-readable, for CI integration):
//
//	terraform show -json plan.tfplan | terraform-permcheck validate \
//	  --plan-file - --policy-from-plan-output deploy_policy_json --cloud aws \
//	  --format json --terraform-root . --exit-zero
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/config"
	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/permdata"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
	"github.com/elecnix/terraform-permcheck/internal/report"
)

// errGapsFound is returned by validateCmd when permission gaps are detected
// and --exit-zero is not set. run() translates this to exit code 1.
var errGapsFound = errors.New("permission gaps found")

func main() {
	err := run(os.Args[1:])
	if code := exitCode(err); code == 2 {
		fmt.Fprintf(os.Stderr, "terraform-permcheck: %v\n", err)
		os.Exit(code)
	} else if code != 0 {
		os.Exit(code)
	}
}

// exitCode maps the result of run to the process exit code: 0 when the run
// passed, 1 when it found permission gaps, and 2 for any other error, such as
// bad input or a failed schema lookup.
func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errGapsFound):
		return 1
	default:
		return 2
	}
}

// version is the single source of truth for the release version — bump it
// here when tagging a release; the version test derives its expectation from
// this constant.
const version = "v0.8.1"

// usage is the top-level help text.
const usage = `Usage: terraform-permcheck <command> [flags]

Commands:
  validate               check that an IAM policy grants what a Terraform plan or root needs
  generate-permissions   regenerate the embedded provider permissions table
  version                print the version
  help [command]         print this help, or the flags of a command

Run 'terraform-permcheck <command> -h' to list the flags of a command.
`

func run(args []string) error {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("a command is required")
	}

	var err error
	switch args[0] {
	case "validate":
		err = validateCmd(args[1:])
	case "generate-permissions":
		err = generatePermissionsCmd(args[1:])
	case "version", "--version", "-version":
		if len(args) > 1 {
			return fmt.Errorf("unexpected argument %q", args[1])
		}
		fmt.Println("terraform-permcheck " + version)
	case "help", "-h", "--help", "-help":
		if len(args) > 1 && args[0] == "help" {
			return run([]string{args[1], "-h"})
		}
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command: %s", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

// newFlagSet returns a flag set for a subcommand whose usage line shows
// synopsis after the command name.
func newFlagSet(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: terraform-permcheck %s %s\n\nFlags:\n", name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags parses args into fs. Asked for help, it prints the usage to
// stdout and returns flag.ErrHelp, which run treats as success. On a bad flag
// or a positional argument it prints the usage to stderr and returns the
// error. A positional argument is an error because the flag package stops at
// it, so any flag after it would be dropped.
func parseFlags(fs *flag.FlagSet, args []string) error {
	// The flag package prints its own error message too; run's caller prints
	// the returned error instead.
	fs.SetOutput(io.Discard)
	err := fs.Parse(args)
	if err == nil && fs.NArg() > 0 {
		err = fmt.Errorf("unexpected argument %q (flags go before arguments, and %s takes none)", fs.Arg(0), fs.Name())
	}
	switch {
	case errors.Is(err, flag.ErrHelp):
		fs.SetOutput(os.Stdout)
		fs.Usage()
	case err != nil:
		fs.SetOutput(os.Stderr)
		fs.Usage()
	}
	return err
}

func validateCmd(args []string) error {
	fs := newFlagSet("validate", "[flags]")
	planFile := fs.String("plan-file", "", "path to terraform plan JSON, or - for stdin (default: stdin when --terraform-root is not set)")
	policyFile := fs.String("policy-file", "", "path to IAM policy JSON")
	policyFromPlanOutput := fs.String("policy-from-plan-output", "", "read IAM policy from named output in plan JSON")
	policyFromStateOutput := fs.String("policy-from-state-output", "", "read IAM policy from named output in state JSON")
	stateFile := fs.String("state-file", "", "path to terraform state JSON, or - for stdin, for use with --policy-from-state-output (default: stdin)")
	cloudName := fs.String("cloud", "", "cloud provider: aws (required)")
	noFilter := fs.Bool("no-filter", false, "disable permission filtering (report all CFN schema permissions)")
	onlyRequired := fs.Bool("only-required", false, "suppress conditional permissions (show only unconditional [required] actions)")
	terraformRoot := fs.String("terraform-root", "", "root directory of terraform configuration for file/line annotations in github-annotations/json output; without --plan-file, also turns on static HCL mode")
	format := fs.String("format", "text", "output format: text, github-annotations, json")
	exitZero := fs.Bool("exit-zero", false, "exit with code 0 even when permission gaps are found")
	configFile := fs.String("config", "", "path to permcheck config JSON (default: ./permcheck.json if present)")
	showExcluded := fs.Bool("show-excluded", false, "list config-excluded permissions in the report (default: suppressed silently)")
	principal := fs.String("principal", "", "also check the needs the config declares for this principal (needs without a principal are always checked)")
	strictResources := fs.Bool("strict-resources", false, "report an action as unverified when its target ARN is unknown and the policy grants it only on some resources (default: from config strict_resources)")
	allowUnresolved := fs.Bool("allow-unresolved-types", false, "report resource types no schema source knows but do not fail the run on them (default: from config allow_unresolved_types)")
	providerSource := fs.String("provider-source", os.Getenv(check.ProviderSourceEnv), "where provider-source permissions come from: embedded (the table built into the binary) or live (clone and parse terraform-provider-aws) (default: $"+check.ProviderSourceEnv+", else embedded)")

	if err := parseFlags(fs, args); err != nil {
		return err
	}

	outFormat, err := report.ParseFormat(*format)
	if err != nil {
		return err
	}
	source, err := check.ParseProviderSource(*providerSource)
	if err != nil {
		return err
	}

	// Load the config (auto-discover ./permcheck.json unless --config
	// overrides). Missing default config is fine; an explicit --config path
	// that fails to load is fatal.
	cfg, err := loadConfig(*configFile)
	if err != nil {
		return err
	}
	// An explicit --strict-resources or --allow-unresolved-types, true or
	// false, overrides the config.
	strict := cfg.StrictResources
	allowUnresolvedTypes := cfg.AllowUnresolvedTypes
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "strict-resources":
			strict = *strictResources
		case "allow-unresolved-types":
			allowUnresolvedTypes = *allowUnresolved
		}
	})
	opts := check.Options{
		Filter: check.Filter{
			NoFilter:        *noFilter,
			OnlyRequired:    *onlyRequired,
			StrictResources: strict,
		},
		Exclusions: cfg.Exclude,
		Needs:      cfg.Needs,
		Principal:  *principal,

		AllowUnresolvedTypes: allowUnresolvedTypes,

		Resolver: check.ResolverFor(source),
	}

	sources := check.Sources{
		PlanFile:      *planFile,
		TerraformRoot: *terraformRoot,
		Policy: check.PolicySource{
			File:        *policyFile,
			PlanOutput:  *policyFromPlanOutput,
			StateOutput: *policyFromStateOutput,
			StateFile:   *stateFile,
		},
	}
	stdin := processStdin()
	static := sources.Static()

	// Build resource-to-file location map when --terraform-root is set, for
	// the file= and line= parameters of annotations. A plan names resources
	// by address, and the parser knows the address of root-module blocks
	// only, so plan mode maps those. Static mode checks every block it
	// parsed, so it maps every block.
	var locations report.Locations
	if *terraformRoot != "" {
		mapResources := hcl.MapRootResources
		if static {
			mapResources = hcl.MapResources
		}
		var locErr error
		locations, locErr = mapResources(*terraformRoot)
		if locErr != nil {
			// Non-fatal: continue without file locations.
			fmt.Fprintf(os.Stderr, "terraform-permcheck: building file map: %v\n", locErr)
		}
	}

	if err := sources.Validate(stdin); err != nil {
		return err
	}
	prefix, err := check.CloudPrefix(*cloudName)
	if err != nil {
		return err
	}
	if static {
		if sources.StdinIgnored(stdin) {
			fmt.Fprintln(os.Stderr, "terraform-permcheck: --terraform-root without --plan-file runs static HCL mode; stdin is ignored. Pass --plan-file - to check a piped plan.")
		}
		return validateStaticHCL(*terraformRoot, sources.Policy, opts, outFormat, *exitZero, locations, *showExcluded)
	}

	planRaw, err := sources.ReadPlan(stdin)
	if err != nil {
		return err
	}
	policyRaw, err := sources.Policy.Load(planRaw, stdin.Read)
	if err != nil {
		return err
	}
	changes, err := plan.Parse(planRaw, prefix)
	if err != nil {
		return fmt.Errorf("parse plan: %w", err)
	}

	res, err := check.Run(check.FromPlan(changes), func() ([]byte, error) { return policyRaw, nil }, opts)
	if err != nil {
		return err
	}

	return reportResult(res, outFormat, *exitZero, *showExcluded, locations)
}

// processStdin describes os.Stdin to the input rules without reading it.
func processStdin() check.Stdin {
	in := check.Stdin{Read: func() ([]byte, error) { return io.ReadAll(os.Stdin) }}
	stat, err := os.Stdin.Stat()
	if err != nil {
		return in
	}
	switch mode := stat.Mode(); {
	case mode&os.ModeCharDevice != 0:
		// A terminal, or /dev/null. Either way there is no plan to read.
		in.Terminal = true
	case mode.IsRegular():
		in.MayHoldPlan = stat.Size() > 0
	default:
		in.MayHoldPlan = true
	}
	return in
}

// defaultConfigFile is the config file auto-discovered in the working
// directory when --config is not given.
const defaultConfigFile = "permcheck.json"

// loadConfig resolves the permcheck config. When configPath is set it is
// loaded explicitly (a load failure is fatal). Otherwise ./permcheck.json is
// used if present; an absent default config yields an empty config.
func loadConfig(configPath string) (*config.Config, error) {
	path := configPath
	if path == "" {
		if _, err := os.Stat(defaultConfigFile); err != nil {
			return &config.Config{}, nil // no default config present
		}
		path = defaultConfigFile
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	return cfg, nil
}

// reportResult prints the check result and returns errGapsFound when
// actionable (non-excluded) gaps remain and --exit-zero was not set. A gap is
// a missing or unverified permission, or a resource type no schema source
// knows unless unresolved types are allowed. Excluded findings never fail
// the run.
func reportResult(res check.Result, format report.Format, exitZero, showExcluded bool, locations report.Locations) error {
	printReport(res, format, locations, showExcluded)
	if res.HasGaps() && !exitZero {
		return errGapsFound
	}
	return nil
}

// printReport writes the report of res in the given format. The report
// package decides the content and which stream each part goes to.
func printReport(res check.Result, format report.Format, locations report.Locations, showExcluded bool) {
	report.New(res, locations, showExcluded).Write(format, os.Stdout, os.Stderr)
}

// validateStaticHCL runs validation against terraform configuration files
// directly, without requiring a terraform plan or AWS credentials. It
// over-approximates: every resource type referenced in .tf files is included
// regardless of count, for_each, or whether the resource would actually be
// created.
func validateStaticHCL(terraformRoot string, policySource check.PolicySource, opts check.Options, format report.Format, exitZero bool, locations report.Locations, showExcluded bool) error {
	blocks, err := hcl.ParseDir(terraformRoot)
	if err != nil {
		return fmt.Errorf("parse terraform configurations: %w", err)
	}

	// The policy file is read only when there is something to check.
	readPolicy := func() ([]byte, error) { return policySource.Load(nil, nil) }
	res, err := check.Run(check.FromHCL(blocks), readPolicy, opts)
	if err != nil {
		return err
	}

	return reportResult(res, format, exitZero, showExcluded, locations)
}

// generatePermissionsCmd parses the terraform-provider-aws source and writes
// the permissions table that the binary embeds. Without --provider-dir it
// clones provideraws.DefaultProviderRef into the provider cache.
func generatePermissionsCmd(args []string) error {
	fs := newFlagSet("generate-permissions", "[flags]")
	providerDir := fs.String("provider-dir", "", "use this terraform-provider-aws checkout, which must be at "+provideraws.DefaultProviderRef+" (default: clone it into the provider cache)")
	out := fs.String("out", "-", "write the table to this file (default: stdout); the embedded table is "+permdata.EmbeddedFile)
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	src := provideraws.NewSourceProvider()
	if *providerDir != "" {
		src = provideraws.NewSourceProviderWithPath(*providerDir)
	}
	schemas, err := src.Schemas()
	if err != nil {
		return fmt.Errorf("generate permissions: %w", err)
	}
	data, err := permdata.Generate(schemas, provideraws.DefaultProviderRef)
	if err != nil {
		return fmt.Errorf("generate permissions: %w", err)
	}
	if *out == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return writeFileAtomic(*out, data)
}

// writeFileAtomic writes data to a temporary file next to path and renames it
// into place, so path never holds a partial table.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
