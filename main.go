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
// GitHub Actions annotations (warn, don't fail):
//
//	terraform show -json plan.tfplan | terraform-permcheck validate \
//	  --policy-file deploy_policy.json --cloud aws \
//	  --format github-annotations --exit-zero
//
//	# With file/line annotations (inline in the PR "Files changed" tab):
//	terraform show -json plan.tfplan | terraform-permcheck validate \
//	  --policy-file deploy_policy.json --cloud aws \
//	  --format github-annotations --terraform-root . --exit-zero
//
// JSON output (machine-readable, for CI integration):
//
//	terraform show -json plan.tfplan | terraform-permcheck validate \
//	  --policy-from-plan-output deploy_policy_json --cloud aws \
//	  --format json --terraform-root . --exit-zero
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// errGapsFound is returned by validateCmd when permission gaps are detected
// and --exit-zero is not set. run() translates this to exit code 1.
var errGapsFound = errors.New("permission gaps found")

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errGapsFound) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "terraform-permcheck: %v\n", err)
		os.Exit(2)
	}
}

// version is the single source of truth for the release version — bump it
// here when tagging a release; the version test derives its expectation from
// this constant.
const version = "v0.8.1"

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("subcommand required: validate")
	}

	switch args[0] {
	case "validate":
		return validateCmd(args[1:])
	case "version":
		fmt.Println("terraform-permcheck " + version)
		return nil
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func validateCmd(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	planFile := fs.String("plan-file", "", "path to terraform plan JSON (default: stdin)")
	policyFile := fs.String("policy-file", "", "path to IAM policy JSON")
	policyFromPlanOutput := fs.String("policy-from-plan-output", "", "read IAM policy from named output in plan JSON")
	policyFromStateOutput := fs.String("policy-from-state-output", "", "read IAM policy from named output in state JSON")
	stateFile := fs.String("state-file", "", "path to terraform state JSON (default: stdin, for use with --policy-from-state-output)")
	cloudName := fs.String("cloud", "", "cloud provider: aws (required)")
	noFilter := fs.Bool("no-filter", false, "disable permission filtering (report all CFN schema permissions)")
	onlyRequired := fs.Bool("only-required", false, "suppress conditional permissions (show only unconditional [required] actions)")
	terraformRoot := fs.String("terraform-root", "", "root directory of terraform configuration for file/line annotations in github-annotations/json output; when no plan is provided, also enables static HCL mode")
	format := fs.String("format", "text", "output format: text, github-annotations, json")
	exitZero := fs.Bool("exit-zero", false, "exit with code 0 even when permission gaps are found")
	configFile := fs.String("config", "", "path to permcheck config JSON (default: ./permcheck.json if present)")
	showExcluded := fs.Bool("show-excluded", false, "list config-excluded permissions in the report (default: suppressed silently)")
	principal := fs.String("principal", "", "also check the needs the config declares for this principal (needs without a principal are always checked)")
	strictResources := fs.Bool("strict-resources", false, "report an action as unverified when its target ARN is unknown and the policy grants it only on some resources (default: from config strict_resources)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *format != "text" && *format != "github-annotations" && *format != "json" {
		return fmt.Errorf("unsupported format %q (supported: text, github-annotations, json)", *format)
	}

	// Load the config (auto-discover ./permcheck.json unless --config
	// overrides). Missing default config is fine; an explicit --config path
	// that fails to load is fatal.
	cfg, err := loadConfig(*configFile)
	if err != nil {
		return err
	}
	// An explicit --strict-resources, true or false, overrides the config.
	strict := cfg.StrictResources
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "strict-resources" {
			strict = *strictResources
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
	}

	// Build resource-to-file location map when --terraform-root is set.
	// In plan mode, this provides file= and line= parameters for annotations.
	// In static HCL mode, this is also used (though the parser already has
	// file info).
	var locations map[string]iam.FileLocation
	if *terraformRoot != "" {
		var locErr error
		locations, locErr = hcl.MapResources(*terraformRoot)
		if locErr != nil {
			// Non-fatal: continue without file locations.
			fmt.Fprintf(os.Stderr, "terraform-permcheck: building file map: %v\n", locErr)
		}
	}

	// Determine whether we have a plan source.
	hasPlanInput := *planFile != "" || stdinHasData()

	if !hasPlanInput {
		// Static HCL mode: read resources from .tf files.
		if *terraformRoot == "" {
			return fmt.Errorf("no plan input: provide --plan-file, pipe plan JSON to stdin, or use --terraform-root for static HCL mode")
		}
		if *policyFromPlanOutput != "" || *policyFromStateOutput != "" {
			return fmt.Errorf("--policy-from-plan/output not applicable in static HCL mode (no plan available)")
		}
		return validateStaticHCL(*terraformRoot, *policyFile, *cloudName, opts, *format, *exitZero, locations, *showExcluded)
	}

	// Plan mode: read plan from stdin or file.
	// Exactly one policy source must be provided.
	policySources := 0
	if *policyFile != "" {
		policySources++
	}
	if *policyFromPlanOutput != "" {
		policySources++
	}
	if *policyFromStateOutput != "" {
		policySources++
	}
	if policySources == 0 {
		return fmt.Errorf("one of --policy-file, --policy-from-plan-output, or --policy-from-state-output is required")
	}
	if policySources > 1 {
		return fmt.Errorf("only one of --policy-file, --policy-from-plan-output, or --policy-from-state-output may be specified")
	}
	if *cloudName == "" {
		return fmt.Errorf("--cloud is required (supported: aws)")
	}
	if *cloudName != "aws" {
		return fmt.Errorf("unsupported cloud %q (supported: aws)", *cloudName)
	}

	// Read plan
	var planRaw []byte
	if *planFile != "" {
		planRaw, err = os.ReadFile(*planFile)
	} else {
		planRaw, err = readStdin()
	}
	if err != nil {
		return fmt.Errorf("read plan: %w", err)
	}

	// Read policy from the appropriate source.
	var policyRaw []byte
	if *policyFile != "" {
		policyRaw, err = os.ReadFile(*policyFile)
		if err != nil {
			return fmt.Errorf("read policy: %w", err)
		}
	} else if *policyFromPlanOutput != "" {
		rawValue, err := plan.ParseOutput(planRaw, *policyFromPlanOutput)
		if err != nil {
			return fmt.Errorf("read policy from plan output: %w", err)
		}
		policyRaw, err = unwrapJSONString(rawValue)
		if err != nil {
			return fmt.Errorf("read policy from plan output %q: %w", *policyFromPlanOutput, err)
		}
	} else if *policyFromStateOutput != "" {
		var stateRaw []byte
		if *stateFile != "" {
			stateRaw, err = os.ReadFile(*stateFile)
		} else {
			stateRaw, err = readStdin()
		}
		if err != nil {
			return fmt.Errorf("read state: %w", err)
		}
		rawValue, err := plan.ParseStateOutput(stateRaw, *policyFromStateOutput)
		if err != nil {
			return fmt.Errorf("read policy from state output: %w", err)
		}
		policyRaw, err = unwrapJSONString(rawValue)
		if err != nil {
			return fmt.Errorf("read policy from state output %q: %w", *policyFromStateOutput, err)
		}
	}

	// Parse plan
	changes, err := plan.Parse(planRaw, strings.ToLower(*cloudName)+"_")
	if err != nil {
		return fmt.Errorf("parse plan: %w", err)
	}

	res, err := check.Run(check.FromPlan(changes), func() ([]byte, error) { return policyRaw, nil }, opts)
	if err != nil {
		return err
	}

	return report(res, *format, *exitZero, *showExcluded, locations)
}

// stdinHasData returns true if stdin is a pipe (not a terminal) and has data
// ready to read.
func stdinHasData() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func readStdin() ([]byte, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, fmt.Errorf("no data on stdin and no file flag set")
	}
	return io.ReadAll(os.Stdin)
}

// defaultConfigFile is the config file auto-discovered in the working
// directory when --config is not given.
const defaultConfigFile = "permcheck.json"

// loadConfig resolves the permcheck config. When configPath is set it is
// loaded explicitly (a load failure is fatal). Otherwise ./permcheck.json is
// used if present; an absent default config yields an empty config.
func loadConfig(configPath string) (*iam.Config, error) {
	path := configPath
	if path == "" {
		if _, err := os.Stat(defaultConfigFile); err != nil {
			return &iam.Config{}, nil // no default config present
		}
		path = defaultConfigFile
	}
	cfg, err := iam.LoadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	return cfg, nil
}

// report prints the check result and returns errGapsFound when actionable
// (non-excluded) gaps remain and --exit-zero was not set. Excluded findings
// never fail the run.
func report(res check.Result, format string, exitZero, showExcluded bool, locations map[string]iam.FileLocation) error {
	printReport(res, format, locations, showExcluded)
	if len(res.Missing) > 0 && !exitZero {
		return errGapsFound
	}
	return nil
}

// printReport formats and prints the missing actions plus, when showExcluded is
// set, the config-excluded actions. In github-annotations mode output goes to
// stdout (so ::warning::/::notice:: commands are parsed by the workflow
// runner); in text mode missing/excluded go to stderr (for human readability)
// and the all-clear line to stdout; in json mode a single object goes to
// stdout. The locations map (keyed by "type.name") adds file= and line= to
// annotations and file paths to text output when available.
func printReport(res check.Result, format string, locations map[string]iam.FileLocation, showExcluded bool) {
	missing, excluded, checked := res.Missing, res.Excluded, res.Checked
	// The JSON label names what checked counts, so only the text lines
	// mention the declared needs.
	resourceLabel := res.Label
	switch {
	case res.Needs == 1:
		resourceLabel += ", 1 declared need"
	case res.Needs > 1:
		resourceLabel += fmt.Sprintf(", %d declared needs", res.Needs)
	}
	switch format {
	case "json":
		var exc []iam.ExcludedAction
		if showExcluded {
			exc = excluded
		}
		fmt.Print(iam.FormatJSON(missing, exc, checked, res.Label, locations))
	case "github-annotations":
		if len(missing) > 0 {
			fmt.Print(iam.FormatGitHubAnnotations(missing, locations))
			fmt.Printf("\n%s\n", summary(missing, checked, resourceLabel))
		} else {
			fmt.Printf("All required permissions covered (%d %s checked).\n", checked, resourceLabel)
		}
		if showExcluded {
			fmt.Print(iam.FormatExcludedAnnotations(excluded))
		}
	default:
		if len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "%s\n", iam.FormatMissing(missing, locations))
			fmt.Fprintf(os.Stderr, "\n%s\n", summary(missing, checked, resourceLabel))
		} else {
			fmt.Printf("All required permissions covered (%d %s checked).\n", checked, resourceLabel)
		}
		if showExcluded {
			fmt.Fprint(os.Stderr, iam.FormatExcluded(excluded))
		}
	}
}

// summary is the closing line of a report with findings. Unverified findings
// get their own count, so the line only mentions them when there are some.
func summary(missing []iam.MissingAction, checked int, resourceLabel string) string {
	unverified := iam.UnverifiedCount(missing)
	line := fmt.Sprintf("%d %s checked, %d distinct missing permissions found", checked, resourceLabel, iam.DistinctCount(missing)-unverified)
	if unverified > 0 {
		line += fmt.Sprintf(", %d unverified (resource scope)", unverified)
	}
	return line + "."
}

// unwrapJSONString converts a json.RawMessage to a []byte suitable for
// policy parsing. If the raw value is a JSON string (e.g. `"..."`), it
// unquotes and returns the inner string. Otherwise it returns the raw
// message as-is (e.g. for nested JSON objects).
func unwrapJSONString(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []byte(s), nil
	}
	return raw, nil
}

// validateStaticHCL runs validation against terraform configuration files
// directly, without requiring a terraform plan or AWS credentials. It
// over-approximates: every resource type referenced in .tf files is included
// regardless of count, for_each, or whether the resource would actually be
// created.
func validateStaticHCL(terraformRoot, policyFile, cloudName string, opts check.Options, format string, exitZero bool, locations map[string]iam.FileLocation, showExcluded bool) error {
	if cloudName == "" {
		return fmt.Errorf("--cloud is required (supported: aws)")
	}
	if cloudName != "aws" {
		return fmt.Errorf("unsupported cloud %q (supported: aws)", cloudName)
	}

	// Parse .tf files
	blocks, err := hcl.ParseDir(terraformRoot)
	if err != nil {
		return fmt.Errorf("parse terraform configurations: %w", err)
	}

	// The policy file is read only when there is something to check.
	readPolicy := func() ([]byte, error) {
		raw, err := os.ReadFile(policyFile)
		if err != nil {
			return nil, fmt.Errorf("read policy: %w", err)
		}
		return raw, nil
	}
	res, err := check.Run(check.FromHCL(blocks), readPolicy, opts)
	if err != nil {
		return err
	}

	return report(res, format, exitZero, showExcluded, locations)
}
