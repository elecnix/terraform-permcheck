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

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
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

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("subcommand required: validate")
	}

	switch args[0] {
	case "validate":
		return validateCmd(args[1:])
	case "version":
		fmt.Println("terraform-permcheck v0.5.0")
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

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *format != "text" && *format != "github-annotations" && *format != "json" {
		return fmt.Errorf("unsupported format %q (supported: text, github-annotations, json)", *format)
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
		return validateStaticHCL(*terraformRoot, *policyFile, *cloudName, *noFilter, *onlyRequired, *format, *exitZero, locations)
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
	var err error
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

	if len(changes) == 0 {
		printSuccess(0, "resource changes", *format)
		return nil
	}

	// Parse policy
	policy, err := iam.ParsePolicy(policyRaw)
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}

	// Resolve schemas
	resolver := cloud.NewChainProvider(
		provideraws.NewSourceProvider(),
		cloud.NewAWSProvider(),
	)

	// Validate with default filtering (skip data-plane and optional permissions)
	filter := iam.DefaultFilter()
	if *noFilter {
		filter = iam.FilterConfig{} // all zero values = no filtering
	}
	if *onlyRequired {
		filter.ExcludeConditional = true
	}
	missing, err := iam.Validate(changes, policy, &schemaAdapter{resolver}, filter)
	if err != nil {
		return err
	}

	if len(missing) > 0 {
		printMissing(missing, len(changes), "resource changes", *format, locations)
		if *exitZero {
			return nil
		}
		return errGapsFound
	}

	printSuccess(len(changes), "resource changes", *format)
	return nil
}

// schemaAdapter bridges cloud.Provider to iam.SchemaLike for the validator.
type schemaAdapter struct {
	p cloud.Provider
}

func (a *schemaAdapter) Resolve(tfType string) (iam.SchemaLike, error) {
	return a.p.Resolve(tfType)
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

// printMissing formats and prints missing actions. In github-annotations mode
// the output goes to stdout (so ::warning:: commands are parsed by the
// workflow runner); in text mode it goes to stderr (for human readability);
// in json mode it goes to stdout as a JSON object.
// The locations map (keyed by "type.name") adds file= and line= to
// annotations and file paths to text output when available.
func printMissing(missing []iam.MissingAction, checked int, resourceLabel, format string, locations map[string]iam.FileLocation) {
	switch format {
	case "github-annotations":
		fmt.Print(iam.FormatGitHubAnnotations(missing, locations))
		fmt.Printf("\n%d %s checked, %d distinct missing permissions found.\n", checked, resourceLabel, iam.DistinctCount(missing))
	case "json":
		fmt.Print(iam.FormatJSON(missing, checked, resourceLabel, locations))
	default:
		fmt.Fprintf(os.Stderr, "%s\n", iam.FormatMissing(missing, locations))
		fmt.Fprintf(os.Stderr, "\n%d %s checked, %d distinct missing permissions found.\n", checked, resourceLabel, iam.DistinctCount(missing))
	}
}

// printSuccess prints the all-clear message.
func printSuccess(checked int, resourceLabel, format string) {
	switch format {
	case "json":
		output := iam.FormatJSON(nil, checked, resourceLabel, nil)
		fmt.Print(output)
	default:
		fmt.Printf("All required permissions covered (%d %s checked).\n", checked, resourceLabel)
	}
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
func validateStaticHCL(terraformRoot, policyFile, cloudName string, noFilter, onlyRequired bool, format string, exitZero bool, locations map[string]iam.FileLocation) error {
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

	if len(blocks) == 0 {
		printSuccess(0, "resource types (static HCL mode)", format)
		return nil
	}

	// Build ResourceChange entries: over-approximate by treating all as create.
	// Deduplicate by (Type) — one entry per resource type, regardless of count.
	// Populate Attributes from parsed HCL to enable conditional permission
	// filtering (e.g., s3:PutBucketWebsite is only reported when a website
	// block is actually configured).
	seen := make(map[string]bool)
	var changes []*plan.ResourceChange
	for _, b := range blocks {
		if !seen[b.Type] {
			seen[b.Type] = true
			var attrs map[string]bool
			if len(b.Attributes) > 0 {
				attrs = make(map[string]bool, len(b.Attributes))
				for _, a := range b.Attributes {
					attrs[a] = true
				}
			}
			changes = append(changes, &plan.ResourceChange{
				Type:       b.Type,
				Name:       b.Name,
				Change:     "create",
				Attributes: attrs,
			})
		}
	}

	// Parse policy
	policyRaw, err := os.ReadFile(policyFile)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	policy, err := iam.ParsePolicy(policyRaw)
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}

	// Resolve schemas
	resolver := cloud.NewChainProvider(
		provideraws.NewSourceProvider(),
		cloud.NewAWSProvider(),
	)

	// Validate
	filter := iam.DefaultFilter()
	if noFilter {
		filter = iam.FilterConfig{}
	}
	if onlyRequired {
		filter.ExcludeConditional = true
	}
	missing, err := iam.Validate(changes, policy, &schemaAdapter{resolver}, filter)
	if err != nil {
		return err
	}

	if len(missing) > 0 {
		printMissing(missing, len(changes), "resource types (static HCL mode)", format, locations)
		if exitZero {
			return nil
		}
		return errGapsFound
	}

	printSuccess(len(changes), "resource types (static HCL mode)", format)
	return nil
}
