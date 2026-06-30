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
		err := validateCmd(args[1:])
		// Translate gaps to exit code 1; --exit-zero suppresses this upstream.
		if errors.Is(err, errGapsFound) {
			return err
		}
		return err
	case "version":
		fmt.Println("terraform-permcheck v0.1.0")
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
	terraformRoot := fs.String("terraform-root", "", "root directory of terraform configuration (static HCL mode — no plan, no AWS credentials required)")
	format := fs.String("format", "text", "output format: text, github-annotations")
	exitZero := fs.Bool("exit-zero", false, "exit with code 0 even when permission gaps are found")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *format != "text" && *format != "github-annotations" {
		return fmt.Errorf("unsupported format %q (supported: text, github-annotations)", *format)
	}

	// Static HCL mode: --terraform-root replaces --plan-file / stdin.
	if *terraformRoot != "" {
		if *planFile != "" {
			return fmt.Errorf("--terraform-root and --plan-file are mutually exclusive")
		}
		if *policyFromPlanOutput != "" || *policyFromStateOutput != "" {
			return fmt.Errorf("--terraform-root requires --policy-file (policy-from-plan/output not applicable)")
		}
		if *policyFile == "" {
			return fmt.Errorf("--terraform-root requires --policy-file")
		}
		return validateStaticHCL(*terraformRoot, *policyFile, *cloudName, *noFilter, *onlyRequired, *format, *exitZero)
	}

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
		fmt.Println("No matching resource changes found in plan.")
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
		printMissing(missing, len(changes), "resource changes", *format)
		if *exitZero {
			return nil
		}
		return errGapsFound
	}

	printSuccess(len(changes), "resource changes")
	return nil
}

// schemaAdapter bridges cloud.Provider to iam.SchemaLike for the validator.
type schemaAdapter struct {
	p cloud.Provider
}

func (a *schemaAdapter) Resolve(tfType string) (iam.SchemaLike, error) {
	return a.p.Resolve(tfType)
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
// workflow runner); in text mode it goes to stderr (for human readability).
func printMissing(missing []iam.MissingAction, checked int, resourceLabel, format string) {
	switch format {
	case "github-annotations":
		fmt.Print(iam.FormatGitHubAnnotations(missing))
		fmt.Printf("\n%d %s checked, %d distinct missing permissions found.\n", checked, resourceLabel, iam.DistinctCount(missing))
	default:
		fmt.Fprintf(os.Stderr, "%s\n", iam.FormatMissing(missing))
		fmt.Fprintf(os.Stderr, "\n%d %s checked, %d distinct missing permissions found.\n", checked, resourceLabel, iam.DistinctCount(missing))
	}
}

// printSuccess prints the all-clear message.
func printSuccess(checked int, resourceLabel string) {
	fmt.Printf("All required permissions covered (%d %s checked).\n", checked, resourceLabel)
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
func validateStaticHCL(terraformRoot, policyFile, cloudName string, noFilter, onlyRequired bool, format string, exitZero bool) error {
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
		fmt.Println("No aws resource or data blocks found in terraform configuration.")
		return nil
	}

	// Build ResourceChange entries: over-approximate by treating all as create.
	// Deduplicate by (Type) — one entry per resource type, regardless of count.
	seen := make(map[string]bool)
	var changes []*plan.ResourceChange
	for _, b := range blocks {
		if !seen[b.Type] {
			seen[b.Type] = true
			changes = append(changes, &plan.ResourceChange{
				Type:   b.Type,
				Name:   b.Name,
				Change: "create",
				// Attributes is nil → conditional permissions are preserved
				// (presence unknown).
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
		printMissing(missing, len(changes), "resource types (static HCL mode)", format)
		if exitZero {
			return nil
		}
		return errGapsFound
	}

	fmt.Printf("All required permissions covered (%d resource types checked, static HCL mode).\n", len(changes))
	return nil
}
