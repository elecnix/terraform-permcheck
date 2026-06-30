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
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
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

	if err := fs.Parse(args); err != nil {
		return err
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
	missing, err := iam.Validate(changes, policy, &schemaAdapter{resolver}, filter)
	if err != nil {
		return err
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "%s\n", iam.FormatMissing(missing))
		fmt.Fprintf(os.Stderr, "\n%d resource changes checked, %d missing permissions found.\n", len(changes), len(missing))
		os.Exit(1)
	}

	fmt.Printf("All required permissions covered (%d resource changes checked).\n", len(changes))
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
