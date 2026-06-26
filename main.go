// tf-permcheck validates that a terraform deploy role has sufficient IAM
// permissions for every resource in a terraform plan.
//
// Usage:
//
//	terraform show -json plan.tfplan | tf-permcheck validate --policy-file deploy_policy.json --cloud aws
//
//	tf-permcheck validate --plan-file plan.json --policy-file deploy_policy.json --cloud aws
package main

import (
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
		fmt.Fprintf(os.Stderr, "tf-permcheck: %v\n", err)
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
		fmt.Println("tf-permcheck v0.1.0")
		return nil
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func validateCmd(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	planFile := fs.String("plan-file", "", "path to terraform plan JSON (default: stdin)")
	policyFile := fs.String("policy-file", "", "path to IAM policy JSON (required)")
	cloudName := fs.String("cloud", "", "cloud provider: aws (required)")
	noFilter := fs.Bool("no-filter", false, "disable permission filtering (report all CFN schema permissions)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *policyFile == "" {
		return fmt.Errorf("--policy-file is required")
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

	// Read policy
	policyRaw, err := os.ReadFile(*policyFile)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
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
		return nil, fmt.Errorf("no plan on stdin and --plan-file not set")
	}
	return io.ReadAll(os.Stdin)
}
