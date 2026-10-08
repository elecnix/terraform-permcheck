package main

import (
	"encoding/json"
	"errors"
	"testing"
)

// verdictCase validates a plan in testdata/verdict-iam against a policy and
// checks which findings the JSON report holds. Each finding is written as
// "<resource type> <action>".
type verdictCase struct {
	name    string
	plan    string
	policy  string
	flags   []string
	present []string
	absent  []string
}

func runVerdictCase(t *testing.T, c verdictCase) {
	t.Helper()
	args := append([]string{"validate",
		"--plan-file", "testdata/verdict-iam/" + c.plan,
		"--policy-file", "testdata/verdict-iam/" + c.policy,
		"--cloud", "aws",
		"--format", "json",
	}, c.flags...)
	var runErr error
	out := captureStdout(t, func() { runErr = run(args) })
	if runErr != nil && !errors.Is(runErr, errGapsFound) {
		t.Fatalf("run: %v", runErr)
	}
	var result struct {
		Missing []struct {
			ResourceType string `json:"resource_type"`
			Action       string `json:"missing_action"`
		} `json:"missing"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\ngot: %s", err, out)
	}
	found := map[string]bool{}
	for _, m := range result.Missing {
		found[m.ResourceType+" "+m.Action] = true
	}
	for _, want := range c.present {
		if !found[want] {
			t.Errorf("want finding %q, got:\n%s", want, out)
		}
	}
	for _, unwanted := range c.absent {
		if found[unwanted] {
			t.Errorf("want no finding %q, got:\n%s", unwanted, out)
		}
	}
}

// TestValidate_VerdictIAM runs the reproducers of the verdict review end to
// end, against the embedded permissions table.
func TestValidate_VerdictIAM(t *testing.T) {
	cases := []verdictCase{
		{
			// A resource that exists to make a data-plane or optional call
			// needs that call: the default filter must not drop it.
			name: "dedicated resources", plan: "dedicated_plan.json", policy: "dedicated_policy.json",
			present: []string{
				"aws_s3_object s3:PutObject",
				"aws_iam_user_policy iam:PutUserPolicy",
				"aws_backup_vault_policy backup:PutBackupVaultAccessPolicy",
				"aws_dynamodb_table_item dynamodb:PutItem",
				"aws_dynamodb_resource_policy dynamodb:PutResourcePolicy",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { runVerdictCase(t, c) })
	}
}
