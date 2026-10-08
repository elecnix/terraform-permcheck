package main

import (
	"errors"
	"strings"
	"testing"
)

// planVerdictCase runs validate on a plan or a terraform root under
// testdata/verdict and checks the verdict: whether the run finds gaps, and
// which lines the report holds or must not hold. Each case is a reproducer
// for a plan shape the checker once misread.
type planVerdictCase struct {
	name     string
	args     []string
	gaps     bool
	want     []string // substrings the report must hold
	wantNone []string // substrings the report must not hold
}

func TestValidate_PlanVerdicts(t *testing.T) {
	const dir = "testdata/verdict-plan/"
	planArgs := func(plan, policy string, extra ...string) []string {
		return append([]string{"validate", "--plan-file", dir + plan, "--policy-file", dir + policy, "--cloud", "aws"}, extra...)
	}
	cases := []planVerdictCase{
		{
			// A replace deletes the old object, so it needs the delete
			// permissions as well as the create ones.
			name: "replace checks delete",
			args: planArgs("replace_plan.json", "replace_policy.json"),
			gaps: true,
			want: []string{"sqs:DeleteQueue", "aws_sqs_queue.q (delete)"},
		},
		{
			// parent_id comes from a reference, so the plan shows it as
			// unknown. It is still set when the provider creates the account.
			name: "unknown attribute satisfies presence gate",
			args: planArgs("unknown_gate_plan.json", "gate_policy.json"),
			gaps: true,
			want: []string{"organizations:MoveAccount [conditional: parent_id]"},
		},
		{
			name: "known attribute satisfies presence gate",
			args: planArgs("known_gate_plan.json", "gate_policy.json"),
			gaps: true,
			want: []string{"organizations:MoveAccount [conditional: parent_id]"},
		},
		{
			// A deferred data source read is not a managed resource change.
			name:     "data source read is skipped",
			args:     planArgs("data_source_plan.json", "none_policy.json"),
			want:     []string{"No resources to check."},
			wantNone: []string{"aws_iam_policy_document"},
		},
		{
			// forget removes the object from state and calls no API.
			name: "forget is skipped",
			args: planArgs("forget_plan.json", "none_policy.json"),
			want: []string{"No resources to check."},
		},
		{
			// The exclusion names the root queue. The module's queue of the
			// same type and name is a different resource and stays reported.
			name:     "exclusion matches the full address",
			args:     planArgs("module_plan.json", "module_policy.json", "--config", dir+"module_config.json"),
			gaps:     true,
			want:     []string{"sqs:DeleteQueue", "module.prod.aws_sqs_queue.q (delete)"},
			wantNone: []string{"→ aws_sqs_queue.q (delete)"},
		},
		{
			// Only one of two blocks of the type sets body. Static mode must
			// still check the permission that body gates.
			name: "static mode reads every block of a type",
			args: []string{"validate", "--terraform-root", dir + "static_mixed", "--policy-file", dir + "apigw_policy.json", "--cloud", "aws"},
			gaps: true,
			want: []string{"apigateway:PUT [conditional: body]", "aws_api_gateway_rest_api.openapi (create)"},
		},
	}
	const real = "testdata/realplan/"
	realArgs := func(policy string, extra ...string) []string {
		return append([]string{"validate", "--plan-file", real + "plan.json", "--policy-file", real + policy, "--cloud", "aws"}, extra...)
	}
	cases = append(cases,
		planVerdictCase{
			// A plan terraform wrote: a replace, a forget, a deferred data
			// source read, a module, and an account whose parent_id is
			// known only after apply. The data source and the forget are
			// not checked, so five resources are.
			name: "real plan",
			args: realArgs("policy.json"),
			gaps: true,
			want: []string{
				"organizations:MoveAccount [conditional: parent_id]\n    → aws_organizations_account.a (create)",
				"sqs:DeleteQueue [required]\n    → aws_sqs_queue.q (delete)",
				"5 resource changes checked, 2 distinct missing permissions found.",
			},
			wantNone: []string{"aws_iam_policy_document", "aws_sqs_queue.kept"},
		},
		planVerdictCase{
			// The exclusion names the root queue, so the module's queue of
			// the same type and name stays reported.
			name:     "real plan module exclusion",
			args:     realArgs("policy_no_create_queue.json", "--config", real+"exclude_root_queue.json"),
			gaps:     true,
			want:     []string{"sqs:CreateQueue [required]\n    → module.prod.aws_sqs_queue.q (create)\n\n"},
			wantNone: []string{"→ aws_sqs_queue.q (create)"},
		},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var runErr error
			stdout, stderr := captureStreams(t, func() { runErr = run(tc.args) })
			out := stdout + stderr
			if tc.gaps != errors.Is(runErr, errGapsFound) {
				t.Fatalf("run error = %v, want gaps=%v\n%s", runErr, tc.gaps, out)
			}
			if !tc.gaps && runErr != nil {
				t.Fatalf("run error = %v\n%s", runErr, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("report lacks %q:\n%s", w, out)
				}
			}
			for _, w := range tc.wantNone {
				if strings.Contains(out, w) {
					t.Errorf("report holds %q:\n%s", w, out)
				}
			}
		})
	}
}
