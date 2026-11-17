package main

import (
	"errors"
	"strings"
	"testing"
)

// The fixtures of worked example 1 in the design of issue #175, one per row
// of its verdict table, and the fixtures of the other resource policy cases.
// Each one changes testdata/principals/ecs_task.json in one way.
const (
	ecsTaskKnownRole           = "testdata/principals/ecs_task_known_role.json"
	ecsTaskSecretDeny          = "testdata/principals/ecs_task_secret_deny.json"
	ecsTaskSecretDenyCondition = "testdata/principals/ecs_task_secret_deny_condition.json"
	ecsTaskSecretPolicyComp    = "testdata/principals/ecs_task_secret_policy_computed.json"
	ecsTaskInlineSecretPolicy  = "testdata/principals/ecs_task_inline_secret_policy.json"
	ecsTaskOtherSecretPolicy   = "testdata/principals/ecs_task_other_secret_policy.json"
	ecsTaskOtherRoleGrant      = "testdata/principals/ecs_task_other_role_grant.json"
	ecsTaskAccountRoot         = "testdata/principals/ecs_task_account_root.json"
	ecsTaskComputedSecretName  = "testdata/principals/ecs_task_computed_secret_name.json"
	ecsTaskNotPrincipalDeny    = "testdata/principals/ecs_task_not_principal_deny.json"
)

// fetchSecrets is the finding of the FetchSecrets need when the policies
// provably don't grant it.
const fetchSecrets = "FetchSecrets secretsmanager:GetSecretValue"

// resourcePolicyCase is one run of a plan and a config, with the findings
// that the default mode and --strict-resources report.
type resourcePolicyCase struct {
	name   string
	plan   string
	config string
	// want and wantStrict are the findings, as verdicts returns them. An
	// empty list means the run passes.
	want, wantStrict []string
}

// check runs the case in both modes and compares the findings.
func (c resourcePolicyCase) check(t *testing.T) {
	t.Helper()
	config := c.config
	if config == "" {
		config = ecsTaskConfig
	}
	for _, strict := range []bool{false, true} {
		args := []string{"--plan-file", c.plan, "--config", config}
		want := c.want
		if strict {
			args = append(args, "--strict-resources")
			want = c.wantStrict
		}
		r, err := runValidateJSON(t, args...)
		switch {
		case len(want) == 0 && err != nil:
			t.Errorf("strict=%v: want a pass, got %v", strict, err)
		case len(want) > 0 && !errors.Is(err, errGapsFound):
			t.Errorf("strict=%v: want errGapsFound, got %v", strict, err)
		}
		if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("strict=%v: findings =\n%s\nwant\n%s", strict, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

// Worked example 1, each row of its verdict table. The secret policy grants
// GetSecretValue to the task role, and no identity policy does.
func TestResourcePolicy_WorkedExample1(t *testing.T) {
	for _, c := range []resourcePolicyCase{
		{
			// The role's ARN is computed, so the Principal entry may name
			// it: its name matches, and its account is unknown.
			name:       "as written",
			plan:       ecsTaskPlan,
			wantStrict: []string{fetchSecrets + " unverified condition"},
		},
		{
			name: "role ARN known",
			plan: ecsTaskKnownRole,
		},
		{
			name:       "secret policy removed",
			plan:       ecsTaskNoSecretPolicy,
			want:       []string{fetchSecrets},
			wantStrict: []string{fetchSecrets},
		},
		{
			name:       "Deny for every principal",
			plan:       ecsTaskSecretDeny,
			want:       []string{fetchSecrets},
			wantStrict: []string{fetchSecrets},
		},
		{
			name:       "Deny with a Condition",
			plan:       ecsTaskSecretDenyCondition,
			wantStrict: []string{fetchSecrets + " unverified condition"},
		},
		{
			name:       "secret policy text computed",
			plan:       ecsTaskSecretPolicyComp,
			wantStrict: []string{fetchSecrets + " unverified policy_unknown"},
		},
	} {
		t.Run(c.name, c.check)
	}
}

// The notice for a secret policy whose text is computed keeps its wording.
// A secret policy whose text the plan shows prints no notice.
func TestResourcePolicy_NoticeOnlyForUnknownText(t *testing.T) {
	_, stderr, err := runValidate(t, "--plan-file", ecsTaskSecretPolicyComp, "--config", ecsTaskConfig)
	if err != nil {
		t.Fatalf("want a pass, got %v", err)
	}
	if !strings.Contains(stderr, secretPolicyNoticeLine+`policy text is known only after apply; needs of "task" may be granted by it`) {
		t.Errorf("stderr has no notice for the computed secret policy:\n%s", stderr)
	}
	_, stderr, err = runValidate(t, "--plan-file", ecsTaskPlan, "--config", ecsTaskConfig)
	if err != nil {
		t.Fatalf("want a pass, got %v", err)
	}
	if strings.Contains(stderr, secretPolicyNoticeLine) {
		t.Errorf("stderr has a notice for a secret policy whose text the plan shows:\n%s", stderr)
	}
}

// policy_sources lists the secret policy with link yes when the need's
// resource is the secret, and maybe when it may be.
func TestResourcePolicy_PolicySourcesLink(t *testing.T) {
	for _, c := range []struct {
		plan, want string
	}{
		{ecsTaskPlan, "yes"},
		{ecsTaskComputedSecretName, "maybe"},
	} {
		r, _ := runValidateJSON(t, "--plan-file", c.plan, "--config", ecsTaskConfig)
		var got []string
		for _, p := range r.PolicySources {
			for _, s := range p.Sources {
				if s.Kind == "resource" {
					got = append(got, s.Address+" "+s.Text+" "+s.Link)
				}
			}
		}
		want := "aws_secretsmanager_secret_policy.app known " + c.want
		if strings.Join(got, "\n") != want {
			t.Errorf("%s: resource sources = %q, want %q", c.plan, got, want)
		}
	}
}

// needOn returns a config that maps the task role and gives it one need of
// GetSecretValue on the resources, and one need of DescribeSecret on the
// same resources.
func needOn(t *testing.T, resources string) string {
	t.Helper()
	return writeConfig(t, t.TempDir(), `{
		"principals": {"task": {"address": "aws_iam_role.task"}},
		"needs": [
			{"sid": "FetchSecrets", "principal": "task", "actions": ["secretsmanager:GetSecretValue"]`+resources+`},
			{"sid": "Describe", "principal": "task", "actions": ["secretsmanager:DescribeSecret"]`+resources+`}
		]
	}`)
}

const (
	appDB   = `, "resources": ["arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-*"]`
	otherDB = `, "resources": ["arn:aws:secretsmanager:us-east-1:123456789012:secret:other-db-*"]`
)

// describe is the finding of the Describe need when the policies provably
// don't grant it.
const describe = "Describe secretsmanager:DescribeSecret"

// The other resource policy cases: which policies apply to a need, and which
// of their statements.
func TestResourcePolicy_Cases(t *testing.T) {
	for _, c := range []resourcePolicyCase{
		{
			// The aws_secretsmanager_secret sets the same policy in its
			// policy attribute.
			name:       "inline policy of the secret",
			plan:       ecsTaskInlineSecretPolicy,
			wantStrict: []string{fetchSecrets + " unverified condition"},
		},
		{
			// The plan's only secret is other-db. Its policy doesn't apply
			// to a need on app-db, and the plan shows no policy of app-db.
			name:       "policy of another secret",
			plan:       ecsTaskOtherSecretPolicy,
			want:       []string{fetchSecrets},
			wantStrict: []string{fetchSecrets},
		},
		{
			// The statement's Resource is "*", and it applies to the secret
			// app-db only. The role's ARN is known, so the statement names
			// the role.
			name:       "Resource * doesn't grant another secret",
			plan:       ecsTaskKnownRole,
			config:     needOn(t, otherDB),
			want:       []string{fetchSecrets, describe},
			wantStrict: []string{fetchSecrets, describe},
		},
		{
			name:       "grant to another role",
			plan:       ecsTaskOtherRoleGrant,
			want:       []string{fetchSecrets},
			wantStrict: []string{fetchSecrets},
		},
		{
			// The account root delegates to the account's IAM policies.
			// The task role's inline policy allows DescribeSecret and not
			// GetSecretValue.
			name:       "account root Allow",
			plan:       ecsTaskAccountRoot,
			config:     needOn(t, appDB),
			want:       []string{fetchSecrets},
			wantStrict: []string{fetchSecrets},
		},
		{
			// The need acts on an unknown resource, so the secret policy
			// may apply. Its grant is limited to the secret, and its
			// Principal may name the role.
			name:       "need without resources",
			plan:       ecsTaskPlan,
			config:     needOn(t, ""),
			want:       []string{describe},
			wantStrict: []string{fetchSecrets + " unverified condition", describe},
		},
		{
			// The secret's name is computed, so it may be app-db. The role's
			// ARN is known, so only the resource is undecidable.
			name:       "secret name computed",
			plan:       ecsTaskComputedSecretName,
			wantStrict: []string{fetchSecrets + " unverified resource_scope"},
		},
		{
			// NotPrincipal lists app-admin only, so the Deny applies to the
			// task role.
			name:       "NotPrincipal Deny",
			plan:       ecsTaskNotPrincipalDeny,
			want:       []string{fetchSecrets},
			wantStrict: []string{fetchSecrets},
		},
		{
			// A secret policy grants the action on one secret, never on
			// every resource.
			name:       "need on every resource",
			plan:       ecsTaskKnownRole,
			config:     needOn(t, `, "resources": ["*"]`),
			want:       []string{fetchSecrets, describe},
			wantStrict: []string{fetchSecrets, describe},
		},
	} {
		t.Run(c.name, c.check)
	}
}
