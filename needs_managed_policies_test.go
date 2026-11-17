package main

import (
	"errors"
	"strings"
	"testing"
)

const ciDeployDataSourcePlan = "testdata/principals/ci_deploy_data_source.json"

// sourcesOf collapses the policy sources of one principal in a json report
// to "address policy text unknown_reason link".
func sourcesOf(t *testing.T, r principalsJSON, label string) []string {
	t.Helper()
	for _, p := range r.PolicySources {
		if p.Principal != label {
			continue
		}
		var out []string
		for _, s := range p.Sources {
			out = append(out, strings.TrimSpace(strings.Join([]string{s.Address, s.Policy, s.Text, s.UnknownReason, s.Link}, " ")))
		}
		return out
	}
	t.Fatalf("policy_sources has no principal %q: %+v", label, r.PolicySources)
	return nil
}

// Worked example 2 reads RollService's grant from aws_iam_policy.deploy_ecs,
// which deploy_ecs attaches through a reference. The json report names the
// policy whose text the check read.
func TestPrincipals_WorkedExample2_PolicySources(t *testing.T) {
	r, _ := runValidateJSON(t, "--plan-file", ciDeployPlan, "--config", ciDeployConfig)
	want := []string{
		"aws_iam_role_policy_attachment.deploy_ecr  unknown outside_plan yes",
		"aws_iam_role_policy_attachment.deploy_ecs aws_iam_policy.deploy_ecs known  yes",
	}
	got := sourcesOf(t, r, "deploy")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Worked example 2 with a data "aws_iam_policy" block for the AWS managed
// policy: terraform reads it during the plan, so the plan's prior_state holds
// its text. The managed policy's statements decide VerifyImage, which is
// covered. No policy the plan shows grants ssm:GetParameter, so ReadParams
// is missing. The run prints no notice for deploy_ecr.
func TestPrincipals_WorkedExample2_DataSourceGivesManagedPolicyText(t *testing.T) {
	for _, strict := range []bool{false, true} {
		args := []string{"--plan-file", ciDeployDataSourcePlan, "--config", ciDeployConfig}
		if strict {
			args = append(args, "--strict-resources")
		}
		r, err := runValidateJSON(t, args...)
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("strict %v: want errGapsFound, got %v", strict, err)
		}
		want := []string{"ReadParams ssm:GetParameter"}
		if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("strict %v: findings = %q, want %q", strict, got, want)
		}
	}

	_, stderr, _ := runValidate(t, "--plan-file", ciDeployDataSourcePlan, "--config", ciDeployConfig)
	if strings.Contains(stderr, "deploy_ecr") {
		t.Errorf("stderr has a notice for deploy_ecr, whose text the data source gives:\n%s", stderr)
	}
	r, _ := runValidateJSON(t, "--plan-file", ciDeployDataSourcePlan, "--config", ciDeployConfig)
	want := []string{
		"aws_iam_role_policy_attachment.deploy_ecr data.aws_iam_policy.ecr_power_user known  yes",
		"aws_iam_role_policy_attachment.deploy_ecs aws_iam_policy.deploy_ecs known  yes",
	}
	if got := sourcesOf(t, r, "deploy"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

const managedPoliciesPlan = "testdata/principals/managed_policies.json"

// managedNeeds maps each role of the managed_policies fixture:
//
//   - reader: an aws_iam_policy_attachment lists it in roles, with the known
//     ARN of aws_iam_policy.reads, which the plan leaves as it is. The policy
//     allows s3:GetObject on app-data.
//   - worker: its managed_policy_arns references aws_iam_policy.queue, which
//     allows sqs:* and denies sqs:DeleteQueue.
//   - builder: an attachment references aws_iam_policy.build, whose text
//     terraform computes at apply time.
//   - auditor: an attachment names a known ARN that may be the ARN of
//     aws_iam_policy.audit, whose name_prefix leaves its name unknown, or of
//     a policy outside the plan. aws_iam_policy.audit allows
//     cloudtrail:LookupEvents.
//   - shard: the first instance of a role with count. Each instance's
//     attachment references aws_iam_policy.shard without a key, and each
//     instance of that policy allows dynamodb:GetItem on its own table.
const managedNeeds = `{
	"principals": {
		"reader": {"address": "aws_iam_role.reader"},
		"worker": {"address": "aws_iam_role.worker"},
		"builder": {"address": "aws_iam_role.builder"},
		"auditor": {"address": "aws_iam_role.auditor"},
		"shard": {"address": "aws_iam_role.shard[0]"}
	},
	"needs": [
		{"sid": "ReadObjects", "principal": "reader", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::app-data/report.csv"]},
		{"sid": "WriteObjects", "principal": "reader", "actions": ["s3:PutObject"], "resources": ["arn:aws:s3:::app-data/report.csv"]},
		{"sid": "SendJobs", "principal": "worker", "actions": ["sqs:SendMessage"], "resources": ["arn:aws:sqs:us-east-1:123456789012:app-jobs"]},
		{"sid": "DropQueue", "principal": "worker", "actions": ["sqs:DeleteQueue"], "resources": ["arn:aws:sqs:us-east-1:123456789012:app-jobs"]},
		{"sid": "PushImage", "principal": "builder", "actions": ["ecr:PutImage"], "resources": ["arn:aws:ecr:us-east-1:123456789012:repository/app"]},
		{"sid": "LookupEvents", "principal": "auditor", "actions": ["cloudtrail:LookupEvents"]},
		{"sid": "ReadLogs", "principal": "auditor", "actions": ["logs:GetLogEvents"]},
		{"sid": "ReadShard", "principal": "shard", "actions": ["dynamodb:GetItem"], "resources": ["arn:aws:dynamodb:us-east-1:123456789012:table/shard-0"]},
		{"sid": "ReadOther", "principal": "shard", "actions": ["dynamodb:GetItem"], "resources": ["arn:aws:dynamodb:us-east-1:123456789012:table/other"]}
	]
}`

// The verdicts of each managed policy case. In the default mode a gap is
// reported only when the plan proves it: the reader lacks s3:PutObject, the
// queue policy denies sqs:DeleteQueue, and no shard policy grants the other
// table. Under --strict-resources, a grant the tool can't check is
// unverified too: the builder's policy text is computed, the auditor's ARN
// may name a policy outside the plan, and the shard's attachment may attach
// either shard policy.
func TestPrincipals_ManagedPolicies(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), managedNeeds)
	r, err := runValidateJSON(t, "--plan-file", managedPoliciesPlan, "--config", cfg)
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("want errGapsFound, got %v", err)
	}
	// Findings come in principal label order.
	want := []string{
		"WriteObjects s3:PutObject",
		"ReadOther dynamodb:GetItem",
		"DropQueue sqs:DeleteQueue",
	}
	if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	r, err = runValidateJSON(t, "--plan-file", managedPoliciesPlan, "--config", cfg, "--strict-resources")
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("strict mode: want errGapsFound, got %v", err)
	}
	want = []string{
		"LookupEvents cloudtrail:LookupEvents unverified condition",
		"ReadLogs logs:GetLogEvents unverified policy_unknown",
		"PushImage ecr:PutImage unverified policy_unknown",
		"WriteObjects s3:PutObject",
		"ReadShard dynamodb:GetItem unverified condition",
		"ReadOther dynamodb:GetItem",
		"DropQueue sqs:DeleteQueue",
	}
	if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("strict findings =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	sources := map[string][]string{
		"reader":  {"aws_iam_policy_attachment.shared_reads aws_iam_policy.reads known  yes"},
		"worker":  {"aws_iam_role.worker aws_iam_policy.queue known  yes"},
		"builder": {"aws_iam_role_policy_attachment.builder aws_iam_policy.build unknown computed yes"},
		"auditor": {
			"aws_iam_role_policy_attachment.auditor aws_iam_policy.audit known  maybe",
			"aws_iam_role_policy_attachment.auditor  unknown outside_plan maybe",
		},
		"shard": {
			"aws_iam_role_policy_attachment.shard[0] aws_iam_policy.shard[0] known  maybe",
			"aws_iam_role_policy_attachment.shard[0] aws_iam_policy.shard[1] known  maybe",
		},
	}
	for label, want := range sources {
		if got := sourcesOf(t, r, label); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s sources =\n%s\nwant\n%s", label, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

// The notices of the managed policy cases: one for the computed text of
// aws_iam_policy.build, and one for the auditor's ARN, which may name a
// policy outside the plan. Both say how the needs may depend on the source.
func TestPrincipals_ManagedPolicyNotices(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), managedNeeds)
	_, stderr, _ := runValidate(t, "--plan-file", managedPoliciesPlan, "--config", cfg)
	want := []string{
		`notice: aws_iam_role_policy_attachment.builder: the text of aws_iam_policy.build is known only after apply; needs of "builder" may be granted by it`,
		`notice: aws_iam_role_policy_attachment.auditor: arn:aws:iam::123456789012:policy/app-audit may be a managed policy that the plan doesn't contain; needs of "auditor" may be granted by it; a data "aws_iam_policy" block with this arn gives PermCheck its text`,
	}
	for _, line := range want {
		if !strings.Contains(stderr, line+"\n") {
			t.Errorf("stderr has no line %q:\n%s", line, stderr)
		}
	}
	if n := strings.Count(stderr, "notice: "); n != len(want)+1 {
		t.Errorf("stderr has %d notices, want %d and the one of the run without a policy source:\n%s", n, len(want), stderr)
	}
}
