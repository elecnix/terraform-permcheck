package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// principalsJSON is the part of the json report that the principals tests
// read. The test decodes it on its own, so it reads the keys a consumer
// sees.
type principalsJSON struct {
	Status  string `json:"status"`
	Missing []struct {
		Need          string `json:"need"`
		Principal     string `json:"principal"`
		NeedResource  string `json:"need_resource"`
		MissingAction string `json:"missing_action"`
		Unverified    string `json:"unverified"`
	} `json:"missing"`
	PolicySources []struct {
		Principal string `json:"principal"`
		Address   string `json:"address"`
		Sources   []struct {
			Address       string `json:"address"`
			Kind          string `json:"kind"`
			Text          string `json:"text"`
			UnknownReason string `json:"unknown_reason"`
			Policy        string `json:"policy"`
			Link          string `json:"link"`
		} `json:"sources"`
	} `json:"policy_sources"`
	PlanResourcesSkipped bool `json:"plan_resources_skipped"`
}

// runValidate runs the validate command and returns its two streams and its
// error.
func runValidate(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	stdout, stderr = captureStreams(t, func() {
		err = run(append([]string{"validate", "--cloud", "aws"}, args...))
	})
	return stdout, stderr, err
}

// runValidateJSON runs the validate command with --format json and decodes
// the report.
func runValidateJSON(t *testing.T, args ...string) (principalsJSON, error) {
	t.Helper()
	stdout, stderr, err := runValidate(t, append(args, "--format", "json")...)
	var out principalsJSON
	if jerr := json.Unmarshal([]byte(stdout), &out); jerr != nil {
		t.Fatalf("invalid JSON (run error %v): %v\nstdout:\n%s\nstderr:\n%s", err, jerr, stdout, stderr)
	}
	return out, err
}

// verdicts collapses the findings of a json report to "sid action
// [unverified reason]".
func verdicts(r principalsJSON) []string {
	var out []string
	for _, m := range r.Missing {
		s := m.Need + " " + m.MissingAction
		if m.Unverified != "" {
			s += " unverified " + m.Unverified
		}
		out = append(out, s)
	}
	return out
}

const (
	ecsTaskPlan            = "testdata/principals/ecs_task.json"
	ecsTaskNoSecretPolicy  = "testdata/principals/ecs_task_no_secret_policy.json"
	ecsTaskConfig          = "testdata/principals/ecs_task_config.json"
	ciDeployPlan           = "testdata/principals/ci_deploy.json"
	ciDeployConfig         = "testdata/principals/ci_deploy_config.json"
	secretPolicyNoticeLine = `notice: aws_secretsmanager_secret_policy.app: `
)

// Worked example 1 without the secret policy: no policy the plan shows
// grants secretsmanager:GetSecretValue to the task role, so the need is
// missing. The run has no --policy-* source, since every need is mapped.
func TestPrincipals_WorkedExample1_NoSecretPolicyIsMissing(t *testing.T) {
	r, err := runValidateJSON(t, "--plan-file", ecsTaskNoSecretPolicy, "--config", ecsTaskConfig)
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("want errGapsFound, got %v", err)
	}
	if len(r.Missing) != 1 {
		t.Fatalf("missing = %+v, want one finding", r.Missing)
	}
	m := r.Missing[0]
	if m.Need != "FetchSecrets" || m.Principal != "task" || m.MissingAction != "secretsmanager:GetSecretValue" || m.Unverified != "" {
		t.Errorf("finding = %+v, want FetchSecrets of task missing secretsmanager:GetSecretValue", m)
	}
	if m.NeedResource != "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-*" {
		t.Errorf("need_resource = %q", m.NeedResource)
	}
}

// Worked example 1 with the secret policy: the secret policy grants
// GetSecretValue to a role ARN whose name is the task role's, and the plan
// doesn't know the role's account. The need is covered by default, without a
// notice, since the plan shows the policy text. It is unverified with
// condition under --strict-resources.
func TestPrincipals_WorkedExample1_SecretPolicyMayGrant(t *testing.T) {
	stdout, stderr, err := runValidate(t, "--plan-file", ecsTaskPlan, "--config", ecsTaskConfig)
	if err != nil {
		t.Fatalf("default mode: want a pass, got %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "All required permissions covered") {
		t.Errorf("stdout = %q, want the all-clear line", stdout)
	}
	if strings.Contains(stderr, secretPolicyNoticeLine) {
		t.Errorf("stderr has a notice for a secret policy whose text the plan shows:\n%s", stderr)
	}

	r, err := runValidateJSON(t, "--plan-file", ecsTaskPlan, "--config", ecsTaskConfig, "--strict-resources")
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("strict mode: want errGapsFound, got %v", err)
	}
	want := []string{"FetchSecrets secretsmanager:GetSecretValue unverified condition"}
	if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("strict findings = %q, want %q", got, want)
	}
}

// Worked example 2: the deploy role's grants come from two policy
// attachments. deploy_ecs references aws_iam_policy.deploy_ecs, whose text
// the plan shows, so RollService is covered under --strict-resources too.
// deploy_ecr attaches an AWS managed policy that the plan doesn't contain.
// VerifyImage and ReadParams are covered by default, with a notice for
// deploy_ecr only, and unverified under --strict-resources.
func TestPrincipals_WorkedExample2_AttachmentsAreUnknownSources(t *testing.T) {
	stdout, stderr, err := runValidate(t, "--plan-file", ciDeployPlan, "--config", ciDeployConfig)
	if err != nil {
		t.Fatalf("default mode: want a pass, got %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "All required permissions covered") {
		t.Errorf("stdout = %q, want the all-clear line", stdout)
	}
	for addr, want := range map[string]int{
		"aws_iam_role_policy_attachment.deploy_ecr": 1,
		"aws_iam_role_policy_attachment.deploy_ecs": 0,
	} {
		if n := strings.Count(stderr, "notice: "+addr+": "); n != want {
			t.Errorf("stderr has %d notices for %s, want %d:\n%s", n, addr, want, stderr)
		}
	}
	if !strings.Contains(stderr, "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser") {
		t.Errorf("the notice for deploy_ecr does not name the managed policy:\n%s", stderr)
	}
	if !strings.Contains(stderr, `a data "aws_iam_policy" block with this arn`) {
		t.Errorf("the notice for deploy_ecr does not give the fix:\n%s", stderr)
	}

	r, err := runValidateJSON(t, "--plan-file", ciDeployPlan, "--config", ciDeployConfig, "--strict-resources")
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("strict mode: want errGapsFound, got %v", err)
	}
	want := []string{
		"VerifyImage ecr:DescribeImages unverified policy_unknown",
		"ReadParams ssm:GetParameter unverified policy_unknown",
	}
	if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("strict findings =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, m := range r.Missing {
		if m.Principal != "deploy" {
			t.Errorf("finding %s has principal %q, want deploy", m.Need, m.Principal)
		}
	}
}

// inlineNeeds maps the task role of the inline_policies fixture. Its inline
// policy allows secretsmanager:* and denies GetSecretValue. A computed
// aws_iam_role_policy may grant anything. A policy whose role link the plan
// can't decide allows s3:GetObject and denies logs:PutLogEvents.
const inlineNeeds = `{
	"principals": {"task": {"address": "aws_iam_role.task"}},
	"needs": [
		{"sid": "ReadSecret", "principal": "task", "actions": ["secretsmanager:GetSecretValue"],
		 "resources": ["arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-*"]},
		{"sid": "SendJobs", "principal": "task", "actions": ["sqs:SendMessage"],
		 "resources": ["arn:aws:sqs:us-east-1:123456789012:app-jobs"]},
		{"sid": "WriteLogs", "principal": "task", "actions": ["logs:PutLogEvents"]},
		{"sid": "ReadObjects", "principal": "task", "actions": ["s3:GetObject"],
		 "resources": ["arn:aws:s3:::app-data/*"]}
	]
}`

const inlinePlan = "testdata/principals/inline_policies.json"

// A definite Deny in an inline policy makes the need missing, even when a
// computed policy of the same role may grant it.
func TestPrincipals_InlineDenyIsMissing(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), inlineNeeds)
	r, err := runValidateJSON(t, "--plan-file", inlinePlan, "--config", cfg)
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("want errGapsFound, got %v", err)
	}
	want := []string{"ReadSecret secretsmanager:GetSecretValue"}
	if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings = %q, want %q", got, want)
	}
}

// A computed inline policy is an unknown source: it prints a notice, and it
// makes a need that only it may grant unverified with policy_unknown under
// --strict-resources. A source whose link to the role is undecidable counts
// its Allows as unchecked grants, with the reason condition, and drops its
// Denies.
func TestPrincipals_ComputedAndUndecidableSources(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), inlineNeeds)
	_, stderr, err := runValidate(t, "--plan-file", inlinePlan, "--config", cfg)
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("want errGapsFound from ReadSecret, got %v", err)
	}
	notice := `notice: aws_iam_role_policy.task_queue: policy text is known only after apply; needs of "task" may be granted by it`
	if !strings.Contains(stderr, notice+"\n") {
		t.Errorf("stderr has no notice for the computed policy:\n%s", stderr)
	}
	if strings.Count(stderr, "notice: ") != 2 {
		t.Errorf("want the notice of the computed policy and the one of the run without a policy source:\n%s", stderr)
	}

	r, err := runValidateJSON(t, "--plan-file", inlinePlan, "--config", cfg, "--strict-resources")
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("want errGapsFound, got %v", err)
	}
	want := []string{
		"ReadSecret secretsmanager:GetSecretValue",
		"SendJobs sqs:SendMessage unverified policy_unknown",
		"ReadObjects s3:GetObject unverified condition",
	}
	if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("strict findings =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	if len(r.PolicySources) != 1 || r.PolicySources[0].Principal != "task" || r.PolicySources[0].Address != "aws_iam_role.task" {
		t.Fatalf("policy_sources = %+v, want one entry for task", r.PolicySources)
	}
	var got []string
	for _, s := range r.PolicySources[0].Sources {
		got = append(got, s.Address+" "+s.Kind+" "+s.Text+" "+s.UnknownReason)
	}
	wantSources := []string{
		"aws_iam_role.task identity known ",
		"aws_iam_role_policy.task_logs identity known ",
		"aws_iam_role_policy.task_queue identity unknown computed",
		"aws_iam_role_policy.shared_reads identity known ",
	}
	if strings.Join(got, "\n") != strings.Join(wantSources, "\n") {
		t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantSources, "\n"))
	}
}

// denyDescribeImages allows every action but ecr:DescribeImages.
const denyDescribeImages = `{"Version":"2012-10-17","Statement":[
	{"Effect":"Allow","Action":"*","Resource":"*"},
	{"Effect":"Deny","Action":"ecr:DescribeImages","Resource":"*"}
]}`

// mixedNeeds maps the task role and leaves the deploy label unmapped. The
// need without a principal runs on every run.
const mixedNeeds = `{
	"principals": {"task": {"address": "aws_iam_role.task"}},
	"needs": [
		{"sid": "Tables", "actions": ["dynamodb:DescribeTable"]},
		{"sid": "FetchSecrets", "principal": "task", "actions": ["secretsmanager:GetSecretValue"],
		 "resources": ["arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-*"]},
		{"sid": "VerifyImage", "principal": "deploy", "actions": ["ecr:DescribeImages"]}
	]
}`

// mixedArgs runs worked example 1 without the secret policy, with the
// mixedNeeds config and a policy file that allows every action but
// ecr:DescribeImages.
func mixedArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	dir := t.TempDir()
	policy := dir + "/policy.json"
	if err := writeFile(policy, denyDescribeImages); err != nil {
		t.Fatal(err)
	}
	return append([]string{"--plan-file", ecsTaskNoSecretPolicy, "--policy-file", policy, "--config", writeConfig(t, dir, mixedNeeds)}, extra...)
}

// A mapped need ignores the --policy-* document: the policy file allows
// GetSecretValue, but no policy of the task role does. An unmapped need uses
// the document. Without --principal, the run checks the mapped needs and
// the needs without a principal, and not the unmapped deploy label.
func TestPrincipals_MappedNeedIgnoresPolicyDocument(t *testing.T) {
	r, err := runValidateJSON(t, mixedArgs(t)...)
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("want errGapsFound, got %v", err)
	}
	want := []string{"FetchSecrets secretsmanager:GetSecretValue"}
	if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings = %q, want %q", got, want)
	}
	if r.Missing[0].Principal != "task" {
		t.Errorf("principal = %q, want task", r.Missing[0].Principal)
	}
	if r.PlanResourcesSkipped {
		t.Error("plan_resources_skipped is set on a run with a policy file")
	}
}

// --principal NAME selects the needs labelled NAME and the needs without a
// principal. A mapped NAME uses the plan's policies, and an unmapped one
// uses the --policy-* document, as before.
func TestPrincipals_PrincipalFlag(t *testing.T) {
	t.Run("mapped", func(t *testing.T) {
		r, err := runValidateJSON(t, mixedArgs(t, "--principal", "task")...)
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("want errGapsFound, got %v", err)
		}
		want := []string{"FetchSecrets secretsmanager:GetSecretValue"}
		if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("findings = %q, want %q", got, want)
		}
		if len(r.PolicySources) != 1 {
			t.Errorf("policy_sources = %+v, want the task role", r.PolicySources)
		}
	})
	t.Run("unmapped", func(t *testing.T) {
		r, err := runValidateJSON(t, mixedArgs(t, "--principal", "deploy")...)
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("want errGapsFound, got %v", err)
		}
		want := []string{"VerifyImage ecr:DescribeImages"}
		if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("findings = %q, want %q", got, want)
		}
		if r.Missing[0].Principal != "" {
			t.Errorf("an unmapped need's finding has principal %q", r.Missing[0].Principal)
		}
		if r.PolicySources != nil {
			t.Errorf("policy_sources = %+v, want none when no mapped need runs", r.PolicySources)
		}
	})
}

// A mapped principal whose address matches no resource change in the plan
// is a usage error, so a typo doesn't pass as a role with no policies.
func TestPrincipals_AddressMissingFromPlan(t *testing.T) {
	cfg := writeConfig(t, t.TempDir(), `{"principals":{"task":{"address":"aws_iam_role.tsak"}},
		"needs":[{"sid":"FetchSecrets","principal":"task","actions":["secretsmanager:GetSecretValue"]}]}`)
	_, _, err := runValidate(t, "--plan-file", ecsTaskPlan, "--config", cfg)
	if exitCode(err) != 2 || !strings.Contains(err.Error(), "aws_iam_role.tsak matches no resource change in the plan") {
		t.Errorf("want a usage error that names the address, got %v", err)
	}
}

// Static HCL mode has no plan, so a run there that selects a mapped need is
// a usage error.
func TestPrincipals_StaticModeIsUsageError(t *testing.T) {
	_, _, err := runValidate(t, "--terraform-root", "testdata/realplan", "--policy-file", "testdata/policy_allow_all.json", "--config", ecsTaskConfig)
	if exitCode(err) != 2 || !strings.Contains(err.Error(), "static HCL mode has no plan") {
		t.Errorf("want a static mode usage error, got %v", err)
	}
	// Without a --policy-* flag, the same error comes before any read of a
	// policy file.
	_, _, err = runValidate(t, "--terraform-root", "testdata/realplan", "--config", ecsTaskConfig)
	if exitCode(err) != 2 || !strings.Contains(err.Error(), "static HCL mode has no plan") {
		t.Errorf("without a --policy-* flag: want a static mode usage error, got %v", err)
	}
}

// A run without a --policy-* source checks the mapped needs only, skips the
// plan's resources, and says so. A run without one that selects an unmapped
// need, or whose config has no principals map, fails as before.
func TestPrincipals_RunWithoutPolicySource(t *testing.T) {
	t.Run("mapped needs only", func(t *testing.T) {
		_, stderr, err := runValidate(t, "--plan-file", ecsTaskPlan, "--config", ecsTaskConfig)
		if err != nil {
			t.Fatalf("want a pass, got %v", err)
		}
		if strings.Count(stderr, "the plan's resources weren't checked") != 1 {
			t.Errorf("stderr does not say the resources weren't checked:\n%s", stderr)
		}
		r, _ := runValidateJSON(t, "--plan-file", ecsTaskPlan, "--config", ecsTaskConfig)
		if !r.PlanResourcesSkipped {
			t.Error("plan_resources_skipped is not set")
		}
	})
	usage := "one of --policy-file, --policy-from-plan-output, or --policy-from-state-output is required"
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"need without a principal": {"--config", writeConfig(t, t.TempDir(), mixedNeeds)},
		"unmapped principal":       {"--config", writeConfig(t, dir, mixedNeeds), "--principal", "deploy"},
		"no principals map":        {"--config", "testdata/principal_config.json", "--principal", "task"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := runValidate(t, append([]string{"--plan-file", ecsTaskPlan}, args...)...)
			if exitCode(err) != 2 || err.Error() != usage {
				t.Errorf("want %q, got %v", usage, err)
			}
		})
	}
}

// writeFile writes body to path.
func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}

// Two mapped principals may give a need the same sid, and both run without
// --principal. The text report names the principal of each finding, so the
// findings stay apart. An exclusion "needs.<label>.<sid>" hides the need of
// one principal, and "needs.<sid>" hides the sid of both.
func TestPrincipals_TwoPrincipalsShareASid(t *testing.T) {
	planPath := writePlan(t,
		change("aws_iam_role.task", `"name": "app-task", "arn": "arn:aws:iam::123456789012:role/app-task"`),
		change("aws_iam_role.deploy", `"name": "app-deploy", "arn": "arn:aws:iam::123456789012:role/app-deploy"`))
	config := func(exclude string) string {
		return writeConfig(t, t.TempDir(), `{
			"principals": {"task": {"address": "aws_iam_role.task"}, "deploy": {"address": "aws_iam_role.deploy"}},
			"needs": [
				{"sid": "Read", "principal": "task", "actions": ["s3:GetObject"]},
				{"sid": "Read", "principal": "deploy", "actions": ["s3:GetObject"]}
			],
			"exclude": [`+exclude+`]
		}`)
	}
	_, stderr, _ := runValidate(t, "--plan-file", planPath, "--config", config(""))
	for _, line := range []string{`→ needs "Read" of deploy`, `→ needs "Read" of task`} {
		if !strings.Contains(stderr, line+"\n") {
			t.Errorf("stderr has no line %q:\n%s", line, stderr)
		}
	}
	for exclude, want := range map[string]string{
		`{"permission": "s3:GetObject", "resource": "needs.deploy.Read"}`: "task",
		`{"permission": "s3:GetObject", "resource": "needs.Read"}`:        "",
	} {
		r, _ := runValidateJSON(t, "--plan-file", planPath, "--config", config(exclude))
		var got []string
		for _, m := range r.Missing {
			got = append(got, m.Principal)
		}
		if strings.Join(got, ",") != want {
			t.Errorf("%s: findings of %v, want %q", exclude, got, want)
		}
	}
}
