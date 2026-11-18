package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	outsideRolePlan          = "testdata/principals/outside_role.json"
	outsideRoleExclusivePlan = "testdata/principals/outside_role_exclusive.json"
	outsideRoleConfig        = "testdata/principals/outside_role_config.json"
)

// A role outside the plan, mapped by its name. The plan attaches one inline
// policy to it, which grants logs:PutLogEvents. Other stacks may attach more
// policies to the role, so the need for ssm:GetParameter is covered by
// default and unverified with policy_unknown under --strict-resources. When
// the plan also has both exclusive resources for the role, it shows every
// policy of the role, and the need is missing.
func TestOutsideRole_ExclusiveResourcesMakeTheSetComplete(t *testing.T) {
	_, stderr, err := runValidate(t, "--plan-file", outsideRolePlan, "--config", outsideRoleConfig)
	if err != nil {
		t.Fatalf("default mode: want a pass, got %v\nstderr:\n%s", err, stderr)
	}
	r, err := runValidateJSON(t, "--plan-file", outsideRolePlan, "--config", outsideRoleConfig, "--strict-resources")
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("strict mode: want errGapsFound, got %v", err)
	}
	want := []string{"ReadParams ssm:GetParameter unverified policy_unknown"}
	if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("strict findings = %q, want %q", got, want)
	}

	for _, strict := range []bool{false, true} {
		args := []string{"--plan-file", outsideRoleExclusivePlan, "--config", outsideRoleConfig}
		if strict {
			args = append(args, "--strict-resources")
		}
		r, err := runValidateJSON(t, args...)
		if !errors.Is(err, errGapsFound) {
			t.Fatalf("strict %v with exclusives: want errGapsFound, got %v", strict, err)
		}
		want := []string{"ReadParams ssm:GetParameter"}
		if got := verdicts(r); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("strict %v with exclusives: findings = %q, want %q", strict, got, want)
		}
	}
}

// outsideJSON is the part of the json report that the outside role tests
// read, with the keys of a role outside the plan.
type outsideJSON struct {
	PolicySources []struct {
		Principal string `json:"principal"`
		Address   string `json:"address"`
		Name      string `json:"name"`
		ARN       string `json:"arn"`
		Complete  *bool  `json:"complete"`
		Sources   []struct {
			Address       string   `json:"address"`
			Path          string   `json:"path"`
			Kind          string   `json:"kind"`
			Text          string   `json:"text"`
			UnknownReason string   `json:"unknown_reason"`
			PolicyARN     string   `json:"policy_arn"`
			PolicyName    string   `json:"policy_name"`
			Policy        string   `json:"policy"`
			Unlisted      []string `json:"unlisted"`
			Link          string   `json:"link"`
		} `json:"sources"`
	} `json:"policy_sources"`
}

// outsideReport runs the validate command with --format json and decodes the
// policy_sources of the report.
func outsideReport(t *testing.T, args ...string) outsideJSON {
	t.Helper()
	stdout, stderr, _ := runValidate(t, append(args, "--format", "json")...)
	var out outsideJSON
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("invalid JSON: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	return out
}

// outsideSources collapses the sources of the only principal of a report to
// "address path text unknown_reason policy_name policy unlisted link".
func outsideSources(t *testing.T, r outsideJSON) []string {
	t.Helper()
	if len(r.PolicySources) != 1 {
		t.Fatalf("policy_sources = %+v, want one principal", r.PolicySources)
	}
	var out []string
	for _, s := range r.PolicySources[0].Sources {
		fields := []string{s.Address, s.Path, s.Text, s.UnknownReason, s.PolicyName, s.Policy, strings.Join(s.Unlisted, ","), s.Link}
		var kept []string
		for _, f := range fields {
			if f != "" {
				kept = append(kept, f)
			}
		}
		out = append(out, strings.Join(kept, " "))
	}
	return out
}

// Resource changes for the outside role plans. Each is an entry of
// resource_changes. The plans have no configuration section, so each link
// is decided by its known value.
const (
	opsLogsPolicy = `{"address": "aws_iam_role_policy.ops_logs", "type": "aws_iam_role_policy", "name": "ops_logs",
		"change": {"actions": ["create"], "after": {"name": "ops-logs", "role": "ops-admin",
		"policy": "{\"Statement\":[{\"Action\":\"logs:PutLogEvents\",\"Effect\":\"Allow\",\"Resource\":\"*\"}]}"}, "after_unknown": {"id": true}}}`
	opsPoliciesExclusive = `{"address": "aws_iam_role_policies_exclusive.ops", "type": "aws_iam_role_policies_exclusive", "name": "ops",
		"change": {"actions": ["create"], "after": {"role_name": "ops-admin", "policy_names": ["ops-logs"]}, "after_unknown": {}}}`
	opsAttachmentsExclusiveEmpty = `{"address": "aws_iam_role_policy_attachments_exclusive.ops", "type": "aws_iam_role_policy_attachments_exclusive", "name": "ops",
		"change": {"actions": ["create"], "after": {"role_name": "ops-admin", "policy_arns": []}, "after_unknown": {}}}`
	paramsPolicy = `{"address": "aws_iam_policy.params", "type": "aws_iam_policy", "name": "params",
		"change": {"actions": ["create"], "after": {"name": "ops-params", "arn": "arn:aws:iam::123456789012:policy/ops-params",
		"policy": "{\"Statement\":[{\"Action\":\"ssm:GetParameter\",\"Effect\":\"Allow\",\"Resource\":\"*\"}]}"}, "after_unknown": {}}}`
)

// opsAttachmentsExclusive returns an aws_iam_role_policy_attachments_exclusive
// for ops-admin with the given policy_arns and after_unknown values.
func opsAttachmentsExclusive(arns, unknown string) string {
	return `{"address": "aws_iam_role_policy_attachments_exclusive.ops", "type": "aws_iam_role_policy_attachments_exclusive", "name": "ops",
		"change": {"actions": ["create"], "after": {"role_name": "ops-admin"` + arns + `}, "after_unknown": {` + unknown + `}}}`
}

// writePlan writes a plan with the given resource_changes entries and
// returns its path.
func writePlan(t *testing.T, changes ...string) string {
	t.Helper()
	path := t.TempDir() + "/plan.json"
	if err := writeFile(path, `{"format_version": "1.2", "resource_changes": [`+strings.Join(changes, ",\n")+`]}`); err != nil {
		t.Fatal(err)
	}
	return path
}

// outsideNeeds is a config that maps ops to the role given by entry, with a
// need for ssm:GetParameter and a need for logs:PutLogEvents, which the
// plan's inline policy grants.
func outsideNeeds(t *testing.T, entry string) string {
	t.Helper()
	return writeConfig(t, t.TempDir(), `{
		"principals": {"ops": `+entry+`},
		"needs": [
			{"sid": "ReadParams", "principal": "ops", "actions": ["ssm:GetParameter"],
			 "resources": ["arn:aws:ssm:us-east-1:123456789012:parameter/app/*"]},
			{"sid": "WriteLogs", "principal": "ops", "actions": ["logs:PutLogEvents"]}
		]
	}`)
}

// strictVerdicts runs the check under --strict-resources and returns its
// findings.
func strictVerdicts(t *testing.T, planPath, cfg string) []string {
	t.Helper()
	r, _ := runValidateJSON(t, "--plan-file", planPath, "--config", cfg, "--strict-resources")
	return verdicts(r)
}

// assertVerdicts fails the test when the findings differ from want.
func assertVerdicts(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s: findings =\n%s\nwant\n%s", what, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// An arn entry gives the role's name, the last part of its path, so the
// inline policy on role = "ops-admin" attaches to it. The verdicts are those
// of the name entry.
//
// The plan's resources name the role by its name, which the provider
// resolves in an account that the plan doesn't show. They may name a role of
// another account, so the inline policy may grant a need, and the exclusive
// resources don't make the plan list every policy of the role.
func TestOutsideRole_ARNEntry(t *testing.T) {
	cfg := outsideNeeds(t, `{"arn": "arn:aws:iam::123456789012:role/ops-admin"}`)
	unverified := []string{
		"ReadParams ssm:GetParameter unverified policy_unknown",
		"WriteLogs logs:PutLogEvents unverified condition",
	}
	assertVerdicts(t, "without exclusives", strictVerdicts(t, writePlan(t, opsLogsPolicy), cfg), unverified)
	withExclusives := writePlan(t, opsLogsPolicy, opsPoliciesExclusive, opsAttachmentsExclusiveEmpty)
	assertVerdicts(t, "with exclusives", strictVerdicts(t, withExclusives, cfg), unverified)
	assertVerdicts(t, "sources with exclusives", outsideSources(t, outsideReport(t, "--plan-file", withExclusives, "--config", cfg)), []string{
		"aws_iam_role_policy.ops_logs policy known ops-logs maybe",
		"unknown attached_outside_plan inline,managed yes",
	})
	_, stderr, _ := runValidate(t, "--plan-file", withExclusives, "--config", cfg)
	line := `notice: role arn:aws:iam::123456789012:role/ops-admin is outside the plan, and other stacks may attach inline and managed policies to it; needs of "ops" may be granted by them; with a "name" entry instead of "arn", an aws_iam_role_policies_exclusive and an aws_iam_role_policy_attachments_exclusive for the role make the plan list every policy of that kind, since the plan doesn't show the account that a name resolves in`
	// The exclusive resource of inline policies names ops-logs, which the
	// plan defines for the same role name, so it adds no notice of its own.
	if !strings.Contains(stderr, line+"\n") || strings.Contains(stderr, "aws_iam_role_policies_exclusive.ops:") {
		t.Errorf("stderr has no line %q, or has a notice of the exclusive resource:\n%s", line, stderr)
	}

	r := outsideReport(t, "--plan-file", writePlan(t, opsLogsPolicy), "--config", cfg)
	p := r.PolicySources[0]
	if p.Address != "" || p.Name != "" || p.ARN != "arn:aws:iam::123456789012:role/ops-admin" {
		t.Errorf("principal = %+v, want the arn only", p)
	}
}

// A need that the plan's inline policy grants is covered under
// --strict-resources, with and without the exclusive resources: the policies
// attached outside the plan can't remove a grant.
func TestOutsideRole_NeedThePlanGrants(t *testing.T) {
	cfg := outsideNeeds(t, `{"name": "ops-admin"}`)
	assertVerdicts(t, "without exclusives", strictVerdicts(t, writePlan(t, opsLogsPolicy), cfg),
		[]string{"ReadParams ssm:GetParameter unverified policy_unknown"})
	assertVerdicts(t, "with exclusives", strictVerdicts(t, writePlan(t, opsLogsPolicy, opsPoliciesExclusive, opsAttachmentsExclusiveEmpty), cfg),
		[]string{"ReadParams ssm:GetParameter"})
}

// With one of the two exclusive resources, the plan lists one kind of
// policy only. The implicit source stays, and it names the other kind. The
// role isn't complete.
func TestOutsideRole_OneExclusiveResource(t *testing.T) {
	cfg := outsideNeeds(t, `{"name": "ops-admin"}`)
	for name, c := range map[string]struct {
		exclusive string
		unlisted  string
		fix       string
	}{
		"inline only":  {opsPoliciesExclusive, "managed", "an aws_iam_role_policy_attachments_exclusive for the role makes"},
		"managed only": {opsAttachmentsExclusiveEmpty, "inline", "an aws_iam_role_policies_exclusive for the role makes"},
	} {
		t.Run(name, func(t *testing.T) {
			planPath := writePlan(t, opsLogsPolicy, c.exclusive)
			assertVerdicts(t, "strict", strictVerdicts(t, planPath, cfg), []string{"ReadParams ssm:GetParameter unverified policy_unknown"})
			r := outsideReport(t, "--plan-file", planPath, "--config", cfg)
			if p := r.PolicySources[0]; p.Complete == nil || *p.Complete {
				t.Errorf("complete = %v, want false", p.Complete)
			}
			got := outsideSources(t, r)
			want := []string{
				"aws_iam_role_policy.ops_logs policy known ops-logs yes",
				"unknown attached_outside_plan " + c.unlisted + " yes",
			}
			assertVerdicts(t, "sources", got, want)
			_, stderr, _ := runValidate(t, "--plan-file", planPath, "--config", cfg)
			line := `notice: role ops-admin is outside the plan, and other stacks may attach ` + c.unlisted + ` policies to it; needs of "ops" may be granted by them; ` + c.fix + ` the plan list every policy of that kind`
			if !strings.Contains(stderr, line+"\n") {
				t.Errorf("stderr has no line %q:\n%s", line, stderr)
			}
		})
	}
}

// An exclusive list that terraform computes at apply time still lists every
// policy of its kind, so the role is complete. The list is one source with
// unknown text: the need is covered by default and unverified with
// policy_unknown under --strict-resources.
func TestOutsideRole_ComputedExclusiveList(t *testing.T) {
	cfg := outsideNeeds(t, `{"name": "ops-admin"}`)
	planPath := writePlan(t, opsLogsPolicy, opsPoliciesExclusive, opsAttachmentsExclusive("", `"policy_arns": true`))
	if _, stderr, err := runValidate(t, "--plan-file", planPath, "--config", cfg); err != nil {
		t.Fatalf("default mode: want a pass, got %v\nstderr:\n%s", err, stderr)
	}
	assertVerdicts(t, "strict", strictVerdicts(t, planPath, cfg), []string{"ReadParams ssm:GetParameter unverified policy_unknown"})
	r := outsideReport(t, "--plan-file", planPath, "--config", cfg)
	if p := r.PolicySources[0]; p.Complete == nil || !*p.Complete {
		t.Errorf("complete = %v, want true", p.Complete)
	}
	assertVerdicts(t, "sources", outsideSources(t, r), []string{
		"aws_iam_role_policy.ops_logs policy known ops-logs yes",
		"aws_iam_role_policy_attachments_exclusive.ops policy_arns unknown computed yes",
	})
}

// An inline policy that policy_names lists and that the plan doesn't define
// stays on the role, and the plan doesn't show its text. It is an unknown
// source, with a notice that names it.
func TestOutsideRole_PolicyNameThePlanDoesNotDefine(t *testing.T) {
	cfg := outsideNeeds(t, `{"name": "ops-admin"}`)
	exclusive := strings.Replace(opsPoliciesExclusive, `["ops-logs"]`, `["ops-logs", "ops-extra"]`, 1)
	planPath := writePlan(t, opsLogsPolicy, exclusive, opsAttachmentsExclusiveEmpty)
	assertVerdicts(t, "strict", strictVerdicts(t, planPath, cfg), []string{"ReadParams ssm:GetParameter unverified policy_unknown"})
	r := outsideReport(t, "--plan-file", planPath, "--config", cfg)
	assertVerdicts(t, "sources", outsideSources(t, r), []string{
		"aws_iam_role_policy.ops_logs policy known ops-logs yes",
		"aws_iam_role_policies_exclusive.ops policy_names.1 unknown outside_plan ops-extra yes",
	})
	_, stderr, _ := runValidate(t, "--plan-file", planPath, "--config", cfg)
	line := `notice: aws_iam_role_policies_exclusive.ops: the plan doesn't define the inline policy ops-extra that the list names; needs of "ops" may be granted by it`
	if !strings.Contains(stderr, line+"\n") {
		t.Errorf("stderr has no line %q:\n%s", line, stderr)
	}
}

// policy_arns attaches managed policies as stage 4's attachments do. An ARN
// of an aws_iam_policy of the plan reads its text, which grants
// ssm:GetParameter. An AWS managed policy is outside the plan, so it is an
// unknown source.
func TestOutsideRole_PolicyARNs(t *testing.T) {
	cfg := outsideNeeds(t, `{"name": "ops-admin"}`)
	t.Run("aws_iam_policy of the plan", func(t *testing.T) {
		planPath := writePlan(t, paramsPolicy, opsLogsPolicy, opsPoliciesExclusive,
			opsAttachmentsExclusive(`, "policy_arns": ["arn:aws:iam::123456789012:policy/ops-params"]`, ""))
		assertVerdicts(t, "strict", strictVerdicts(t, planPath, cfg), nil)
		assertVerdicts(t, "sources", outsideSources(t, outsideReport(t, "--plan-file", planPath, "--config", cfg)), []string{
			"aws_iam_role_policy.ops_logs policy known ops-logs yes",
			"aws_iam_role_policy_attachments_exclusive.ops policy_arns.0 known aws_iam_policy.params yes",
		})
	})
	t.Run("AWS managed policy", func(t *testing.T) {
		planPath := writePlan(t, opsLogsPolicy, opsPoliciesExclusive,
			opsAttachmentsExclusive(`, "policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]`, ""))
		assertVerdicts(t, "strict", strictVerdicts(t, planPath, cfg), []string{"ReadParams ssm:GetParameter unverified policy_unknown"})
		assertVerdicts(t, "sources", outsideSources(t, outsideReport(t, "--plan-file", planPath, "--config", cfg)), []string{
			"aws_iam_role_policy.ops_logs policy known ops-logs yes",
			"aws_iam_role_policy_attachments_exclusive.ops policy_arns.0 unknown outside_plan yes",
		})
	})
}

// A name or arn that a role of the plan has is a usage error that gives the
// role's address, so a role has one way to be named.
func TestOutsideRole_RoleInThePlan(t *testing.T) {
	role := `{"address": "aws_iam_role.ops", "type": "aws_iam_role", "name": "ops",
		"change": {"actions": ["create"], "after": {"name": "ops-admin"}, "after_unknown": {"arn": true}}}`
	planPath := writePlan(t, role, opsLogsPolicy)
	for _, entry := range []string{`{"name": "ops-admin"}`, `{"arn": "arn:aws:iam::123456789012:role/ops-admin"}`} {
		_, _, err := runValidate(t, "--plan-file", planPath, "--config", outsideNeeds(t, entry))
		if exitCode(err) != 2 || !strings.Contains(err.Error(), `is in the plan as aws_iam_role.ops: map it with "address": "aws_iam_role.ops"`) {
			t.Errorf("%s: want a usage error that gives the address, got %v", entry, err)
		}
	}
}

// The config errors of a principals entry fail the run with exit code 2.
func TestOutsideRole_ConfigErrors(t *testing.T) {
	for entry, want := range map[string]string{
		`{"name": "ops-admin", "arn": "arn:aws:iam::123456789012:role/ops-admin"}`: "set only one of address, name and arn",
		`{"address": "aws_iam_role.ops", "name": "ops-admin"}`:                     "set only one of address, name and arn",
		`{"arn": "arn:aws:iam::123456789012:policy/ops"}`:                          "is not the ARN of an IAM role",
		`{"arn": "arn:aws:iam::123456789012:role/ops-*"}`:                          "has a wildcard",
		`{"name": "ops-*"}`: "has a wildcard",
		`{}`:                "address is required, or name or arn for a role or user outside the plan",
	} {
		_, _, err := runValidate(t, "--plan-file", outsideRolePlan, "--config", outsideNeeds(t, entry))
		if exitCode(err) != 2 || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want a usage error with %q, got %v", entry, want, err)
		}
	}
}

// The notice and the json report of a role outside the plan without the
// exclusive resources: one notice for the implicit source, and a
// policy_sources entry with the name, complete false, and the implicit
// source last, with no address.
func TestOutsideRole_NoticeAndJSON(t *testing.T) {
	_, stderr, _ := runValidate(t, "--plan-file", outsideRolePlan, "--config", outsideRoleConfig)
	line := `notice: role ops-admin is outside the plan, and other stacks may attach inline and managed policies to it; needs of "ops" may be granted by them; an aws_iam_role_policies_exclusive and an aws_iam_role_policy_attachments_exclusive for the role make the plan list every policy of that kind`
	if !strings.Contains(stderr, line+"\n") {
		t.Errorf("stderr has no line %q:\n%s", line, stderr)
	}
	if n := strings.Count(stderr, "notice: "); n != 2 {
		t.Errorf("stderr has %d notices, want the implicit source's and the one of the run without a policy source:\n%s", n, stderr)
	}

	r := outsideReport(t, "--plan-file", outsideRolePlan, "--config", outsideRoleConfig)
	p := r.PolicySources[0]
	if p.Principal != "ops" || p.Address != "" || p.Name != "ops-admin" || p.ARN != "" || p.Complete == nil || *p.Complete {
		t.Errorf("principal = %+v, want ops by name, not complete", p)
	}
	assertVerdicts(t, "sources", outsideSources(t, r), []string{
		"aws_iam_role_policy.ops_logs policy known ops-logs yes",
		"unknown attached_outside_plan inline,managed yes",
	})
	if s := p.Sources[1]; s.Kind != "identity" {
		t.Errorf("implicit source kind = %q, want identity", s.Kind)
	}

	r = outsideReport(t, "--plan-file", outsideRoleExclusivePlan, "--config", outsideRoleConfig)
	if p := r.PolicySources[0]; p.Complete == nil || !*p.Complete {
		t.Errorf("with exclusives: complete = %v, want true", p.Complete)
	}
	assertVerdicts(t, "sources with exclusives", outsideSources(t, r), []string{"aws_iam_role_policy.ops_logs policy known ops-logs yes"})
	_, stderr, _ = runValidate(t, "--plan-file", outsideRoleExclusivePlan, "--config", outsideRoleConfig)
	if strings.Contains(stderr, "outside the plan") {
		t.Errorf("with exclusives: stderr has a notice for the role:\n%s", stderr)
	}
}

// A role in the plan keeps its JSON layout: an address and no complete key.
func TestOutsideRole_RoleInPlanHasNoCompleteKey(t *testing.T) {
	r := outsideReport(t, "--plan-file", ecsTaskPlan, "--config", ecsTaskConfig)
	if p := r.PolicySources[0]; p.Address != "aws_iam_role.task" || p.Complete != nil || p.Name != "" {
		t.Errorf("principal = %+v, want the address and no complete key", p)
	}
}
