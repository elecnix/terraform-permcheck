package principal

import (
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// checkPlan parses an inline plan, finds the role at aws_iam_role.task, and
// checks the needs of the label task against the plan's policy sources.
func checkPlan(t *testing.T, raw string, needs []iam.Need, strict bool) Result {
	t.Helper()
	changes, err := plan.Parse([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	role, err := Find(changes, "task", "aws_iam_role.task")
	if err != nil {
		t.Fatal(err)
	}
	for i := range needs {
		needs[i].Principal = "task"
	}
	res, err := Check(Principal{Label: "task", Change: role}, needs, plan.PolicySources(changes, nil), plan.Exclusives(changes), strict)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// verdicts collapses findings to "sid action reason".
func verdicts(missing []iam.MissingAction) string {
	var out []string
	for _, m := range missing {
		s := m.Need + " " + m.Action
		switch {
		case m.PolicyUnknownUnverified:
			s += " policy_unknown"
		case m.ConditionUnverified:
			s += " condition"
		case m.ResourceScopeUnverified:
			s += " resource_scope"
		}
		if m.Principal != "task" {
			s += " without the label"
		}
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

const taskRole = `{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
	"change": {"actions": ["create"], "after": {"name": "app-task", "permissions_boundary": "arn:aws:iam::123456789012:policy/boundary"},
	"after_unknown": {"arn": true}}}`

const allowSQS = `{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sqs:SendMessage\",\"Resource\":\"*\"}]}`

// A permissions boundary whose text this version doesn't read can only
// remove permissions. It never makes a need covered that no identity policy
// grants, and under --strict-resources it makes a granted need unverified.
func TestCheck_UnknownBoundary(t *testing.T) {
	raw := `{"resource_changes": [` + taskRole + `,
		{"address": "aws_iam_role_policy.p", "type": "aws_iam_role_policy", "name": "p",
		 "change": {"actions": ["create"], "after": {"role": "app-task", "policy": "` + allowSQS + `"}, "after_unknown": {}}}]}`
	needs := func() []iam.Need {
		return []iam.Need{
			{Sid: "Send", Actions: []string{"sqs:SendMessage"}},
			{Sid: "Read", Actions: []string{"s3:GetObject"}},
		}
	}
	if got, want := verdicts(checkPlan(t, raw, needs(), false).Missing), "Read s3:GetObject"; got != want {
		t.Errorf("default: %q, want %q", got, want)
	}
	res := checkPlan(t, raw, needs(), true)
	if got, want := verdicts(res.Missing), "Send sqs:SendMessage policy_unknown; Read s3:GetObject"; got != want {
		t.Errorf("strict: %q, want %q", got, want)
	}
	var kinds []string
	for _, s := range res.Sources {
		kinds = append(kinds, s.Address+" "+string(s.Kind)+" "+s.Match.String())
	}
	if got, want := strings.Join(kinds, "; "), "aws_iam_role.task boundary yes; aws_iam_role_policy.p identity yes"; got != want {
		t.Errorf("sources = %q, want %q", got, want)
	}
}

// A resource policy applies to the actions of its service only. A need
// without resources may act on a key outside the plan, whose key policy is
// unknown: the check adds an implicit source for it.
func TestCheck_ResourcePolicyByService(t *testing.T) {
	raw := `{"resource_changes": [
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
		 "change": {"actions": ["create"], "after": {"name": "app-task"}, "after_unknown": {"arn": true}}},
		{"address": "aws_kms_key_policy.k", "type": "aws_kms_key_policy", "name": "k",
		 "change": {"actions": ["create"], "after": {"key_id": "1234abcd-12ab-34cd-56ef-1234567890ab", "policy": "{}"}, "after_unknown": {}}}]}`
	needs := []iam.Need{
		{Sid: "Decrypt", Actions: []string{"kms:Decrypt"}},
		{Sid: "Read", Actions: []string{"s3:GetObject"}},
	}
	res := checkPlan(t, raw, needs, true)
	if got, want := verdicts(res.Missing), "Decrypt kms:Decrypt policy_unknown; Read s3:GetObject"; got != want {
		t.Errorf("strict: %q, want %q", got, want)
	}
	if len(res.Sources) != 2 || res.Sources[0].Address != "aws_kms_key_policy.k" || res.Sources[0].Match != plan.LinkMaybe ||
		!res.Sources[1].ResourceOutside || res.Sources[1].Resource != "" || !res.Sources[1].Unknown {
		t.Errorf("sources = %+v, want the key policy as a maybe, then the key outside the plan", res.Sources)
	}
}

// secretPolicy is an aws_secretsmanager_secret_policy whose secret_arn the
// configuration sets to the value secretARN, and whose policy grants
// GetSecretValue to every principal.
func secretPolicy(secretARN string) string {
	after := `"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"secretsmanager:GetSecretValue\",\"Resource\":\"*\"}]}"`
	unknown := `{"secret_arn": true}`
	if secretARN != "" {
		after += `, "secret_arn": "` + secretARN + `"`
		unknown = `{}`
	}
	return `{"address": "aws_secretsmanager_secret_policy.s", "type": "aws_secretsmanager_secret_policy", "name": "s",
		"change": {"actions": ["create"], "after": {` + after + `}, "after_unknown": ` + unknown + `}}`
}

// A secret policy applies to the secret its secret_arn names. A known ARN
// names a secret outside the plan, and the policy applies to a need on that
// secret only. A secret_arn that the plan computes from no resource of the
// plan, such as a variable, may name any secret: the policy's Allows are
// grants the tool can't check, with the reason resource_scope.
func TestCheck_SecretPolicyResource(t *testing.T) {
	need := func(resource string) []iam.Need {
		return []iam.Need{{Sid: "Fetch", Actions: []string{"secretsmanager:GetSecretValue"},
			Resources: []string{"arn:aws:secretsmanager:us-east-1:123456789012:secret:" + resource}}}
	}
	// The role has no permissions boundary, which would be an unknown
	// source.
	role := `{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
		"change": {"actions": ["create"], "after": {"name": "app-task"}, "after_unknown": {"arn": true}}}`
	known := `{"resource_changes": [` + role + `, ` + secretPolicy("arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf") + `]}`
	for resource, want := range map[string]string{"shared-AbCdEf": "", "app-db-AbCdEf": "Fetch secretsmanager:GetSecretValue"} {
		res := checkPlan(t, known, need(resource), true)
		if got := verdicts(res.Missing); got != want {
			t.Errorf("known secret_arn, need on %s: %q, want %q", resource, got, want)
		}
	}

	unknown := `{"resource_changes": [` + role + `, ` + secretPolicy("") + `]}`
	if got := verdicts(checkPlan(t, unknown, need("app-db-AbCdEf"), false).Missing); got != "" {
		t.Errorf("unknown secret_arn, default: %q, want covered", got)
	}
	res := checkPlan(t, unknown, need("app-db-AbCdEf"), true)
	if got, want := verdicts(res.Missing), "Fetch secretsmanager:GetSecretValue resource_scope"; got != want {
		t.Errorf("unknown secret_arn, strict: %q, want %q", got, want)
	}
	if len(res.Sources) != 1 || res.Sources[0].Match != plan.LinkMaybe {
		t.Errorf("sources = %+v, want the secret policy as a maybe", res.Sources)
	}
}

// A resource policy of another service applies to no checked need, so it
// isn't one of the principal's sources.
func TestCheck_ResourcePolicyOfAnotherService(t *testing.T) {
	raw := `{"resource_changes": [
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
		 "change": {"actions": ["create"], "after": {"name": "app-task"}, "after_unknown": {"arn": true}}},
		{"address": "aws_kms_key_policy.k", "type": "aws_kms_key_policy", "name": "k",
		 "change": {"actions": ["create"], "after": {"key_id": "1234abcd-12ab-34cd-56ef-1234567890ab", "policy": "{}"}, "after_unknown": {}}}]}`
	res := checkPlan(t, raw, []iam.Need{{Sid: "Send", Actions: []string{"sqs:SendMessage"}}}, false)
	if got, want := verdicts(res.Missing), "Send sqs:SendMessage"; got != want {
		t.Errorf("findings = %q, want %q", got, want)
	}
	if len(res.Sources) != 0 {
		t.Errorf("sources = %+v, want none", res.Sources)
	}
}

// A policy text in the plan that doesn't parse is an error that names its
// source.
func TestCheck_UnparsablePolicy(t *testing.T) {
	changes, err := plan.Parse([]byte(`{"resource_changes": [
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
		 "change": {"actions": ["create"], "after": {"name": "app-task"}, "after_unknown": {}}},
		{"address": "aws_iam_role_policy.p", "type": "aws_iam_role_policy", "name": "p",
		 "change": {"actions": ["create"], "after": {"role": "app-task", "policy": "not json"}, "after_unknown": {}}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Check(Principal{Label: "task", Change: changes[0]}, nil, plan.PolicySources(changes, nil), nil, false)
	if err == nil || !strings.Contains(err.Error(), "aws_iam_role_policy.p") {
		t.Errorf("error = %v, want one that names the source", err)
	}
}

// TestPrincipal_Identity checks the policy.Principal of a role or user in
// the plan and of a role or user outside it, which the resource policy stages match against
// the Principal and NotPrincipal elements.
func TestPrincipal_Identity(t *testing.T) {
	changes, err := plan.Parse([]byte(`{"resource_changes": [`+taskRole+`]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	got := Principal{Label: "task", Change: changes[0]}.Identity()
	want := policy.Principal{Kind: policy.KindRole, Name: "app-task", PermissionsBoundary: true}
	if got != want {
		t.Errorf("role in the plan = %+v, want %+v", got, want)
	}
	outside := plan.OutsidePrincipal{Type: "aws_iam_role", Name: "ops-admin", ARN: "arn:aws:iam::123456789012:role/ops-admin"}
	got = Principal{Label: "ops", Outside: &outside}.Identity()
	want = policy.Principal{Kind: policy.KindRole, Name: "ops-admin", ARN: outside.ARN}
	if got != want {
		t.Errorf("role outside the plan = %+v, want %+v", got, want)
	}

	users, err := plan.Parse([]byte(`{"resource_changes": [
		{"address": "aws_iam_user.ci", "type": "aws_iam_user", "name": "ci",
		 "change": {"actions": ["no-op"], "before": {"name": "ci", "arn": "arn:aws:iam::123456789012:user/ci"},
		 "after": {"name": "ci", "arn": "arn:aws:iam::123456789012:user/ci", "permissions_boundary": "arn:aws:iam::123456789012:policy/b"}, "after_unknown": {}}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	got = Principal{Label: "ci", Change: users[0]}.Identity()
	want = policy.Principal{Kind: policy.KindUser, Name: "ci", ARN: "arn:aws:iam::123456789012:user/ci", PermissionsBoundary: true}
	if got != want {
		t.Errorf("user in the plan = %+v, want %+v", got, want)
	}
	user := plan.OutsidePrincipal{Type: "aws_iam_user", Name: "ci"}
	got = Principal{Label: "ci", Outside: &user}.Identity()
	want = policy.Principal{Kind: policy.KindUser, Name: "ci"}
	if got != want {
		t.Errorf("user outside the plan = %+v, want %+v", got, want)
	}
}

// For a role in the plan, an exclusive resource doesn't change a verdict by
// completing the set, since the check assumes the plan shows every policy.
// A source whose kind the list covers and that the list omits may be
// removed after the apply, so its link is maybe: its Allow counts as a grant
// the tool can't check, and its Deny doesn't count. A listed source keeps
// its link.
func TestCheck_ExclusiveOmitsSourceOfRoleInPlan(t *testing.T) {
	denyLogs := `{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sqs:SendMessage\",\"Resource\":\"*\"},{\"Effect\":\"Deny\",\"Action\":\"logs:PutLogEvents\",\"Resource\":\"*\"}]}`
	allowLogs := `{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"logs:PutLogEvents\",\"Resource\":\"*\"}]}`
	plain := `{"resource_changes": [
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
		 "change": {"actions": ["create"], "after": {"name": "app-task"}, "after_unknown": {"arn": true}}},
		{"address": "aws_iam_role_policy.kept", "type": "aws_iam_role_policy", "name": "kept",
		 "change": {"actions": ["create"], "after": {"role": "app-task", "name": "kept", "policy": "` + allowLogs + `"}, "after_unknown": {}}},
		{"address": "aws_iam_role_policy.omitted", "type": "aws_iam_role_policy", "name": "omitted",
		 "change": {"actions": ["create"], "after": {"role": "app-task", "name": "omitted", "policy": "` + denyLogs + `"}, "after_unknown": {}}}`
	withExclusive := plain + `,
		{"address": "aws_iam_role_policies_exclusive.task", "type": "aws_iam_role_policies_exclusive", "name": "task",
		 "change": {"actions": ["create"], "after": {"role_name": "app-task", "policy_names": ["kept"]}, "after_unknown": {}}}]}`
	needs := func() []iam.Need {
		return []iam.Need{
			{Sid: "Send", Actions: []string{"sqs:SendMessage"}},
			{Sid: "Logs", Actions: []string{"logs:PutLogEvents"}},
		}
	}
	// Without the exclusive resource, the Deny of the omitted policy makes
	// Logs missing.
	if got, want := verdicts(checkPlan(t, plain+`]}`, needs(), true).Missing), "Logs logs:PutLogEvents"; got != want {
		t.Errorf("without exclusive: %q, want %q", got, want)
	}
	if got, want := verdicts(checkPlan(t, withExclusive, needs(), false).Missing), ""; got != want {
		t.Errorf("default: %q, want %q", got, want)
	}
	res := checkPlan(t, withExclusive, needs(), true)
	if got, want := verdicts(res.Missing), "Send sqs:SendMessage condition"; got != want {
		t.Errorf("strict: %q, want %q", got, want)
	}
	var links []string
	for _, s := range res.Sources {
		links = append(links, s.Address+" "+s.Match.String())
	}
	if got, want := strings.Join(links, "; "), "aws_iam_role_policy.kept yes; aws_iam_role_policy.omitted maybe"; got != want {
		t.Errorf("sources = %q, want %q", got, want)
	}
	if !res.Complete {
		t.Error("a role in the plan is not complete")
	}
}

// boundedRole is the role app-task, whose ARN the plan knows, with the
// boundary aws_iam_policy.boundary. The boundary policy allows logs:* only.
const boundedRole = `{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
	"change": {"actions": ["no-op"],
		"before": {"name": "app-task", "arn": "arn:aws:iam::123456789012:role/app-task", "permissions_boundary": "arn:aws:iam::123456789012:policy/app-boundary"},
		"after": {"name": "app-task", "arn": "arn:aws:iam::123456789012:role/app-task", "permissions_boundary": "arn:aws:iam::123456789012:policy/app-boundary"},
		"after_unknown": {}}},
	{"address": "aws_iam_policy.boundary", "type": "aws_iam_policy", "name": "boundary",
	 "change": {"actions": ["no-op"],
		"before": {"name": "app-boundary", "arn": "arn:aws:iam::123456789012:policy/app-boundary", "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"logs:*\",\"Resource\":\"*\"}]}"},
		"after": {"name": "app-boundary", "arn": "arn:aws:iam::123456789012:policy/app-boundary", "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"logs:*\",\"Resource\":\"*\"}]}"},
		"after_unknown": {}}}`

// kmsKey is a KMS key whose key policy has the given statements, as they
// appear inside a JSON string of a plan.
func kmsKey(statements string) string {
	policy := `{\"Version\":\"2012-10-17\",\"Statement\":[` + statements + `]}`
	state := `{"arn": "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab", "key_id": "1234abcd-12ab-34cd-56ef-1234567890ab", "policy": "` + policy + `"}`
	return `{"address": "aws_kms_key.k", "type": "aws_kms_key", "name": "k",
		"change": {"actions": ["no-op"], "before": ` + state + `, "after": ` + state + `, "after_unknown": {}}}`
}

// The KMS documentation doesn't say how a permissions boundary combines with
// a key policy, so the check applies IAM's rule for resource policies. A key
// policy statement for the role's ARN is limited by the boundary, so a need
// that the boundary doesn't allow is missing and names the boundary. A
// statement for a session of the role isn't limited, and it may or may not
// grant the session that makes the request, so the need is covered by
// default and unverified under --strict-resources. An account statement
// delegates to the identity policies, which the boundary limits.
func TestCheck_BoundaryWithKeyPolicy(t *testing.T) {
	need := func() []iam.Need {
		return []iam.Need{{Sid: "Decrypt", Actions: []string{"kms:Decrypt"},
			Resources: []string{"arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"}}}
	}
	allowKMS := `{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"kms:Decrypt\",\"Resource\":\"*\"}]}`
	identity := `{"address": "aws_iam_role_policy.p", "type": "aws_iam_role_policy", "name": "p",
		"change": {"actions": ["create"], "after": {"role": "app-task", "policy": "` + allowKMS + `"}, "after_unknown": {}}}`
	cases := []struct {
		name, statement, identity string
		want, wantStrict          string
		boundary                  string
	}{
		{"the role's ARN", `{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:role/app-task\"},\"Action\":\"kms:Decrypt\",\"Resource\":\"*\"}`, "",
			"Decrypt kms:Decrypt", "Decrypt kms:Decrypt", "aws_iam_policy.boundary"},
		{"a session of the role", `{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:sts::123456789012:assumed-role/app-task/app-session\"},\"Action\":\"kms:Decrypt\",\"Resource\":\"*\"}`, "",
			"", "Decrypt kms:Decrypt condition", ""},
		{"the account and an identity policy", `{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}`, ", " + identity,
			"Decrypt kms:Decrypt", "Decrypt kms:Decrypt", "aws_iam_policy.boundary"},
	}
	for _, c := range cases {
		raw := `{"resource_changes": [` + boundedRole + `, ` + kmsKey(c.statement) + c.identity + `]}`
		res := checkPlan(t, raw, need(), false)
		if got := verdicts(res.Missing); got != c.want {
			t.Errorf("%s, default: %q, want %q", c.name, got, c.want)
		}
		if len(res.Missing) == 1 && res.Missing[0].Boundary != c.boundary {
			t.Errorf("%s: boundary = %q, want %q", c.name, res.Missing[0].Boundary, c.boundary)
		}
		if got := verdicts(checkPlan(t, raw, need(), true).Missing); got != c.wantStrict {
			t.Errorf("%s, strict: %q, want %q", c.name, got, c.wantStrict)
		}
	}
}

// A boundary ARN that may name either of two policies is one of them. The
// need is missing only when neither allows it. When one of them allows it,
// the need is covered by default and unverified with the reason condition
// under --strict-resources.
func TestCheck_BoundaryMayNameEitherPolicy(t *testing.T) {
	policy := func(index, action string) string {
		text := `{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"` + action + `\",\"Resource\":\"*\"}]}`
		return `{"address": "aws_iam_policy.b[` + index + `]", "type": "aws_iam_policy", "name": "b", "index": ` + index + `,
			"change": {"actions": ["create"], "after": {"policy": "` + text + `"}, "after_unknown": {"arn": true, "name": true}}}`
	}
	allowS3 := `{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}`
	plan := func(second string) string {
		return `{"resource_changes": [
			{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
			 "change": {"actions": ["create"], "after": {"name": "app-task"}, "after_unknown": {"arn": true, "permissions_boundary": true}}},
			` + policy("0", "logs:*") + `, ` + policy("1", second) + `,
			{"address": "aws_iam_role_policy.p", "type": "aws_iam_role_policy", "name": "p",
			 "change": {"actions": ["create"], "after": {"role": "app-task", "policy": "` + allowS3 + `"}, "after_unknown": {}}}],
			"configuration": {"root_module": {"resources": [
				{"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
				 "expressions": {"name": {}, "permissions_boundary": {"references": ["aws_iam_policy.b.arn", "aws_iam_policy.b"]}}}]}}}`
	}
	need := func() []iam.Need { return []iam.Need{{Sid: "Read", Actions: []string{"s3:GetObject"}}} }
	res := checkPlan(t, plan("sqs:*"), need(), false)
	if got, want := verdicts(res.Missing), "Read s3:GetObject"; got != want {
		t.Errorf("neither allows: %q, want %q", got, want)
	}
	if len(res.Missing) == 1 && res.Missing[0].Boundary != "aws_iam_policy.b[0] or aws_iam_policy.b[1]" {
		t.Errorf("boundary = %q, want both policies", res.Missing[0].Boundary)
	}
	if got := verdicts(checkPlan(t, plan("s3:*"), need(), false).Missing); got != "" {
		t.Errorf("one allows, default: %q, want covered", got)
	}
	if got, want := verdicts(checkPlan(t, plan("s3:*"), need(), true).Missing), "Read s3:GetObject condition"; got != want {
		t.Errorf("one allows, strict: %q, want %q", got, want)
	}
}

// A need crosses accounts only when the tool knows both account ids and they
// differ.
func TestCrossAccount(t *testing.T) {
	role := policy.Principal{Kind: policy.KindRole, ARN: "arn:aws:iam::111122223333:role/app-task"}
	for _, c := range []struct {
		name     string
		identity policy.Principal
		resource string
		want     bool
	}{
		{"other account", role, "arn:aws:secretsmanager:us-east-1:444455556666:secret:app-db-AbCdEf", true},
		{"same account", role, "arn:aws:secretsmanager:us-east-1:111122223333:secret:app-db-AbCdEf", false},
		{"role in another account", role, "arn:aws:iam::444455556666:role/deploy", true},
		{"principal ARN unknown", policy.Principal{Kind: policy.KindRole, Name: "app-task"}, "arn:aws:iam::444455556666:role/deploy", false},
		{"S3 object", role, "arn:aws:s3:::app-data/report.csv", false},
		{"wildcard account", role, "arn:aws:sqs:us-east-1:*:app-jobs", false},
		{"every resource", role, "*", false},
		{"no resources", role, "", false},
	} {
		if got := crossAccount(c.identity, c.resource); got != c.want {
			t.Errorf("%s: crossAccount = %v, want %v", c.name, got, c.want)
		}
	}
}
