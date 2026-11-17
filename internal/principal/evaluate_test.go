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
	res, err := Check(Principal{Label: "task", Role: role}, needs, plan.PolicySources(changes, nil), plan.Exclusives(changes), strict)
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

// A resource policy applies to the actions of its service only. A queue
// policy is an unknown source, since this version doesn't read SQS queue
// policies yet.
func TestCheck_ResourcePolicyByService(t *testing.T) {
	raw := `{"resource_changes": [
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
		 "change": {"actions": ["create"], "after": {"name": "app-task"}, "after_unknown": {"arn": true}}},
		{"address": "aws_sqs_queue_policy.q", "type": "aws_sqs_queue_policy", "name": "q",
		 "change": {"actions": ["create"], "after": {"queue_url": "https://sqs.us-east-1.amazonaws.com/123456789012/app-jobs", "policy": "` + allowSQS + `"}, "after_unknown": {}}}]}`
	needs := []iam.Need{
		{Sid: "Send", Actions: []string{"sqs:SendMessage"}},
		{Sid: "Read", Actions: []string{"s3:GetObject"}},
	}
	res := checkPlan(t, raw, needs, true)
	if got, want := verdicts(res.Missing), "Send sqs:SendMessage policy_unknown; Read s3:GetObject"; got != want {
		t.Errorf("strict: %q, want %q", got, want)
	}
	if len(res.Sources) != 1 || res.Sources[0].Address != "aws_sqs_queue_policy.q" || res.Sources[0].Match != plan.LinkMaybe {
		t.Errorf("sources = %+v, want the queue policy as a maybe", res.Sources)
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
	_, err = Check(Principal{Label: "task", Role: changes[0]}, nil, plan.PolicySources(changes, nil), nil, false)
	if err == nil || !strings.Contains(err.Error(), "aws_iam_role_policy.p") {
		t.Errorf("error = %v, want one that names the source", err)
	}
}

// TestPrincipal_Identity checks the policy.Principal of a role in the plan
// and of a role outside it, which the resource policy stages match against
// the Principal and NotPrincipal elements.
func TestPrincipal_Identity(t *testing.T) {
	changes, err := plan.Parse([]byte(`{"resource_changes": [`+taskRole+`]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	got := Principal{Label: "task", Role: changes[0]}.Identity()
	want := policy.Principal{Kind: policy.KindRole, Name: "app-task", PermissionsBoundary: true}
	if got != want {
		t.Errorf("role in the plan = %+v, want %+v", got, want)
	}
	outside := plan.OutsideRole{Name: "ops-admin", ARN: "arn:aws:iam::123456789012:role/ops-admin"}
	got = Principal{Label: "ops", Outside: &outside}.Identity()
	want = policy.Principal{Kind: policy.KindRole, Name: "ops-admin", ARN: outside.ARN}
	if got != want {
		t.Errorf("role outside the plan = %+v, want %+v", got, want)
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
