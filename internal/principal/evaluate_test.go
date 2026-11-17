package principal

import (
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
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
	res, err := Check(Principal{Label: "task", Role: role}, needs, plan.PolicySources(changes), strict)
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

// A resource policy applies to the actions of its service only. It is an
// unknown source, since this version doesn't read whom it grants.
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
	_, err = Check(Principal{Label: "task", Role: changes[0]}, nil, plan.PolicySources(changes), false)
	if err == nil || !strings.Contains(err.Error(), "aws_iam_role_policy.p") {
		t.Errorf("error = %v, want one that names the source", err)
	}
}
