package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The cross-account cases of issue #175. A request across accounts needs an
// Allow from the identity side and from the resource side. Each fixture maps
// the role aws_iam_role.task, whose ARN arn:aws:iam::111122223333:role/app-task
// the plan knows, unless a case says otherwise. The resources are in account
// 444455556666.
//
// testdata/principals/cross_account.json holds these resources:
//
//   - An inline policy of the task role allows GetSecretValue on every secret
//     of 444455556666 and denies it on id-denied-*. It allows sts:AssumeRole on
//     the role deploy, kms:Decrypt and kms:GenerateDataKey on every key, and
//     dynamodb:GetItem on the table app.
//   - Secret policies: app-db grants the task role GetSecretValue and
//     DescribeSecret, other-db grants another role, root-db grants the
//     account 111122223333, deny-db grants the task role and denies every
//     principal, id-denied-db grants the task role, computed-db has a policy
//     text known only after apply, and session-db grants a session of the
//     role bounded.
//   - The KMS key aws_kms_key.shared, whose key policy allows the task role
//     kms:Decrypt and kms:Encrypt, and the account 111122223333
//     kms:GenerateDataKey.
//   - The role bounded, with no identity policy, and a permissions boundary
//     that allows logs:* only.
const (
	crossAccountPlan         = "testdata/principals/cross_account.json"
	crossAccountNoIdentity   = "testdata/principals/cross_account_no_identity.json"
	crossAccountComputedRole = "testdata/principals/cross_account_computed_role.json"
)

// otherSecret returns the ARN of a secret in account 444455556666.
func otherSecret(name string) string {
	return "arn:aws:secretsmanager:us-east-1:444455556666:secret:" + name + "-AbCdEf"
}

// otherKey is the ARN of aws_kms_key.shared.
const otherKey = "arn:aws:kms:us-east-1:444455556666:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// crossNeed returns a need of the task role, as a JSON object without its
// principal. An empty resource gives a need without resources.
func crossNeed(sid, action, resource string) string {
	return kmsNeed(sid, action, resource)
}

// crossAccountNotice is the notice line for a resource in another account
// whose resource policy isn't in the plan.
func crossAccountNotice(resource string) string {
	return "notice: " + resource + ` is outside the account of "task", and its resource policy isn't in the plan; needs of "task" on it depend on that policy`
}

// The secret policy grants the role's ARN, and no identity policy allows the
// action. In one account the secret policy's Allow is enough. Across
// accounts the identity side must allow the request on its own.
func TestCrossAccount_IdentitySideMustAllow(t *testing.T) {
	missing := []string{fetchSecrets}
	resourcePolicyCase{
		plan:       crossAccountNoIdentity,
		config:     serviceConfig(t, crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", otherSecret("app-db"))),
		want:       missing,
		wantStrict: missing,
	}.check(t)
}

// The role's ARN is computed, so its account is unknown, and the
// same-account rule applies. The secret policy names a role of the same
// name in an account the tool can't compare, so it may grant the role.
func TestCrossAccount_UnknownAccountUsesSameAccountRule(t *testing.T) {
	resourcePolicyCase{
		plan:       crossAccountComputedRole,
		config:     serviceConfig(t, crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", otherSecret("app-db"))),
		wantStrict: []string{fetchSecrets + " unverified condition"},
	}.check(t)
}

// Each side of a cross-account need, with the secret policies.
func TestCrossAccount_SecretPolicies(t *testing.T) {
	missing := []string{fetchSecrets}
	for _, c := range []resourcePolicyCase{{
		name: "both sides allow",
		plan: crossAccountPlan,
	}, {
		name:       "resource policy grants another role",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", otherSecret("other-db"))),
		want:       missing,
		wantStrict: missing,
	}, {
		// The account statement lets the account's IAM policies grant the
		// request, and the identity side allows it.
		name:   "resource policy grants the principal's account",
		plan:   crossAccountPlan,
		config: serviceConfig(t, crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", otherSecret("root-db"))),
	}, {
		name:       "no resource policy in the plan",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", otherSecret("absent-db"))),
		wantStrict: []string{fetchSecrets + " unverified cross_account"},
	}, {
		name:       "resource policy text computed",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", otherSecret("computed-db"))),
		wantStrict: []string{fetchSecrets + " unverified policy_unknown"},
	}, {
		name:       "Deny in the resource policy",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", otherSecret("deny-db"))),
		want:       missing,
		wantStrict: missing,
	}, {
		name:       "Deny in the identity policy",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", otherSecret("id-denied-db"))),
		want:       missing,
		wantStrict: missing,
	}, {
		// The secret policy grants DescribeSecret, and no identity policy
		// does.
		name:       "resource policy grants, identity side doesn't",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("Describe", "secretsmanager:DescribeSecret", otherSecret("app-db"))),
		want:       []string{describe},
		wantStrict: []string{describe},
	}, {
		// A need without resources has no account, so the same-account rule
		// applies, and the grant of app-db may reach the need's resource.
		name:       "need without resources",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("Describe", "secretsmanager:DescribeSecret", "")),
		wantStrict: []string{describe + " unverified resource_scope"},
	}} {
		if c.config == "" {
			c.config = serviceConfig(t, crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", otherSecret("app-db")))
		}
		t.Run(c.name, c.check)
	}
}

// PermCheck doesn't read a role's trust policy, or the resource policy of a
// DynamoDB table. Across accounts, that policy must allow the request too,
// and the plan doesn't show it.
func TestCrossAccount_UnreadResourcePolicies(t *testing.T) {
	for _, c := range []resourcePolicyCase{{
		name:       "sts:AssumeRole with an identity grant",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("Assume", "sts:AssumeRole", "arn:aws:iam::444455556666:role/deploy")),
		wantStrict: []string{"Assume sts:AssumeRole unverified cross_account"},
	}, {
		name:       "sts:AssumeRole without an identity grant",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("Assume", "sts:AssumeRole", "arn:aws:iam::444455556666:role/admin")),
		want:       []string{"Assume sts:AssumeRole"},
		wantStrict: []string{"Assume sts:AssumeRole"},
	}, {
		name:       "DynamoDB table",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("Read", "dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:444455556666:table/app")),
		wantStrict: []string{"Read dynamodb:GetItem unverified cross_account"},
	}} {
		t.Run(c.name, c.check)
	}
}

// A KMS key in another account needs a key policy Allow and an IAM policy
// Allow in the caller's account. A key policy statement for the role itself
// doesn't cover the need without an identity grant.
func TestCrossAccount_KMSKey(t *testing.T) {
	for _, c := range []resourcePolicyCase{{
		name:   "key policy names the role, identity grant",
		plan:   crossAccountPlan,
		config: serviceConfig(t, crossNeed("Decrypt", "kms:Decrypt", otherKey)),
	}, {
		name:       "key policy names the role, no identity grant",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("Encrypt", "kms:Encrypt", otherKey)),
		want:       []string{"Encrypt kms:Encrypt"},
		wantStrict: []string{"Encrypt kms:Encrypt"},
	}, {
		name:   "key policy names the account, identity grant",
		plan:   crossAccountPlan,
		config: serviceConfig(t, crossNeed("DataKey", "kms:GenerateDataKey", otherKey)),
	}, {
		name:       "key outside the plan",
		plan:       crossAccountPlan,
		config:     serviceConfig(t, crossNeed("Decrypt", "kms:Decrypt", "arn:aws:kms:us-east-1:444455556666:key/abcd1234-12ab-34cd-56ef-1234567890ab")),
		wantStrict: []string{"Decrypt kms:Decrypt unverified cross_account"},
	}} {
		t.Run(c.name, c.check)
	}
}

// The secret policy of session-db grants a session of the role bounded,
// which has no identity policy. In one account a permissions boundary
// doesn't limit a grant to a session. Across accounts the identity side must
// still allow the request on its own, so the need is missing.
func TestCrossAccount_BoundaryDoesNotOpenIdentitySide(t *testing.T) {
	config := writeConfig(t, t.TempDir(), `{
		"principals": {"bounded": {"address": "aws_iam_role.bounded"}},
		"needs": [{"sid": "FetchSecrets", "principal": "bounded", "actions": ["secretsmanager:GetSecretValue"], "resources": ["`+otherSecret("session-db")+`"]}]
	}`)
	missing := []string{fetchSecrets}
	resourcePolicyCase{plan: crossAccountPlan, config: config, want: missing, wantStrict: missing}.check(t)
}

// A resource in another account without a resource policy in the plan gets
// one notice per principal and resource, and policy_sources lists it as an
// unknown resource source.
func TestCrossAccount_NoticeAndPolicySource(t *testing.T) {
	absent := otherSecret("absent-db")
	config := serviceConfig(t,
		crossNeed("FetchSecrets", "secretsmanager:GetSecretValue", absent),
		crossNeed("Describe", "secretsmanager:DescribeSecret", absent),
		crossNeed("Read", "dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:444455556666:table/app"))
	_, stderr, err := runValidate(t, "--plan-file", crossAccountPlan, "--config", config)
	if err != nil && !errors.Is(err, errGapsFound) {
		t.Fatal(err)
	}
	if n := strings.Count(stderr, crossAccountNotice(absent)); n != 1 {
		t.Errorf("stderr has %d notices for %s, want 1:\n%s", n, absent, stderr)
	}
	if !strings.Contains(stderr, crossAccountNotice("arn:aws:dynamodb:us-east-1:444455556666:table/app")) {
		t.Errorf("stderr lacks the notice of the table:\n%s", stderr)
	}

	stdout, _, _ := runValidate(t, "--plan-file", crossAccountPlan, "--config", config, "--format", "json")
	var out struct {
		PolicySources []struct {
			Sources []struct {
				Address       string `json:"address"`
				Kind          string `json:"kind"`
				Text          string `json:"text"`
				UnknownReason string `json:"unknown_reason"`
				Resource      string `json:"resource"`
				Link          string `json:"link"`
			} `json:"sources"`
		} `json:"policy_sources"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &out); jerr != nil {
		t.Fatalf("invalid JSON: %v\n%s", jerr, stdout)
	}
	var got []string
	for _, p := range out.PolicySources {
		for _, s := range p.Sources {
			if s.UnknownReason == "cross_account" {
				got = append(got, strings.Join([]string{s.Address, s.Kind, s.Text, s.Resource, s.Link}, " "))
			}
		}
	}
	want := []string{
		" resource unknown " + absent + " yes",
		" resource unknown arn:aws:dynamodb:us-east-1:444455556666:table/app yes",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("cross-account sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
