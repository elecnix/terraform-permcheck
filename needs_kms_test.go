package main

import (
	"strings"
	"testing"
)

// KMS key policies follow AWS's own evaluation: a key policy must allow the
// role, or allow the role's account and so let an identity policy grant the
// action. Each fixture maps the role aws_iam_role.task, whose ARN the plan
// knows, and the key aws_kms_key.data, whose ARN the plan knows too.

// kmsKey is the ARN of aws_kms_key.data in the KMS fixtures.
const kmsKey = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// kmsNeed returns a need of the task role on the resource, as a JSON object
// without its principal. An empty resource gives a need without resources.
func kmsNeed(sid, action, resource string) string {
	n := `"sid": "` + sid + `", "actions": ["` + action + `"]`
	if resource != "" {
		n += `, "resources": ["` + resource + `"]`
	}
	return n
}

// kmsCases runs each case with the config of its need, or with config when
// the case gives none.
func kmsCases(t *testing.T, config string, cases []resourcePolicyCase) {
	t.Helper()
	for _, c := range cases {
		if c.config == "" {
			c.config = config
		}
		t.Run(c.name, c.check)
	}
}

// Rule 4: a key policy that allows neither the role nor its account makes
// the need missing, even when an identity policy allows the action. The
// union rule of the other services would report it covered.
func TestKMS_KeyPolicyGrantsAnotherRoleOnly(t *testing.T) {
	missing := []string{"Decrypt kms:Decrypt"}
	kmsCases(t, serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)), []resourcePolicyCase{{
		name:       "aws_kms_key_policy",
		plan:       "testdata/principals/kms_other_role_only.json",
		want:       missing,
		wantStrict: missing,
	}, {
		// The configuration of the key writes its policy attribute.
		name:       "policy attribute of the key",
		plan:       "testdata/principals/kms_key_policy_attribute.json",
		want:       missing,
		wantStrict: missing,
	}})
}

// Rules 2 and 5: a key policy statement that allows the role itself covers
// the need without an identity grant. A statement on "*" under a condition
// the tool can't evaluate may grant.
func TestKMS_KeyPolicyGrantsTheRole(t *testing.T) {
	kmsCases(t, "", []resourcePolicyCase{{
		name:   "role ARN",
		plan:   "testdata/principals/kms_role_grant.json",
		config: serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey), kmsNeed("Encrypt", "kms:Encrypt", kmsKey)),
	}, {
		name:       "every principal under a condition",
		plan:       "testdata/principals/kms_role_grant.json",
		config:     serviceConfig(t, kmsNeed("DataKey", "kms:GenerateDataKey", kmsKey)),
		wantStrict: []string{"DataKey kms:GenerateDataKey unverified condition"},
	}, {
		name:       "no statement for the action",
		plan:       "testdata/principals/kms_role_grant.json",
		config:     serviceConfig(t, kmsNeed("Sign", "kms:Sign", kmsKey)),
		want:       []string{"Sign kms:Sign"},
		wantStrict: []string{"Sign kms:Sign"},
	}})
}

// Rule 3: a statement for the role's account delegates the actions it
// allows to the identity policies, and only those actions.
func TestKMS_AccountDelegation(t *testing.T) {
	plan := "testdata/principals/kms_account.json"
	kmsCases(t, "", []resourcePolicyCase{{
		// The account statement allows Decrypt, and so does the identity
		// policy.
		name:   "delegated and granted",
		plan:   plan,
		config: serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)),
	}, {
		name:       "delegated, not granted",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("DataKey", "kms:GenerateDataKey", kmsKey)),
		want:       []string{"DataKey kms:GenerateDataKey"},
		wantStrict: []string{"DataKey kms:GenerateDataKey"},
	}, {
		// The identity policy allows DescribeKey, but the account statement
		// doesn't delegate it.
		name:       "granted, not delegated",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Describe", "kms:DescribeKey", kmsKey)),
		want:       []string{"Describe kms:DescribeKey"},
		wantStrict: []string{"Describe kms:DescribeKey"},
	}, {
		// A role statement grants Encrypt without an identity grant.
		name:   "role statement beside the account statement",
		plan:   plan,
		config: serviceConfig(t, kmsNeed("Encrypt", "kms:Encrypt", kmsKey)),
	}, {
		// A need on "*" acts on no particular key, so the identity policies
		// decide it.
		name:   "need on every resource",
		plan:   plan,
		config: serviceConfig(t, kmsNeed("ListAliases", "kms:ListAliases", "*")),
	}, {
		// A need without resources may act on a key outside the plan, whose
		// key policy is unknown.
		name:       "need without resources",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", "")),
		wantStrict: []string{"Decrypt kms:Decrypt unverified resource_scope"},
	}})
}

// Rule 1: a definite Deny in the key policy or in an identity policy makes
// the need missing.
func TestKMS_Deny(t *testing.T) {
	plan := "testdata/principals/kms_deny.json"
	kmsCases(t, "", []resourcePolicyCase{{
		name:       "Deny in the key policy",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)),
		want:       []string{"Decrypt kms:Decrypt"},
		wantStrict: []string{"Decrypt kms:Decrypt"},
	}, {
		// The key policy grants Encrypt to the role, and the identity
		// policy denies it.
		name:       "Deny in the identity policy",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Encrypt", "kms:Encrypt", kmsKey)),
		want:       []string{"Encrypt kms:Encrypt"},
		wantStrict: []string{"Encrypt kms:Encrypt"},
	}})
}

// Rule 6: a key whose configuration leaves the policy out, and that no
// aws_kms_key_policy sets, gets AWS's default key policy. It delegates every
// action to the identity policies.
func TestKMS_DefaultKeyPolicy(t *testing.T) {
	plan := "testdata/principals/kms_default_policy.json"
	kmsCases(t, "", []resourcePolicyCase{{
		name:   "identity grant",
		plan:   plan,
		config: serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)),
	}, {
		name:       "no identity grant",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Encrypt", "kms:Encrypt", kmsKey)),
		want:       []string{"Encrypt kms:Encrypt"},
		wantStrict: []string{"Encrypt kms:Encrypt"},
	}})
	// The default key policy has a known text, so it gets no notice.
	checkNoticeAbsent(t, plan, serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)), "aws_kms_key.data")
}

// The key's policy attribute and an aws_kms_key_policy both set the policy.
// Each apply sets one of them, so the key policy is either one, and its
// grants are grants the tool can't check.
func TestKMS_BothPolicies(t *testing.T) {
	kmsCases(t, serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)), []resourcePolicyCase{{
		name:       "one grants the role",
		plan:       "testdata/principals/kms_both_policies.json",
		wantStrict: []string{"Decrypt kms:Decrypt unverified condition"},
	}})
}

// Rule 5: terraform computes the key policy at apply time. The key policy
// may grant the role itself, so the need is covered by default with or
// without an identity grant.
func TestKMS_KeyPolicyComputed(t *testing.T) {
	plan := "testdata/principals/kms_key_policy_computed.json"
	kmsCases(t, "", []resourcePolicyCase{{
		name:       "identity grant",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)),
		wantStrict: []string{"Decrypt kms:Decrypt unverified policy_unknown"},
	}, {
		name:       "no identity grant",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Encrypt", "kms:Encrypt", kmsKey)),
		wantStrict: []string{"Encrypt kms:Encrypt unverified policy_unknown"},
	}})
	checkNotice(t, plan, serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)), "aws_kms_key_policy.data", true)
}

// Rule 7: the plan has no key with the need's ARN, so the key policy is
// unknown. A definite identity Deny still makes the need missing.
func TestKMS_KeyOutsidePlan(t *testing.T) {
	plan := "testdata/principals/kms_outside_plan.json"
	kmsCases(t, "", []resourcePolicyCase{{
		name:       "identity grant",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)),
		wantStrict: []string{"Decrypt kms:Decrypt unverified policy_unknown"},
	}, {
		name:       "no identity grant",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Encrypt", "kms:Encrypt", kmsKey)),
		wantStrict: []string{"Encrypt kms:Encrypt unverified policy_unknown"},
	}, {
		name:       "identity Deny",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Delete", "kms:ScheduleKeyDeletion", kmsKey)),
		want:       []string{"Delete kms:ScheduleKeyDeletion"},
		wantStrict: []string{"Delete kms:ScheduleKeyDeletion"},
	}})
	_, stderr, _ := runValidate(t, "--plan-file", plan, "--config", serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)))
	want := `notice: KMS key ` + kmsKey + ` isn't in the plan, so its key policy is unknown; needs of "task" may be granted by it`
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr lacks %q:\n%s", want, stderr)
	}

	// The json report gives the key policy the reason outside_plan, not
	// computed: the policy exists, and the plan doesn't contain it.
	r, _ := runValidateJSON(t, "--plan-file", plan, "--config", serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)))
	var reasons []string
	for _, p := range r.PolicySources {
		for _, s := range p.Sources {
			if s.Kind == "resource" && s.Text == "unknown" {
				reasons = append(reasons, s.UnknownReason)
			}
		}
	}
	if strings.Join(reasons, ",") != "outside_plan" {
		t.Errorf("unknown_reason of the key policy = %q, want outside_plan", reasons)
	}
}

// Rule 9: a need may name the key by an alias. The plan links the alias to
// the key through target_key_id, so the key's policy decides the need. An
// alias that the plan doesn't show may name a key outside the plan.
func TestKMS_Alias(t *testing.T) {
	plan := "testdata/principals/kms_alias.json"
	kmsCases(t, "", []resourcePolicyCase{{
		name:   "alias of the key",
		plan:   plan,
		config: serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", "arn:aws:kms:us-east-1:123456789012:alias/app-data")),
	}, {
		name:       "alias outside the plan",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", "arn:aws:kms:us-east-1:123456789012:alias/app-other")),
		wantStrict: []string{"Decrypt kms:Decrypt unverified policy_unknown"},
	}})
}

// Rule 10: a grant gives access outside key policies and IAM policies. A
// grant in the plan whose grantee may be the role covers the need by
// default, and the need is unverified under --strict-resources.
func TestKMS_Grant(t *testing.T) {
	plan := "testdata/principals/kms_grant.json"
	kmsCases(t, "", []resourcePolicyCase{{
		name:       "operation of the grant",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Decrypt", "kms:Decrypt", kmsKey)),
		wantStrict: []string{"Decrypt kms:Decrypt unverified condition"},
	}, {
		name:       "operation outside the grant",
		plan:       plan,
		config:     serviceConfig(t, kmsNeed("Encrypt", "kms:Encrypt", kmsKey)),
		want:       []string{"Encrypt kms:Encrypt"},
		wantStrict: []string{"Encrypt kms:Encrypt"},
	}})
}

// checkNoticeAbsent runs the plan and checks that stderr has no notice line
// for the address.
func checkNoticeAbsent(t *testing.T, plan, config, address string) {
	t.Helper()
	_, stderr, _ := runValidate(t, "--plan-file", plan, "--config", config)
	if strings.Contains(stderr, "notice: "+address+":") {
		t.Errorf("%s: stderr has a notice for %s:\n%s", plan, address, stderr)
	}
}
