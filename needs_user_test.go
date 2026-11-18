package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	userGroupPlan   = "testdata/principals/user_group.json"
	userGroupConfig = "testdata/principals/user_group_config.json"
)

// A user whose only grant comes from a group: the plan puts
// aws_iam_user.deployer in aws_iam_group.deployers, whose inline policy
// allows ecr:DescribeImages. The need is covered, and covered under
// --strict-resources.
func TestUser_GrantFromAGroup(t *testing.T) {
	for _, strict := range []bool{false, true} {
		args := []string{"--plan-file", userGroupPlan, "--config", userGroupConfig}
		if strict {
			args = append(args, "--strict-resources")
		}
		_, stderr, err := runValidate(t, args...)
		if err != nil {
			t.Errorf("strict %v: want a pass, got %v\nstderr:\n%s", strict, err, stderr)
		}
	}
	r, err := runValidateJSON(t, "--plan-file", userGroupPlan, "--config", userGroupConfig, "--strict-resources")
	if errors.Is(err, errGapsFound) || len(verdicts(r)) != 0 {
		t.Errorf("findings = %q, want none", verdicts(r))
	}

	// The group policy's source entry gives the group it comes through.
	got := userSources(t, "--plan-file", userGroupPlan, "--config", userGroupConfig)
	want := []string{"aws_iam_group_policy.deployers policy identity known group=aws_iam_group.deployers yes"}
	assertVerdicts(t, "sources", got, want)
}

// Resource changes of the user tests. The plans have no configuration
// section, so each link is decided by its known value. The user exists, so
// the plan knows its ARN.
const (
	deployerARN = "arn:aws:iam::123456789012:user/deployer"
	ecrRepo     = "arn:aws:ecr:us-east-1:123456789012:repository/app"
	ecrPolicy   = "arn:aws:iam::123456789012:policy/app-ecr"
)

// userChange returns the aws_iam_user deployer with extra after values.
func userChange(extra string) string {
	return `{"address": "aws_iam_user.deployer", "type": "aws_iam_user", "name": "deployer",
		"change": {"actions": ["no-op"], "before": {"name": "deployer", "arn": "` + deployerARN + `"` + extra + `},
		"after": {"name": "deployer", "arn": "` + deployerARN + `"` + extra + `}, "after_unknown": {}}}`
}

// policyText returns an escaped policy text with one statement of the
// effect on the action and every resource.
func policyText(effect, action string) string {
	return `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"` + effect + `\",\"Action\":\"` + action + `\",\"Resource\":\"*\"}]}`
}

// change returns a create of a resource at address with the after values.
func change(address, after string) string {
	typ, name, _ := strings.Cut(address, ".")
	return `{"address": "` + address + `", "type": "` + typ + `", "name": "` + name + `",
		"change": {"actions": ["create"], "after": {` + after + `}, "after_unknown": {"id": true}}}`
}

var (
	deployer        = userChange("")
	deployersGroup  = change("aws_iam_group.deployers", `"name": "deployers"`)
	deployersECR    = change("aws_iam_group_policy.deployers", `"name": "deployers-ecr", "group": "deployers", "policy": "`+policyText("Allow", "ecr:DescribeImages")+`"`)
	deployerInGroup = change("aws_iam_user_group_membership.deployer", `"user": "deployer", "groups": ["deployers"]`)
	ecrManaged      = change("aws_iam_policy.ecr", `"name": "app-ecr", "arn": "`+ecrPolicy+`", "policy": "`+policyText("Allow", "ecr:DescribeImages")+`"`)
)

// userConfig maps deployer to the entry and gives it a need for
// ecr:DescribeImages on the app repository.
func userConfig(t *testing.T, entry string) string {
	t.Helper()
	return writeConfig(t, t.TempDir(), `{
		"principals": {"deployer": `+entry+`},
		"needs": [{"sid": "ReadImages", "principal": "deployer", "actions": ["ecr:DescribeImages"], "resources": ["`+ecrRepo+`"]}]
	}`)
}

// userFindings runs the check in json format and collapses each finding to
// "sid action [unverified reason] [boundary name]".
func userFindings(t *testing.T, planPath, config string, strict bool) []string {
	t.Helper()
	args := []string{"--plan-file", planPath, "--config", config, "--format", "json"}
	if strict {
		args = append(args, "--strict-resources")
	}
	stdout, stderr, err := runValidate(t, args...)
	if err != nil && !errors.Is(err, errGapsFound) {
		t.Fatalf("strict %v: %v\nstderr:\n%s", strict, err, stderr)
	}
	var out struct {
		Missing []struct {
			Need          string `json:"need"`
			MissingAction string `json:"missing_action"`
			Unverified    string `json:"unverified"`
			Boundary      string `json:"boundary"`
		} `json:"missing"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &out); jerr != nil {
		t.Fatalf("invalid JSON: %v\nstdout:\n%s", jerr, stdout)
	}
	var got []string
	for _, m := range out.Missing {
		s := m.Need + " " + m.MissingAction
		if m.Unverified != "" {
			s += " unverified " + m.Unverified
		}
		if m.Boundary != "" {
			s += " boundary " + m.Boundary
		}
		got = append(got, s)
	}
	return got
}

// userCase is one plan and config, with the findings of the default mode and
// of --strict-resources.
type userCase struct {
	name       string
	changes    []string
	config     string
	want       []string
	wantStrict []string
}

// checkUserCases runs each case in both modes. A case without a config
// maps deployer to aws_iam_user.deployer.
func checkUserCases(t *testing.T, cases []userCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			config := c.config
			if config == "" {
				config = userConfig(t, `{"address": "aws_iam_user.deployer"}`)
			}
			planPath := writePlan(t, c.changes...)
			assertVerdicts(t, "default", userFindings(t, planPath, config, false), c.want)
			assertVerdicts(t, "strict", userFindings(t, planPath, config, true), c.wantStrict)
		})
	}
}

// userSources runs the check in json format and collapses the sources of
// its only principal to "address path kind text [unknown_reason]
// [group=...] [unlisted=...] link".
func userSources(t *testing.T, args ...string) []string {
	t.Helper()
	stdout, stderr, _ := runValidate(t, append(args, "--format", "json")...)
	var out struct {
		PolicySources []struct {
			Sources []struct {
				Address       string   `json:"address"`
				Path          string   `json:"path"`
				Kind          string   `json:"kind"`
				Text          string   `json:"text"`
				UnknownReason string   `json:"unknown_reason"`
				Group         string   `json:"group"`
				Unlisted      []string `json:"unlisted"`
				Link          string   `json:"link"`
			} `json:"sources"`
		} `json:"policy_sources"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("invalid JSON: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if len(out.PolicySources) != 1 {
		t.Fatalf("policy_sources = %+v, want one principal", out.PolicySources)
	}
	var got []string
	for _, s := range out.PolicySources[0].Sources {
		fields := []string{s.Address, s.Path, s.Kind, s.Text, s.UnknownReason}
		if s.Group != "" {
			fields = append(fields, "group="+s.Group)
		}
		if len(s.Unlisted) > 0 {
			fields = append(fields, "unlisted="+strings.Join(s.Unlisted, ","))
		}
		fields = append(fields, s.Link)
		var kept []string
		for _, f := range fields {
			if f != "" {
				kept = append(kept, f)
			}
		}
		got = append(got, strings.Join(kept, " "))
	}
	return got
}

// userNotices runs the check in text format and returns its notice lines.
func userNotices(t *testing.T, planPath, config string) []string {
	t.Helper()
	_, stderr, _ := runValidate(t, "--plan-file", planPath, "--config", config)
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "notice: ") && !strings.HasPrefix(line, resourcesSkippedPrefix) {
			out = append(out, line)
		}
	}
	return out
}

// resourcesSkippedPrefix starts the notice of a run without a --policy-*
// source, which every user test prints.
const resourcesSkippedPrefix = "notice: the plan's resources weren't checked"

// The grants of a user's own policies and of its groups' policies, and the
// gaps that the plan proves.
func TestUser_IdentityPolicies(t *testing.T) {
	missing := []string{"ReadImages ecr:DescribeImages"}
	checkUserCases(t, []userCase{{
		name:       "the group policy without the membership",
		changes:    []string{deployer, deployersGroup, deployersECR},
		want:       missing,
		wantStrict: missing,
	}, {
		name: "aws_iam_group_membership",
		changes: []string{deployer, deployersGroup, deployersECR,
			change("aws_iam_group_membership.deployers", `"name": "deployers", "group": "deployers", "users": ["deployer", "other"]`)},
	}, {
		name: "aws_iam_group_membership of other users",
		changes: []string{deployer, deployersGroup, deployersECR,
			change("aws_iam_group_membership.deployers", `"name": "deployers", "group": "deployers", "users": ["other"]`)},
		want:       missing,
		wantStrict: missing,
	}, {
		name: "a group policy attachment to a managed policy of the plan",
		changes: []string{deployer, deployersGroup, deployerInGroup, ecrManaged,
			change("aws_iam_group_policy_attachment.deployers", `"group": "deployers", "policy_arn": "`+ecrPolicy+`"`)},
	}, {
		name: "aws_iam_user_policy",
		changes: []string{deployer,
			change("aws_iam_user_policy.deployer", `"name": "ecr", "user": "deployer", "policy": "`+policyText("Allow", "ecr:DescribeImages")+`"`)},
	}, {
		name: "aws_iam_user_policy of another user",
		changes: []string{deployer,
			change("aws_iam_user_policy.other", `"name": "ecr", "user": "other", "policy": "`+policyText("Allow", "ecr:DescribeImages")+`"`)},
		want:       missing,
		wantStrict: missing,
	}, {
		name: "aws_iam_user_policy_attachment",
		changes: []string{deployer, ecrManaged,
			change("aws_iam_user_policy_attachment.deployer", `"user": "deployer", "policy_arn": "`+ecrPolicy+`"`)},
	}, {
		name: "aws_iam_policy_attachment with users",
		changes: []string{deployer, ecrManaged,
			change("aws_iam_policy_attachment.ecr", `"name": "ecr", "policy_arn": "`+ecrPolicy+`", "users": ["deployer"]`)},
	}, {
		name: "aws_iam_policy_attachment with groups",
		changes: []string{deployer, deployersGroup, deployerInGroup, ecrManaged,
			change("aws_iam_policy_attachment.ecr", `"name": "ecr", "policy_arn": "`+ecrPolicy+`", "groups": ["deployers"]`)},
	}, {
		name: "a Deny in a group policy",
		changes: []string{deployer, deployersGroup, deployerInGroup,
			change("aws_iam_user_policy.deployer", `"name": "ecr", "user": "deployer", "policy": "`+policyText("Allow", "ecr:*")+`"`),
			change("aws_iam_group_policy.deny", `"name": "deny", "group": "deployers", "policy": "`+policyText("Deny", "ecr:DescribeImages")+`"`)},
		want:       missing,
		wantStrict: missing,
	}, {
		name: "a user AWS managed policy outside the plan",
		changes: []string{deployer,
			change("aws_iam_user_policy_attachment.deployer", `"user": "deployer", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"`)},
		wantStrict: []string{"ReadImages ecr:DescribeImages unverified policy_unknown"},
	}})
}

// A membership whose user the plan doesn't know may put the user in the
// group. The group policy's Allow counts as a grant the tool can't check,
// and its Deny doesn't count.
func TestUser_UndecidableMembership(t *testing.T) {
	unknownUser := `{"address": "aws_iam_user_group_membership.someone", "type": "aws_iam_user_group_membership", "name": "someone",
		"change": {"actions": ["create"], "after": {"groups": ["deployers"]}, "after_unknown": {"id": true, "user": true}}}`
	checkUserCases(t, []userCase{{
		name:       "a grant",
		changes:    []string{deployer, deployersGroup, deployersECR, unknownUser},
		wantStrict: []string{"ReadImages ecr:DescribeImages unverified condition"},
	}, {
		name: "a Deny",
		changes: []string{deployer, deployersGroup, unknownUser,
			change("aws_iam_user_policy.deployer", `"name": "ecr", "user": "deployer", "policy": "`+policyText("Allow", "ecr:*")+`"`),
			change("aws_iam_group_policy.deny", `"name": "deny", "group": "deployers", "policy": "`+policyText("Deny", "ecr:DescribeImages")+`"`)},
	}})

	planPath := writePlan(t, deployer, deployersGroup, deployersECR, unknownUser)
	got := userSources(t, "--plan-file", planPath, "--config", userConfig(t, `{"address": "aws_iam_user.deployer"}`))
	assertVerdicts(t, "sources", got, []string{"aws_iam_group_policy.deployers policy identity known group=aws_iam_group.deployers maybe"})
}

// A membership that puts the user in a group the plan doesn't create: the
// plan shows the membership and can't show the group's policies. The need
// is covered with a notice, and unverified with policy_unknown under
// --strict-resources.
func TestUser_GroupOutsideThePlan(t *testing.T) {
	inOps := change("aws_iam_user_group_membership.deployer", `"user": "deployer", "groups": ["deployers", "ops"]`)
	checkUserCases(t, []userCase{{
		name:       "a group outside the plan",
		changes:    []string{deployer, deployersGroup, inOps},
		wantStrict: []string{"ReadImages ecr:DescribeImages unverified policy_unknown"},
	}, {
		// A group policy of the plan for ops shows that the plan manages
		// the group's policies.
		name: "a group policy of the plan",
		changes: []string{deployer, deployersGroup, inOps,
			change("aws_iam_group_policy.ops", `"name": "ops-logs", "group": "ops", "policy": "`+policyText("Allow", "logs:PutLogEvents")+`"`)},
		want:       []string{"ReadImages ecr:DescribeImages"},
		wantStrict: []string{"ReadImages ecr:DescribeImages"},
	}, {
		name: "both exclusive resources of the group",
		changes: []string{deployer, deployersGroup, inOps,
			change("aws_iam_group_policies_exclusive.ops", `"group_name": "ops", "policy_names": []`),
			change("aws_iam_group_policy_attachments_exclusive.ops", `"group_name": "ops", "policy_arns": []`)},
		want:       []string{"ReadImages ecr:DescribeImages"},
		wantStrict: []string{"ReadImages ecr:DescribeImages"},
	}})

	planPath := writePlan(t, deployer, deployersGroup, inOps)
	config := userConfig(t, `{"address": "aws_iam_user.deployer"}`)
	assertVerdicts(t, "notices", userNotices(t, planPath, config), []string{
		`notice: aws_iam_user_group_membership.deployer: group ops isn't in the plan, so the plan doesn't show its policies; needs of "deployer" may be granted by them`,
	})
	assertVerdicts(t, "sources", userSources(t, "--plan-file", planPath, "--config", config),
		[]string{"aws_iam_user_group_membership.deployer groups identity unknown outside_plan group=ops yes"})
}

// Users' permissions boundaries: a boundary that doesn't allow the need
// makes it missing, and the finding names the boundary. A resource policy
// that grants the user's ARN isn't limited by the boundary: "resource-based
// policies that grant permissions to an IAM user ARN (that is not a
// federated user session) are not limited by an implicit deny in an
// identity-based policy or permissions boundary".
func TestUser_Boundary(t *testing.T) {
	logsOnly := change("aws_iam_policy.logs_only", `"name": "logs-only", "arn": "arn:aws:iam::123456789012:policy/logs-only", "policy": "`+policyText("Allow", "logs:*")+`"`)
	bounded := userChange(`, "permissions_boundary": "arn:aws:iam::123456789012:policy/logs-only"`)
	userPolicy := change("aws_iam_user_policy.deployer", `"name": "ecr", "user": "deployer", "policy": "`+policyText("Allow", "ecr:DescribeImages")+`"`)
	repo := change("aws_ecr_repository.app", `"name": "app"`)
	repoPolicy := func(principal string) string {
		return change("aws_ecr_repository_policy.app", `"repository": "app", "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"`+principal+`\"},\"Action\":\"ecr:DescribeImages\",\"Resource\":\"*\"}]}"`)
	}
	limited := []string{"ReadImages ecr:DescribeImages boundary aws_iam_policy.logs_only"}
	checkUserCases(t, []userCase{{
		name:       "a boundary that doesn't allow",
		changes:    []string{logsOnly, bounded, userPolicy},
		want:       limited,
		wantStrict: limited,
	}, {
		name:    "a repository policy that grants the user's ARN",
		changes: []string{logsOnly, bounded, repo, repoPolicy(deployerARN)},
	}, {
		// A grant to the account goes through the identity policies, which
		// the boundary limits.
		name:       "a repository policy that grants the account",
		changes:    []string{logsOnly, bounded, userPolicy, repo, repoPolicy("arn:aws:iam::123456789012:root")},
		want:       limited,
		wantStrict: limited,
	}})
}

// A user's needs on a resource in another account need an Allow on both
// sides, as a role's do.
func TestUser_CrossAccount(t *testing.T) {
	secret := "arn:aws:secretsmanager:us-east-1:444455556666:secret:app-db-AbCdEf"
	config := writeConfig(t, t.TempDir(), `{
		"principals": {"deployer": {"address": "aws_iam_user.deployer"}},
		"needs": [{"sid": "FetchSecrets", "principal": "deployer", "actions": ["secretsmanager:GetSecretValue"], "resources": ["`+secret+`"]}]
	}`)
	userPolicy := change("aws_iam_user_policy.deployer", `"name": "secrets", "user": "deployer", "policy": "`+policyText("Allow", "secretsmanager:GetSecretValue")+`"`)
	secretPolicy := change("aws_secretsmanager_secret_policy.app", `"secret_arn": "`+secret+`", "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"`+deployerARN+`\"},\"Action\":\"secretsmanager:GetSecretValue\",\"Resource\":\"*\"}]}"`)
	missing := []string{"FetchSecrets secretsmanager:GetSecretValue"}
	checkUserCases(t, []userCase{{
		name:       "an identity grant and no resource policy in the plan",
		changes:    []string{deployer, userPolicy},
		config:     config,
		wantStrict: []string{"FetchSecrets secretsmanager:GetSecretValue unverified cross_account"},
	}, {
		name:    "both sides",
		changes: []string{deployer, userPolicy, secretPolicy},
		config:  config,
	}, {
		name:       "the resource side only",
		changes:    []string{deployer, secretPolicy},
		config:     config,
		want:       missing,
		wantStrict: missing,
	}})
}

// A KMS key policy must allow the user, or its account, as it must a role.
func TestUser_KMSKey(t *testing.T) {
	config := writeConfig(t, t.TempDir(), `{
		"principals": {"deployer": {"address": "aws_iam_user.deployer"}},
		"needs": [{"sid": "Decrypt", "principal": "deployer", "actions": ["kms:Decrypt"], "resources": ["`+kmsKey+`"]}]
	}`)
	key := `{"address": "aws_kms_key.data", "type": "aws_kms_key", "name": "data",
		"change": {"actions": ["no-op"], "before": {"arn": "` + kmsKey + `", "key_id": "1234abcd-12ab-34cd-56ef-1234567890ab"},
		"after": {"arn": "` + kmsKey + `", "key_id": "1234abcd-12ab-34cd-56ef-1234567890ab"}, "after_unknown": {}}}`
	keyPolicy := func(principal string) string {
		return change("aws_kms_key_policy.data", `"key_id": "1234abcd-12ab-34cd-56ef-1234567890ab", "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"`+principal+`\"},\"Action\":\"kms:Decrypt\",\"Resource\":\"*\"}]}"`)
	}
	userPolicy := change("aws_iam_user_policy.deployer", `"name": "kms", "user": "deployer", "policy": "`+policyText("Allow", "kms:Decrypt")+`"`)
	missing := []string{"Decrypt kms:Decrypt"}
	checkUserCases(t, []userCase{{
		name:    "a key policy that allows the user",
		changes: []string{deployer, key, keyPolicy(deployerARN)},
		config:  config,
	}, {
		name:       "a key policy that allows another user",
		changes:    []string{deployer, key, userPolicy, keyPolicy("arn:aws:iam::123456789012:user/other")},
		config:     config,
		want:       missing,
		wantStrict: missing,
	}, {
		name:    "a key policy that allows the account, and a user policy",
		changes: []string{deployer, key, userPolicy, keyPolicy("arn:aws:iam::123456789012:root")},
		config:  config,
	}})
}

// A user outside the plan, mapped by its ARN or by its name with type user.
// The plan attaches one inline policy to it. Other stacks may attach more
// policies to the user, or add it to groups, so a need that the plan
// doesn't grant is covered by default and unverified with policy_unknown
// under --strict-resources. The user's exclusive resources don't change
// that, since no resource lists every group of a user.
func TestUser_OutsideThePlan(t *testing.T) {
	ciPolicy := change("aws_iam_user_policy.ci", `"name": "logs", "user": "ci", "policy": "`+policyText("Allow", "logs:PutLogEvents")+`"`)
	exclusives := []string{ciPolicy,
		change("aws_iam_user_policies_exclusive.ci", `"user_name": "ci", "policy_names": ["logs"]`),
		change("aws_iam_user_policy_attachments_exclusive.ci", `"user_name": "ci", "policy_arns": []`)}
	unknown := []string{"ReadParams ssm:GetParameter unverified policy_unknown"}
	// The plan names the user by its name, in an account that it doesn't
	// show, so for an arn entry its inline policy may grant a need.
	byARN := []string{"ReadParams ssm:GetParameter unverified policy_unknown", "WriteLogs logs:PutLogEvents unverified condition"}
	for entry, want := range map[string][]string{
		`{"arn": "arn:aws:iam::123456789012:user/ci"}`: byARN,
		`{"name": "ci", "type": "user"}`:               unknown,
	} {
		cfg := outsideNeeds(t, entry)
		assertVerdicts(t, entry+" without exclusives", strictVerdicts(t, writePlan(t, ciPolicy), cfg), want)
		assertVerdicts(t, entry+" with exclusives", strictVerdicts(t, writePlan(t, exclusives...), cfg), want)
	}

	cfg := outsideNeeds(t, `{"name": "ci", "type": "user"}`)
	assertVerdicts(t, "notices", userNotices(t, writePlan(t, ciPolicy), cfg), []string{
		`notice: user ci is outside the plan, and other stacks may attach inline and managed policies to it or add it to groups; needs of "ops" may be granted by them; an aws_iam_user_policies_exclusive and an aws_iam_user_policy_attachments_exclusive for the user make the plan list every policy of that kind`,
	})
	assertVerdicts(t, "notices with exclusives", userNotices(t, writePlan(t, exclusives...), cfg), []string{
		`notice: user ci is outside the plan, and other stacks may add it to groups; needs of "ops" may be granted by them`,
	})
	assertVerdicts(t, "sources", userSources(t, "--plan-file", writePlan(t, ciPolicy), "--config", cfg), []string{
		"aws_iam_user_policy.ci policy identity known yes",
		"identity unknown attached_outside_plan unlisted=inline,managed,groups yes",
	})
	arnCfg := outsideNeeds(t, `{"arn": "arn:aws:iam::123456789012:user/ci"}`)
	assertVerdicts(t, "arn entry notices with exclusives", userNotices(t, writePlan(t, exclusives...), arnCfg), []string{
		`notice: user arn:aws:iam::123456789012:user/ci is outside the plan, and other stacks may attach inline and managed policies to it or add it to groups; needs of "ops" may be granted by them; with a "name" entry instead of "arn", an aws_iam_user_policies_exclusive and an aws_iam_user_policy_attachments_exclusive for the user make the plan list every policy of that kind, since the plan doesn't show the account that a name resolves in`,
	})
	assertVerdicts(t, "arn entry sources", userSources(t, "--plan-file", writePlan(t, ciPolicy), "--config", arnCfg), []string{
		"aws_iam_user_policy.ci policy identity known maybe",
		"identity unknown attached_outside_plan unlisted=inline,managed,groups yes",
	})

	// A name entry without a type is a role, so the user's policy doesn't
	// attach to it, and the need it grants is unverified too.
	roleCfg := outsideNeeds(t, `{"name": "ci"}`)
	assertVerdicts(t, "a role named ci", strictVerdicts(t, writePlan(t, ciPolicy), roleCfg), []string{
		"ReadParams ssm:GetParameter unverified policy_unknown",
		"WriteLogs logs:PutLogEvents unverified policy_unknown",
	})
}

// A user outside the plan may get a group policy of the plan through a
// membership of the plan.
func TestUser_OutsideThePlanInAGroupOfThePlan(t *testing.T) {
	inGroup := change("aws_iam_user_group_membership.ci", `"user": "ci", "groups": ["deployers"]`)
	cfg := userConfig(t, `{"name": "ci", "type": "user"}`)
	planPath := writePlan(t, deployersGroup, deployersECR, inGroup)
	assertVerdicts(t, "default", userFindings(t, planPath, cfg, false), nil)
	assertVerdicts(t, "strict", userFindings(t, planPath, cfg, true), nil)
}

// A name or arn entry of a user that the plan contains must use its address.
func TestUser_UserInThePlan(t *testing.T) {
	for _, entry := range []string{`{"name": "deployer", "type": "user"}`, `{"arn": "` + deployerARN + `"}`} {
		_, _, err := runValidate(t, "--plan-file", writePlan(t, deployer), "--config", userConfig(t, entry))
		if err == nil || !strings.Contains(err.Error(), `the user of`) || !strings.Contains(err.Error(), `map it with "address": "aws_iam_user.deployer"`) {
			t.Errorf("%s: error = %v, want one that gives the address", entry, err)
		}
	}
}

// The config errors of a user entry.
func TestUser_ConfigErrors(t *testing.T) {
	for entry, want := range map[string]string{
		`{"name": "ci", "type": "group"}`:                                `type "group" must be "role" or "user"`,
		`{"address": "aws_iam_user.ci", "type": "role"}`:                 `gives an IAM user, and type is "role"`,
		`{"arn": "arn:aws:iam::123456789012:role/ci", "type": "user"}`:   `gives an IAM role, and type is "user"`,
		`{"address": "aws_iam_group.deployers"}`:                         "has the type aws_iam_group",
		`{"arn": "arn:aws:iam::123456789012:group/deployers"}`:           "is not the ARN of an IAM role or user",
		`{"arn": "arn:aws:iam::123456789012:user/"}`:                     "is not the ARN of an IAM role or user",
		`{"name": "ci", "address": "aws_iam_user.ci", "type": "user"}`:   "set only one of address, name and arn",
		`{"arn": "arn:aws:iam::123456789012:user/ci-*", "type": "user"}`: "has a wildcard",
		`{"name": "arn:aws:iam::123456789012:user/ci", "type": "user"}`:  "set it as arn",
		`{"type": "user"}`: "address is required",
	} {
		_, _, err := runValidate(t, "--plan-file", writePlan(t, deployer), "--config", userConfig(t, entry))
		if exitCode(err) != 2 || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want a usage error with %q, got %v", entry, want, err)
		}
	}
}
