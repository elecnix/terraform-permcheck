package plan

import (
	"strings"
	"testing"
)

// TestMatchOutside checks how a link matches a role that the plan doesn't
// contain: a known name decides, a reference to a role of the plan names
// another role, and an unknown value may name the role.
func TestMatchOutside(t *testing.T) {
	byName := OutsidePrincipal{Type: roleType, Name: "ops-admin"}
	byARN := OutsidePrincipal{Type: roleType, Name: "ops-admin", ARN: "arn:aws:iam::123456789012:role/ops-admin"}
	cases := []struct {
		name string
		link PolicyLink
		role OutsidePrincipal
		want LinkMatch
	}{
		{"the same name", PolicyLink{Type: "aws_iam_role", Value: "ops-admin"}, byName, LinkYes},
		{"the same name in another case", PolicyLink{Type: "aws_iam_role", Value: "Ops-Admin"}, byName, LinkYes},
		{"another name", PolicyLink{Type: "aws_iam_role", Value: "app-task"}, byName, LinkNo},
		{"the name of an arn entry, account unknown", PolicyLink{Type: "aws_iam_role", Value: "ops-admin"}, byARN, LinkMaybe},
		{"the name of an arn entry in another case", PolicyLink{Type: "aws_iam_role", Value: "Ops-Admin"}, byARN, LinkMaybe},
		{"another name than an arn entry's", PolicyLink{Type: "aws_iam_role", Value: "app-task"}, byARN, LinkNo},
		{"an unknown value", PolicyLink{Type: "aws_iam_role"}, byName, LinkMaybe},
		{"a reference to a role of the plan", PolicyLink{Type: "aws_iam_role", References: []string{"aws_iam_role.task.name", "aws_iam_role.task"}}, byName, LinkNo},
		{"a reference to a variable", PolicyLink{Type: "aws_iam_role", References: []string{"var.role"}}, byName, LinkMaybe},
		{"a variable with the same known value", PolicyLink{Type: "aws_iam_role", References: []string{"var.role"}, Value: "ops-admin"}, byName, LinkYes},
		{"a role or a variable", PolicyLink{Type: "aws_iam_role", References: []string{"aws_iam_role.task.name", "aws_iam_role.task", "var.role"}}, byName, LinkMaybe},
		{"the same arn", PolicyLink{Type: "aws_iam_role", Value: "arn:aws:iam::123456789012:role/ops-admin"}, byARN, LinkYes},
		{"another account", PolicyLink{Type: "aws_iam_role", Value: "arn:aws:iam::210987654321:role/ops-admin"}, byARN, LinkNo},
		{"an arn with the name, account unknown", PolicyLink{Type: "aws_iam_role", Value: "arn:aws:iam::210987654321:role/ops-admin"}, byName, LinkMaybe},
		{"an arn with another name", PolicyLink{Type: "aws_iam_role", Value: "arn:aws:iam::123456789012:role/app-task"}, byName, LinkNo},
		{"a list with the name", PolicyLink{Type: "aws_iam_role", Values: []string{"app-task", "ops-admin"}}, byName, LinkYes},
		{"a list without the name", PolicyLink{Type: "aws_iam_role", Values: []string{"app-task"}}, byName, LinkNo},
		{"the inline policy of a role of the plan", PolicyLink{Type: "aws_iam_role", Self: "aws_iam_role.task"}, byName, LinkNo},
		{"a user link", PolicyLink{Type: "aws_iam_user", Value: "ops-admin"}, byName, LinkNo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.link.MatchOutside(c.role); got != c.want {
				t.Errorf("MatchOutside = %v, want %v", got, c.want)
			}
		})
	}
}

// TestExclusives checks the two exclusive resources: a known list, a list
// with an entry that terraform computes at apply time, a list that terraform
// computes whole, and a delete, which adds none.
func TestExclusives(t *testing.T) {
	changes := parseRaw(t, `{"resource_changes": [
		{"address": "aws_iam_role_policies_exclusive.a", "type": "aws_iam_role_policies_exclusive", "name": "a",
		 "change": {"actions": ["create"], "after": {"role_name": "ops-admin", "policy_names": ["ops-logs", null]},
		  "after_unknown": {"policy_names": [false, true]}}},
		{"address": "aws_iam_role_policy_attachments_exclusive.b", "type": "aws_iam_role_policy_attachments_exclusive", "name": "b",
		 "change": {"actions": ["create"], "after": {"role_name": "ops-admin"}, "after_unknown": {"policy_arns": true}}},
		{"address": "aws_iam_role_policy_attachments_exclusive.c", "type": "aws_iam_role_policy_attachments_exclusive", "name": "c",
		 "change": {"actions": ["delete"], "before": {"role_name": "ops-admin", "policy_arns": []}, "after": null}}
	]}`)
	got := Exclusives(changes)
	if len(got) != 2 {
		t.Fatalf("exclusives = %+v, want 2", got)
	}
	a, b := got[0], got[1]
	if a.Kind != ExclusiveInline || a.Attribute != "policy_names" || a.Computed || strings.Join(a.Entries, ",") != "ops-logs," {
		t.Errorf("inline exclusive = %+v", a)
	}
	if a.Link.MatchOutside(OutsidePrincipal{Type: roleType, Name: "ops-admin"}) != LinkYes {
		t.Errorf("inline exclusive link = %+v, want role_name ops-admin", a.Link)
	}
	if b.Kind != ExclusiveManaged || b.Attribute != "policy_arns" || !b.Computed || b.Entries != nil {
		t.Errorf("managed exclusive = %+v, want a computed list", b)
	}
}

// TestPolicySources_ExclusiveAttachments checks that the policy_arns of an
// aws_iam_role_policy_attachments_exclusive attach managed policies, as the
// managed_policy_arns of a role do: an ARN of an aws_iam_policy of the plan
// reads its text, an AWS managed policy is outside the plan, and an empty
// list attaches none.
func TestPolicySources_ExclusiveAttachments(t *testing.T) {
	changes := parseRaw(t, `{"resource_changes": [
		`+managedPolicyChange("aws_iam_policy.ops", `"arn": "arn:aws:iam::123456789012:policy/ops", "policy": "`+allowECR+`"`, ``)+`,
		{"address": "aws_iam_role_policy_attachments_exclusive.a", "type": "aws_iam_role_policy_attachments_exclusive", "name": "a",
		 "change": {"actions": ["create"], "after": {"role_name": "ops-admin",
		  "policy_arns": ["arn:aws:iam::123456789012:policy/ops", "arn:aws:iam::aws:policy/ReadOnlyAccess"]}, "after_unknown": {}}},
		{"address": "aws_iam_role_policy_attachments_exclusive.none", "type": "aws_iam_role_policy_attachments_exclusive", "name": "none",
		 "change": {"actions": ["create"], "after": {"role_name": "ops-admin", "policy_arns": []}, "after_unknown": {}}}
	]}`)
	var got []string
	for _, s := range PolicySources(changes, nil) {
		got = append(got, strings.Join([]string{s.Address, s.Path, s.Policy, s.PolicyARN, boolWord(s.Unknown, "unknown"), boolWord(s.OutsidePlan, "outside"), boolWord(s.Managed, "managed")}, " "))
	}
	want := []string{
		"aws_iam_role_policy_attachments_exclusive.a policy_arns.0 aws_iam_policy.ops arn:aws:iam::123456789012:policy/ops   managed",
		"aws_iam_role_policy_attachments_exclusive.a policy_arns.1  arn:aws:iam::aws:policy/ReadOnlyAccess unknown outside managed",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPolicySources_InlinePolicyName checks the policy name of the inline
// sources: the name of an aws_iam_role_policy and the name of an
// inline_policy block.
func TestPolicySources_InlinePolicyName(t *testing.T) {
	changes := parseRaw(t, `{"resource_changes": [
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
		 "change": {"actions": ["create"], "after": {"name": "app-task", "inline_policy": [{"name": "block-policy", "policy": "{}"}]}, "after_unknown": {}}},
		{"address": "aws_iam_role_policy.p", "type": "aws_iam_role_policy", "name": "p",
		 "change": {"actions": ["create"], "after": {"role": "app-task", "name": "role-policy", "policy": "{}"}, "after_unknown": {}}}
	]}`)
	var got []string
	for _, s := range PolicySources(changes, nil) {
		got = append(got, s.Address+" "+s.PolicyName+" "+boolWord(s.Managed, "managed"))
	}
	want := "aws_iam_role.task block-policy ; aws_iam_role_policy.p role-policy "
	if strings.Join(got, "; ") != want {
		t.Errorf("sources = %q, want %q", strings.Join(got, "; "), want)
	}
}

// TestExclusive_ListsInline checks which inline sources an
// aws_iam_role_policies_exclusive list provably names: by known name, and
// by a reference to the source's resource.
func TestExclusive_ListsInline(t *testing.T) {
	ex := Exclusive{Kind: ExclusiveInline, Entries: []string{"ops-logs", ""}, References: []string{"aws_iam_role_policy.extra[0].name", "aws_iam_role_policy.extra[0]"}}
	cases := []struct {
		source PolicySource
		want   bool
	}{
		{PolicySource{Address: "aws_iam_role_policy.logs", PolicyName: "ops-logs"}, true},
		{PolicySource{Address: "aws_iam_role_policy.extra[0]"}, true},
		{PolicySource{Address: "aws_iam_role_policy.extra[1]"}, false},
		{PolicySource{Address: "aws_iam_role_policy.other", PolicyName: "other"}, false},
		{PolicySource{Address: "aws_iam_role_policy.unnamed"}, false},
	}
	for _, c := range cases {
		if got := ex.ListsInline(c.source); got != c.want {
			t.Errorf("ListsInline(%s) = %v, want %v", c.source.Address, got, c.want)
		}
	}
	if !ex.EntriesFromPlan("aws_iam_role_policy") {
		t.Error("EntriesFromPlan = false for a list that references aws_iam_role_policy only")
	}
	ex.References = append(ex.References, "var.extra_names")
	if ex.EntriesFromPlan("aws_iam_role_policy") {
		t.Error("EntriesFromPlan = true for a list that references a variable")
	}
}

// boolWord returns word when b is true, and "" otherwise.
func boolWord(b bool, word string) string {
	if b {
		return word
	}
	return ""
}
