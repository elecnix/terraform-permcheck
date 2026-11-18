package plan

import (
	"fmt"
	"strings"
	"testing"
)

// TestPolicySources_RoleAttributes checks the managed_policy_arns and
// permissions_boundary of a role. Each is a source only when the
// configuration writes it and the plan doesn't hold it as null or empty,
// since a role's computed managed_policy_arns lists what other resources
// attach. A boundary that references a policy the plan doesn't contain has
// unknown text.
func TestPolicySources_RoleAttributes(t *testing.T) {
	changes := parseRaw(t, `{
		"resource_changes": [
			{"address": "aws_iam_role.set", "type": "aws_iam_role", "name": "set",
			 "change": {"actions": ["create"],
				"after": {"name": "app-set", "managed_policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]},
				"after_unknown": {"arn": true, "permissions_boundary": true}}},
			{"address": "aws_iam_role.computed", "type": "aws_iam_role", "name": "computed",
			 "change": {"actions": ["create"],
				"after": {"name": "app-computed", "permissions_boundary": null},
				"after_unknown": {"arn": true, "managed_policy_arns": true}}},
			{"address": "aws_iam_role.empty", "type": "aws_iam_role", "name": "empty",
			 "change": {"actions": ["create"],
				"after": {"name": "app-empty", "managed_policy_arns": [], "permissions_boundary": null},
				"after_unknown": {"arn": true}}}
		],
		"configuration": {"root_module": {"resources": [
			{"address": "aws_iam_role.set", "mode": "managed", "type": "aws_iam_role", "name": "set",
			 "expressions": {"name": {}, "managed_policy_arns": {}, "permissions_boundary": {"references": ["aws_iam_policy.b.arn", "aws_iam_policy.b"]}}},
			{"address": "aws_iam_role.computed", "mode": "managed", "type": "aws_iam_role", "name": "computed",
			 "expressions": {"name": {}}},
			{"address": "aws_iam_role.empty", "mode": "managed", "type": "aws_iam_role", "name": "empty",
			 "expressions": {"name": {}, "managed_policy_arns": {}, "permissions_boundary": {"references": ["var.boundary"]}}}
		]}}
	}`)
	sources := PolicySources(changes, nil)
	if len(sources) != 2 {
		t.Fatalf("got %d sources, want 2: %+v", len(sources), sources)
	}
	arns, boundary := sources[0], sources[1]
	if arns.Address != "aws_iam_role.set" || arns.Path != "managed_policy_arns.0" || arns.Kind != KindIdentity || arns.Unread || !arns.OutsidePlan {
		t.Errorf("managed_policy_arns source = %+v", arns)
	}
	if boundary.Address != "aws_iam_role.set" || boundary.Path != "permissions_boundary" || boundary.Kind != KindBoundary || boundary.Unread || !boundary.Unknown || boundary.OutsidePlan {
		t.Errorf("permissions_boundary source = %+v", boundary)
	}
	set := changeAt(t, changes, "aws_iam_role.set", "create")
	for _, s := range sources {
		if got := s.Link.Match(set); got != LinkYes {
			t.Errorf("%s: match = %v, want yes", s.Path, got)
		}
	}
}

// TestPolicySources_PolicyAttachmentLists checks aws_iam_policy_attachment,
// which links to each of its roles, users and groups. It gives a role source
// only when it names roles, and the known names decide the link.
func TestPolicySources_PolicyAttachmentLists(t *testing.T) {
	changes := parseRaw(t, `{
		"resource_changes": [
			`+role("aws_iam_role.task", "task", `"name": "app-task"`)+`,
			`+role("aws_iam_role.other", "other", `"name": "app-other"`)+`,
			`+role("aws_iam_role.prefixed", "prefixed", `"name_prefix": "app-"`)+`,
			{"address": "aws_iam_policy_attachment.roles", "type": "aws_iam_policy_attachment", "name": "roles",
			 "change": {"actions": ["create"],
				"after": {"name": "roles", "policy_arn": "arn:aws:iam::123456789012:policy/x", "roles": ["app-task", "app-extra"], "users": null},
				"after_unknown": {"id": true}}},
			{"address": "aws_iam_policy_attachment.users", "type": "aws_iam_policy_attachment", "name": "users",
			 "change": {"actions": ["create"],
				"after": {"name": "users", "policy_arn": "arn:aws:iam::123456789012:policy/x", "users": ["ci"]},
				"after_unknown": {"id": true}}}
		]
	}`)
	sources := PolicySources(changes, nil)
	var got []string
	for _, s := range sources {
		got = append(got, s.Address+" "+s.Link.Type)
	}
	want := []string{"aws_iam_policy_attachment.roles aws_iam_role", "aws_iam_policy_attachment.users aws_iam_user"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("sources = %q, want %q", got, want)
	}
	link := sources[0].Link
	for addr, want := range map[string]LinkMatch{
		"aws_iam_role.task":     LinkYes,
		"aws_iam_role.other":    LinkNo,
		"aws_iam_role.prefixed": LinkMaybe,
	} {
		if got := link.Match(changeAt(t, changes, addr, "create")); got != want {
			t.Errorf("match %s = %v, want %v", addr, got, want)
		}
	}
}

// TestPolicySources_UnconfiguredResourcePolicy checks that a resource policy
// attribute the configuration doesn't write gives no source, such as the
// policy AWS gives a new SNS topic.
func TestPolicySources_UnconfiguredResourcePolicy(t *testing.T) {
	changes := parseRaw(t, `{
		"resource_changes": [
			{"address": "aws_sns_topic.t", "type": "aws_sns_topic", "name": "t",
			 "change": {"actions": ["create"], "after": {"name": "app-events"}, "after_unknown": {"arn": true, "policy": true}}}
		],
		"configuration": {"root_module": {"resources": [
			{"address": "aws_sns_topic.t", "mode": "managed", "type": "aws_sns_topic", "name": "t",
			 "expressions": {"name": {"constant_value": "app-events"}}}
		]}}
	}`)
	if sources := PolicySources(changes, nil); len(sources) != 0 {
		t.Errorf("sources = %+v, want none", sources)
	}
}

func TestAddressType(t *testing.T) {
	cases := map[string]string{
		"aws_iam_role.task":                     "aws_iam_role",
		"aws_iam_role.task[0]":                  "aws_iam_role",
		`aws_iam_role.task["a.b"]`:              "aws_iam_role",
		"module.app.aws_iam_role.task":          "aws_iam_role",
		`module.app["eu"].aws_iam_role.task[0]`: "aws_iam_role",
		`module.a[0].module.b.aws_iam_user.ci`:  "aws_iam_user",
		"data.aws_iam_role.task":                "",
		"module.app":                            "",
		"aws_iam_role":                          "",
		"aws_iam_role.task.arn":                 "",
		`module.app["eu".aws_iam_role.task`:     "",
		"task":                                  "",
	}
	for addr, want := range cases {
		got, ok := AddressType(addr)
		if got != want || ok != (want != "") {
			t.Errorf("AddressType(%q) = %q, %v; want %q", addr, got, ok, want)
		}
	}
}

// TestPolicySources_RoleBoundary checks how the permissions_boundary of a role
// resolves to its policy text, as a managed policy attachment does: an
// aws_iam_policy of the plan by reference or by known ARN, a
// data "aws_iam_policy" block, or a managed policy outside the plan.
func TestPolicySources_RoleBoundary(t *testing.T) {
	boundaryText := `{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"logs:*\",\"Resource\":\"*\"}]}`
	changes := parseRaw(t, `{
		"resource_changes": [
			{"address": "aws_iam_policy.b", "type": "aws_iam_policy", "name": "b",
			 "change": {"actions": ["create"], "after": {"name": "app-boundary", "policy": "`+boundaryText+`"}, "after_unknown": {"arn": true}}},
			{"address": "aws_iam_role.ref", "type": "aws_iam_role", "name": "ref",
			 "change": {"actions": ["create"], "after": {"name": "app-ref"}, "after_unknown": {"arn": true, "permissions_boundary": true}}},
			{"address": "aws_iam_role.data", "type": "aws_iam_role", "name": "data",
			 "change": {"actions": ["create"], "after": {"name": "app-data", "permissions_boundary": "arn:aws:iam::aws:policy/ReadOnlyAccess"}, "after_unknown": {"arn": true}}},
			{"address": "aws_iam_role.aws", "type": "aws_iam_role", "name": "aws",
			 "change": {"actions": ["create"], "after": {"name": "app-aws", "permissions_boundary": "arn:aws:iam::aws:policy/PowerUserAccess"}, "after_unknown": {"arn": true}}}
		],
		"configuration": {"root_module": {"resources": [
			{"address": "aws_iam_role.ref", "mode": "managed", "type": "aws_iam_role", "name": "ref",
			 "expressions": {"name": {}, "permissions_boundary": {"references": ["aws_iam_policy.b.arn", "aws_iam_policy.b"]}}},
			{"address": "aws_iam_role.data", "mode": "managed", "type": "aws_iam_role", "name": "data",
			 "expressions": {"name": {}, "permissions_boundary": {}}},
			{"address": "aws_iam_role.aws", "mode": "managed", "type": "aws_iam_role", "name": "aws",
			 "expressions": {"name": {}, "permissions_boundary": {}}}
		]}}
	}`)
	data := []DataSource{{Address: "data.aws_iam_policy.read_only", Type: "aws_iam_policy",
		Values: map[string]string{"arn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "policy": "{}"}}}
	var got []string
	for _, s := range PolicySources(changes, data) {
		got = append(got, strings.Join([]string{s.Address, s.Path, string(s.Kind), s.Policy, s.PolicyARN,
			fmt.Sprintf("unknown=%v outside=%v unread=%v text=%v", s.Unknown, s.OutsidePlan, s.Unread, s.Text != "")}, " "))
	}
	want := []string{
		"aws_iam_role.ref permissions_boundary boundary aws_iam_policy.b  unknown=false outside=false unread=false text=true",
		"aws_iam_role.data permissions_boundary boundary data.aws_iam_policy.read_only arn:aws:iam::aws:policy/ReadOnlyAccess unknown=false outside=false unread=false text=true",
		"aws_iam_role.aws permissions_boundary boundary  arn:aws:iam::aws:policy/PowerUserAccess unknown=true outside=true unread=false text=false",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
