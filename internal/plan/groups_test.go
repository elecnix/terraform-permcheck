package plan

import (
	"strings"
	"testing"
)

// TestPolicySources_UserAndGroupTypes checks that each identity source type
// of a user or a group gives a source with its text, its path, its kind and
// its link.
func TestPolicySources_UserAndGroupTypes(t *testing.T) {
	policy := `{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"ecr:DescribeImages\",\"Resource\":\"*\"}]}`
	cases := []struct {
		typ      string
		after    string
		path     string
		kind     PolicyKind
		linkType string
		name     string
	}{
		{"aws_iam_user_policy", `"name": "ecr", "user": "ci", "policy": "` + policy + `"`, "policy", KindIdentity, "aws_iam_user", "ecr"},
		{"aws_iam_user_policy_attachment", `"user": "ci", "policy_arn": "arn:aws:iam::123456789012:policy/x"`, "policy_arn", KindIdentity, "aws_iam_user", ""},
		{"aws_iam_user_policy_attachments_exclusive", `"user_name": "ci", "policy_arns": ["arn:aws:iam::123456789012:policy/x"]`, "policy_arns.0", KindIdentity, "aws_iam_user", ""},
		{"aws_iam_group_policy", `"name": "ecr", "group": "ops", "policy": "` + policy + `"`, "policy", KindIdentity, "aws_iam_group", "ecr"},
		{"aws_iam_group_policy_attachment", `"group": "ops", "policy_arn": "arn:aws:iam::123456789012:policy/x"`, "policy_arn", KindIdentity, "aws_iam_group", ""},
		{"aws_iam_group_policy_attachments_exclusive", `"group_name": "ops", "policy_arns": ["arn:aws:iam::123456789012:policy/x"]`, "policy_arns.0", KindIdentity, "aws_iam_group", ""},
		{"aws_iam_user", `"name": "ci", "permissions_boundary": "arn:aws:iam::123456789012:policy/x"`, "permissions_boundary", KindBoundary, "aws_iam_user", ""},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			changes := parseRaw(t, `{"resource_changes": [
				{"address": "aws_iam_policy.x", "type": "aws_iam_policy", "name": "x",
				 "change": {"actions": ["create"], "after": {"arn": "arn:aws:iam::123456789012:policy/x", "policy": "`+policy+`"}, "after_unknown": {}}},
				{"address": "`+c.typ+`.x", "type": "`+c.typ+`", "name": "x",
				 "change": {"actions": ["create"], "after": {`+c.after+`}, "after_unknown": {}}}]}`)
			sources := PolicySources(changes, nil)
			if len(sources) != 1 {
				t.Fatalf("got %d sources, want 1: %+v", len(sources), sources)
			}
			s := sources[0]
			if s.Unknown || s.Unread || s.Text == "" {
				t.Errorf("unknown = %v, unread = %v, text = %q, want a source with the text", s.Unknown, s.Unread, s.Text)
			}
			if s.Path != c.path || s.Kind != c.kind || s.Link.Type != c.linkType || s.PolicyName != c.name {
				t.Errorf("path %q, kind %q, link type %q, policy name %q; want %q, %q, %q, %q",
					s.Path, s.Kind, s.Link.Type, s.PolicyName, c.path, c.kind, c.linkType, c.name)
			}
		})
	}
}

// TestPolicySources_NoUnreadType checks that this version reads every
// source type of the design: no spec has the unread marker.
func TestPolicySources_NoUnreadType(t *testing.T) {
	for typ, specs := range sourceSpecs {
		for _, spec := range specs {
			if spec.unread {
				t.Errorf("%s: a spec is unread", typ)
			}
		}
	}
}

// TestExclusives_UsersAndGroups checks the exclusive resources of a user
// and of a group: their kind, their link, and the type of the inline
// policies they name.
func TestExclusives_UsersAndGroups(t *testing.T) {
	changes := parseRaw(t, `{"resource_changes": [
		{"address": "aws_iam_user_policies_exclusive.a", "type": "aws_iam_user_policies_exclusive", "name": "a",
		 "change": {"actions": ["create"], "after": {"user_name": "ci", "policy_names": ["logs"]}, "after_unknown": {}}},
		{"address": "aws_iam_user_policy_attachments_exclusive.b", "type": "aws_iam_user_policy_attachments_exclusive", "name": "b",
		 "change": {"actions": ["create"], "after": {"user_name": "ci", "policy_arns": []}, "after_unknown": {}}},
		{"address": "aws_iam_group_policies_exclusive.c", "type": "aws_iam_group_policies_exclusive", "name": "c",
		 "change": {"actions": ["create"], "after": {"group_name": "ops", "policy_names": []}, "after_unknown": {}}},
		{"address": "aws_iam_group_policy_attachments_exclusive.d", "type": "aws_iam_group_policy_attachments_exclusive", "name": "d",
		 "change": {"actions": ["create"], "after": {"group_name": "ops"}, "after_unknown": {"policy_arns": true}}}
	]}`)
	var got []string
	for _, ex := range Exclusives(changes) {
		got = append(got, strings.Join([]string{ex.Address, string(ex.Kind), ex.Link.Type, ex.Link.Attribute, ex.Link.Value, ex.InlineType, strings.Join(ex.Entries, ",")}, " "))
	}
	want := []string{
		"aws_iam_user_policies_exclusive.a inline aws_iam_user user_name ci aws_iam_user_policy logs",
		"aws_iam_user_policy_attachments_exclusive.b managed aws_iam_user user_name ci aws_iam_user_policy ",
		"aws_iam_group_policies_exclusive.c inline aws_iam_group group_name ops aws_iam_group_policy ",
		"aws_iam_group_policy_attachments_exclusive.d managed aws_iam_group group_name ops aws_iam_group_policy ",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("exclusives =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// groupsPlan is a plan with a user, a group, both membership resources and
// group policies. The configuration links the resources by reference.
const groupsPlan = `{
	"resource_changes": [
		{"address": "aws_iam_user.ci", "type": "aws_iam_user", "name": "ci",
		 "change": {"actions": ["create"], "after": {"name": "ci"}, "after_unknown": {"arn": true}}},
		{"address": "aws_iam_user.other", "type": "aws_iam_user", "name": "other",
		 "change": {"actions": ["create"], "after": {"name": "other"}, "after_unknown": {"arn": true}}},
		{"address": "aws_iam_group.deployers", "type": "aws_iam_group", "name": "deployers",
		 "change": {"actions": ["create"], "after": {"name": "deployers"}, "after_unknown": {"arn": true}}},
		{"address": "aws_iam_group.readers", "type": "aws_iam_group", "name": "readers",
		 "change": {"actions": ["create"], "after": {"name": "readers"}, "after_unknown": {"arn": true}}},
		{"address": "aws_iam_user_group_membership.ci", "type": "aws_iam_user_group_membership", "name": "ci",
		 "change": {"actions": ["create"], "after": {"user": "ci", "groups": ["deployers", "ops"]}, "after_unknown": {"id": true}}},
		{"address": "aws_iam_group_membership.readers", "type": "aws_iam_group_membership", "name": "readers",
		 "change": {"actions": ["create"], "after": {"name": "readers", "group": "readers"}, "after_unknown": {"users": true}}},
		{"address": "aws_iam_group_policy.deployers", "type": "aws_iam_group_policy", "name": "deployers",
		 "change": {"actions": ["create"], "after": {"name": "d", "group": "deployers", "policy": "{}"}, "after_unknown": {}}},
		{"address": "aws_iam_group_policy.readers", "type": "aws_iam_group_policy", "name": "readers",
		 "change": {"actions": ["create"], "after": {"name": "r", "policy": "{}"}, "after_unknown": {"group": true}}}
	],
	"configuration": {"root_module": {"resources": [
		{"address": "aws_iam_user_group_membership.ci", "mode": "managed", "type": "aws_iam_user_group_membership", "name": "ci",
		 "expressions": {"user": {"references": ["aws_iam_user.ci.name", "aws_iam_user.ci"]},
			"groups": {"references": ["aws_iam_group.deployers.name", "aws_iam_group.deployers"]}}},
		{"address": "aws_iam_group_membership.readers", "mode": "managed", "type": "aws_iam_group_membership", "name": "readers",
		 "expressions": {"name": {}, "group": {"references": ["aws_iam_group.readers.name", "aws_iam_group.readers"]},
			"users": {"references": ["var.readers"]}}},
		{"address": "aws_iam_group_policy.deployers", "mode": "managed", "type": "aws_iam_group_policy", "name": "deployers",
		 "expressions": {"name": {}, "policy": {}, "group": {"references": ["aws_iam_group.deployers.name", "aws_iam_group.deployers"]}}},
		{"address": "aws_iam_group_policy.readers", "mode": "managed", "type": "aws_iam_group_policy", "name": "readers",
		 "expressions": {"name": {}, "policy": {}, "group": {"references": ["aws_iam_group.readers.name", "aws_iam_group.readers"]}}}
	]}}
}`

// TestGroups_Member checks the two hops from a group policy to a user: a
// membership that references the user and the group gives yes, a membership
// whose users a variable sets gives maybe, and a user in no membership gives
// no.
func TestGroups_Member(t *testing.T) {
	changes := parseRaw(t, groupsPlan)
	sources := PolicySources(changes, nil)
	groups := ParseGroups(changes, sources, nil)
	if len(groups.Memberships) != 2 {
		t.Fatalf("memberships = %+v, want 2", groups.Memberships)
	}
	ci := changeAt(t, changes, "aws_iam_user.ci", "create")
	other := changeAt(t, changes, "aws_iam_user.other", "create")
	cases := []struct {
		source string
		user   *ResourceChange
		want   LinkMatch
		group  string
	}{
		{"aws_iam_group_policy.deployers", ci, LinkYes, "aws_iam_group.deployers"},
		{"aws_iam_group_policy.deployers", other, LinkNo, ""},
		{"aws_iam_group_policy.readers", ci, LinkMaybe, "aws_iam_group.readers"},
		{"aws_iam_group_policy.readers", other, LinkMaybe, "aws_iam_group.readers"},
	}
	for _, c := range cases {
		var link PolicyLink
		for _, s := range sources {
			if s.Address == c.source {
				link = s.Link
			}
		}
		got, group := groups.Member(link, func(l PolicyLink) LinkMatch { return l.Match(c.user) })
		if got != c.want || group != c.group {
			t.Errorf("%s to %s = %v through %q, want %v through %q", c.source, c.user.Address, got, group, c.want, c.group)
		}
	}
}

// TestGroups_Same checks whether two links point to the same group: a
// reference and a known name of one group, two names, and an unknown value.
func TestGroups_Same(t *testing.T) {
	changes := parseRaw(t, groupsPlan)
	groups := ParseGroups(changes, PolicySources(changes, nil), nil)
	byRef := PolicyLink{Type: groupType, References: []string{"aws_iam_group.deployers.name", "aws_iam_group.deployers"}}
	cases := []struct {
		name string
		a, b PolicyLink
		want LinkMatch
	}{
		{"a reference and the name", byRef, PolicyLink{Type: groupType, Value: "deployers"}, LinkYes},
		{"a reference and another name", byRef, PolicyLink{Type: groupType, Value: "readers"}, LinkNo},
		{"two names outside the plan", PolicyLink{Type: groupType, Value: "ops"}, PolicyLink{Type: groupType, Value: "Ops"}, LinkYes},
		{"two other names outside the plan", PolicyLink{Type: groupType, Value: "ops"}, PolicyLink{Type: groupType, Value: "admins"}, LinkNo},
		{"an unknown value", PolicyLink{Type: groupType}, PolicyLink{Type: groupType, Value: "ops"}, LinkMaybe},
	}
	for _, c := range cases {
		if got := groups.Same(c.a, c.b); got != c.want {
			t.Errorf("%s: Same = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestGroups_OutsideGroups checks the groups outside the plan that a
// membership puts a user in: a known name that no aws_iam_group of the plan
// has, unless a policy of the plan or both exclusive resources attach to
// it, and a group whose name the plan doesn't know.
func TestGroups_OutsideGroups(t *testing.T) {
	changes := parseRaw(t, groupsPlan)
	sources := PolicySources(changes, nil)
	ci := changeAt(t, changes, "aws_iam_user.ci", "create")
	user := func(l PolicyLink) LinkMatch { return l.Match(ci) }
	got := ParseGroups(changes, sources, nil).OutsideGroups(user, sources, nil)
	if len(got) != 1 || got[0].Name != "ops" || got[0].Match != LinkYes || got[0].Membership.Address != "aws_iam_user_group_membership.ci" {
		t.Errorf("outside groups = %+v, want ops through aws_iam_user_group_membership.ci", got)
	}

	exclusives := Exclusives(parseRaw(t, `{"resource_changes": [
		{"address": "aws_iam_group_policies_exclusive.ops", "type": "aws_iam_group_policies_exclusive", "name": "ops",
		 "change": {"actions": ["create"], "after": {"group_name": "ops", "policy_names": []}, "after_unknown": {}}},
		{"address": "aws_iam_group_policy_attachments_exclusive.ops", "type": "aws_iam_group_policy_attachments_exclusive", "name": "ops",
		 "change": {"actions": ["create"], "after": {"group_name": "ops", "policy_arns": []}, "after_unknown": {}}}]}`))
	if got := ParseGroups(changes, sources, exclusives).OutsideGroups(user, sources, exclusives); len(got) != 0 {
		t.Errorf("outside groups with both exclusives = %+v, want none", got)
	}
	if got := ParseGroups(changes, sources, exclusives[:1]).OutsideGroups(user, sources, exclusives[:1]); len(got) != 1 {
		t.Errorf("outside groups with one exclusive = %+v, want ops", got)
	}

	unknown := parseRaw(t, `{"resource_changes": [
		{"address": "aws_iam_user_group_membership.ci", "type": "aws_iam_user_group_membership", "name": "ci",
		 "change": {"actions": ["create"], "after": {"user": "ci"}, "after_unknown": {"groups": true}}}]}`)
	byName := func(l PolicyLink) LinkMatch { return l.MatchOutside(OutsidePrincipal{Type: userType, Name: "ci"}) }
	got = ParseGroups(unknown, nil, nil).OutsideGroups(byName, nil, nil)
	if len(got) != 1 || got[0].Name != "" || got[0].Match != LinkMaybe {
		t.Errorf("outside groups of an unknown list = %+v, want one group with no name", got)
	}
}

// TestMatchOutside_UsersAndGroups checks that a link to a user or a group
// matches a principal outside the plan of its own type only.
func TestMatchOutside_UsersAndGroups(t *testing.T) {
	ci := OutsidePrincipal{Type: userType, Name: "ci", ARN: "arn:aws:iam::123456789012:user/ci"}
	cases := []struct {
		name string
		link PolicyLink
		r    OutsidePrincipal
		want LinkMatch
	}{
		{"a user name", PolicyLink{Type: userType, Value: "ci"}, OutsidePrincipal{Type: userType, Name: "ci"}, LinkYes},
		{"a user name, account unknown", PolicyLink{Type: userType, Value: "ci"}, ci, LinkMaybe},
		{"a user arn", PolicyLink{Type: userType, Value: "arn:aws:iam::123456789012:user/ci"}, ci, LinkYes},
		{"a role link with the user's name", PolicyLink{Type: roleType, Value: "ci"}, ci, LinkNo},
		{"a reference to a user of the plan", PolicyLink{Type: userType, References: []string{"aws_iam_user.app.name", "aws_iam_user.app"}}, ci, LinkNo},
		{"a list of users", PolicyLink{Type: userType, Values: []string{"app", "ci"}}, ci, LinkMaybe},
		{"a group name", PolicyLink{Type: groupType, Value: "ops"}, OutsidePrincipal{Type: groupType, Name: "ops"}, LinkYes},
		{"a group with no known name", PolicyLink{Type: groupType, Value: "ops"}, OutsidePrincipal{Type: groupType}, LinkNo},
		{"an unknown group", PolicyLink{Type: groupType}, OutsidePrincipal{Type: groupType}, LinkMaybe},
	}
	for _, c := range cases {
		if got := c.link.MatchOutside(c.r); got != c.want {
			t.Errorf("%s: MatchOutside = %v, want %v", c.name, got, c.want)
		}
	}
}
