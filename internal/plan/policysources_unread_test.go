package plan

import (
	"testing"
)

// TestPolicySources_UnreadTypes checks that a resource of each type the
// design lists, but this version doesn't read, gives a source with unknown
// text, its kind, its service and its link.
func TestPolicySources_UnreadTypes(t *testing.T) {
	cases := []struct {
		typ      string
		after    string
		path     string
		kind     PolicyKind
		service  string
		linkType string
	}{
		{"aws_iam_user_policy", `"user": "ci", "policy": "{}"`, "policy", KindIdentity, "", "aws_iam_user"},
		{"aws_iam_user_policy_attachment", `"user": "ci", "policy_arn": "arn:aws:iam::123456789012:policy/x"`, "policy_arn", KindIdentity, "", "aws_iam_user"},
		{"aws_iam_group_policy", `"group": "ops", "policy": "{}"`, "policy", KindIdentity, "", "aws_iam_group"},
		{"aws_iam_group_policy_attachment", `"group": "ops", "policy_arn": "arn:aws:iam::123456789012:policy/x"`, "policy_arn", KindIdentity, "", "aws_iam_group"},
		{"aws_iam_user", `"name": "ci", "permissions_boundary": "arn:aws:iam::123456789012:policy/b"`, "permissions_boundary", KindBoundary, "", "aws_iam_user"},
		{"aws_secretsmanager_secret_policy", `"secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-AbCdEf", "policy": "{}"`, "policy", KindResource, "secretsmanager", "aws_secretsmanager_secret"},
		{"aws_secretsmanager_secret", `"name": "app-db", "policy": "{}"`, "policy", KindResource, "secretsmanager", "aws_secretsmanager_secret"},
		{"aws_s3_bucket_policy", `"bucket": "app-data", "policy": "{}"`, "policy", KindResource, "s3", "aws_s3_bucket"},
		{"aws_sqs_queue_policy", `"queue_url": "https://sqs.us-east-1.amazonaws.com/123456789012/app-jobs", "policy": "{}"`, "policy", KindResource, "sqs", "aws_sqs_queue"},
		{"aws_sqs_queue", `"name": "app-jobs", "policy": "{}"`, "policy", KindResource, "sqs", "aws_sqs_queue"},
		{"aws_sns_topic_policy", `"arn": "arn:aws:sns:us-east-1:123456789012:app-events", "policy": "{}"`, "policy", KindResource, "sns", "aws_sns_topic"},
		{"aws_sns_topic", `"name": "app-events", "policy": "{}"`, "policy", KindResource, "sns", "aws_sns_topic"},
		{"aws_ecr_repository_policy", `"repository": "app", "policy": "{}"`, "policy", KindResource, "ecr", "aws_ecr_repository"},
		{"aws_kms_key", `"policy": "{}"`, "policy", KindResource, "kms", "aws_kms_key"},
		{"aws_kms_key_policy", `"key_id": "1234abcd-12ab-34cd-56ef-1234567890ab", "policy": "{}"`, "policy", KindResource, "kms", "aws_kms_key"},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			changes := parseRaw(t, `{"resource_changes": [
				{"address": "`+c.typ+`.x", "type": "`+c.typ+`", "name": "x",
				 "change": {"actions": ["create"], "after": {`+c.after+`}, "after_unknown": {}}}]}`)
			sources := PolicySources(changes, nil)
			if len(sources) != 1 {
				t.Fatalf("got %d sources, want 1: %+v", len(sources), sources)
			}
			s := sources[0]
			if !s.Unknown || !s.Unread || s.Text != "" {
				t.Errorf("unknown = %v, unread = %v, text = %q, want an unread source with no text", s.Unknown, s.Unread, s.Text)
			}
			if s.Path != c.path || s.Kind != c.kind || s.Service != c.service || s.Link.Type != c.linkType {
				t.Errorf("path %q, kind %q, service %q, link type %q; want %q, %q, %q, %q",
					s.Path, s.Kind, s.Service, s.Link.Type, c.path, c.kind, c.service, c.linkType)
			}
		})
	}
}

// TestPolicySources_RoleAttributes checks the managed_policy_arns and
// permissions_boundary of a role. Each is a source only when the
// configuration writes it and the plan doesn't hold it as null or empty,
// since a role's computed managed_policy_arns lists what other resources
// attach. This version reads managed_policy_arns and not the boundary.
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
	if boundary.Address != "aws_iam_role.set" || boundary.Path != "permissions_boundary" || boundary.Kind != KindBoundary || !boundary.Unread {
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
