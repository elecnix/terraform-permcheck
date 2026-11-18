package plan

import (
	"os"
	"strings"
	"testing"
)

// TestParseDataSources reads the plan captured from terraform 1.15 in
// testdata/datasource_capture. A data source that terraform reads during the
// plan is in prior_state only, with its values, in the root module and in a
// child module. A data source whose read terraform defers to the apply is in
// resource_changes with the action read, and after holds its known
// arguments.
func TestParseDataSources(t *testing.T) {
	raw, err := os.ReadFile("testdata/datasource_capture/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := ParseDataSources(raw)
	if err != nil {
		t.Fatal(err)
	}
	byAddress := map[string]DataSource{}
	for _, d := range data {
		byAddress[d.Address] = d
	}
	if len(byAddress) != 4 {
		t.Fatalf("data sources = %+v, want 4", data)
	}
	content := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecr:DescribeImages","Resource":"*"}]}`

	known := byAddress["data.local_file.known"]
	if known.Deferred || known.Type != "local_file" || known.Name != "known" || known.ModuleAddress != "" || known.Values["content"] != content {
		t.Errorf("data.local_file.known = %+v", known)
	}
	inModule := byAddress["module.app.data.local_file.in_module"]
	if inModule.Deferred || inModule.ModuleAddress != "module.app" || inModule.Values["content"] != content {
		t.Errorf("module.app.data.local_file.in_module = %+v", inModule)
	}
	deferred := byAddress["data.local_file.deferred"]
	if !deferred.Deferred || len(deferred.Values) != 0 {
		t.Errorf("data.local_file.deferred = %+v, want a deferred read with no values", deferred)
	}
	depends := byAddress["data.local_file.depends"]
	if !depends.Deferred || depends.Values["filename"] != "./policy.json" || depends.Values["content"] != "" {
		t.Errorf("data.local_file.depends = %+v, want a deferred read with its known filename", depends)
	}
}

// allowECR is a policy text that allows ecr:DescribeImages, as it appears
// inside a JSON string of a plan.
const allowECR = `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"ecr:DescribeImages\",\"Resource\":\"*\"}]}`

// managedPolicyChange is a resource change entry of an aws_iam_policy with
// the given address, after and after_unknown values.
func managedPolicyChange(addr, after, unknown string) string {
	name := addr[strings.LastIndex(addr, ".")+1:]
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	return `{"address": "` + addr + `", "type": "aws_iam_policy", "name": "` + name + `",
		"change": {"actions": ["create"], "after": {` + after + `}, "after_unknown": {` + unknown + `}}}`
}

// attachmentPlan is a plan with the aws_iam_role_policy_attachment a, whose
// policy_arn has the given after value, configuration expression and
// after_unknown entry, and the given other entries.
func attachmentPlan(arnAfter, arnExpr, arnUnknown, others string) string {
	unknown := `"id": true`
	if arnUnknown != "" {
		unknown += ", " + arnUnknown
	}
	return `{
		"resource_changes": [` + others + `,
			{"address": "aws_iam_role_policy_attachment.a", "type": "aws_iam_role_policy_attachment", "name": "a",
			 "change": {"actions": ["create"], "after": {"role": "app-task"` + arnAfter + `}, "after_unknown": {` + unknown + `}}}
		],
		"configuration": {"root_module": {"resources": [
			{"address": "aws_iam_role_policy_attachment.a", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "a",
			 "expressions": {"role": {}, "policy_arn": ` + arnExpr + `}}
		]}}
	}`
}

// describe collapses a source to the fields that resolve its managed
// policy: "policy text|unknown [maybe] [outside]".
func describe(s PolicySource) string {
	out := s.Policy
	if out == "" {
		out = "-"
	}
	if s.Unknown {
		out += " unknown"
	} else {
		out += " text"
	}
	if s.PolicyMaybe {
		out += " maybe"
	}
	if s.OutsidePlan {
		out += " outside"
	}
	return out
}

// TestPolicySources_PolicyARN checks how the policy_arn of an attachment
// names a policy: by its references first, then by its known value against
// the known arn of an aws_iam_policy, then of a data "aws_iam_policy"
// source. A known ARN that may name a policy whose ARN is unknown may also
// name a policy outside the plan.
func TestPolicySources_PolicyARN(t *testing.T) {
	const (
		customerARN = `, "policy_arn": "arn:aws:iam::123456789012:policy/app-writes"`
		managedARN  = `, "policy_arn": "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"`
		constant    = `{}`
		computed    = `"policy_arn": true`
	)
	known := managedPolicyChange("aws_iam_policy.p", `"name": "app-writes", "policy": "`+allowECR+`"`, `"arn": true`)
	cases := []struct {
		name     string
		arnAfter string
		arnExpr  string
		unknown  string
		others   string
		data     []DataSource
		want     []string
	}{
		{
			name:    "a reference to a policy with known text",
			arnExpr: `{"references": ["aws_iam_policy.p.arn", "aws_iam_policy.p"]}`,
			unknown: computed,
			others:  known,
			want:    []string{"aws_iam_policy.p text"},
		},
		{
			name:    "a reference to a policy whose text is computed",
			arnExpr: `{"references": ["aws_iam_policy.p.arn", "aws_iam_policy.p"]}`,
			unknown: computed,
			others:  managedPolicyChange("aws_iam_policy.p", `"name": "app-writes"`, `"arn": true, "policy": true`),
			want:    []string{"aws_iam_policy.p unknown"},
		},
		{
			name:     "a known ARN equal to the known arn of a policy",
			arnAfter: customerARN,
			arnExpr:  `{"references": ["var.policy_arn"]}`,
			others:   managedPolicyChange("aws_iam_policy.p", `"arn": "arn:aws:iam::123456789012:policy/app-writes", "policy": "`+allowECR+`"`, ``),
			want:     []string{"aws_iam_policy.p text"},
		},
		{
			name:     "a known ARN that may name a policy with the same name and an unknown arn",
			arnAfter: customerARN,
			arnExpr:  constant,
			others:   known,
			want:     []string{"aws_iam_policy.p text maybe", "- unknown maybe outside"},
		},
		{
			name:     "a known ARN that may name a policy with an unknown name",
			arnAfter: customerARN,
			arnExpr:  constant,
			others:   managedPolicyChange("aws_iam_policy.p", `"name_prefix": "app-", "policy": "`+allowECR+`"`, `"arn": true, "name": true`),
			want:     []string{"aws_iam_policy.p text maybe", "- unknown maybe outside"},
		},
		{
			name:     "a known ARN that no policy of the plan may have",
			arnAfter: customerARN,
			arnExpr:  constant,
			others:   managedPolicyChange("aws_iam_policy.p", `"name": "app-reads", "policy": "`+allowECR+`"`, `"arn": true`),
			want:     []string{"- unknown outside"},
		},
		{
			name:     "an AWS managed policy",
			arnAfter: managedARN,
			arnExpr:  constant,
			others:   known,
			want:     []string{"- unknown outside"},
		},
		{
			name:     "an AWS managed policy that a data source reads",
			arnAfter: managedARN,
			arnExpr:  constant,
			others:   known,
			data: []DataSource{{Address: "data.aws_iam_policy.ecr", Type: "aws_iam_policy", Name: "ecr",
				Values: map[string]string{"arn": "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser", "policy": "{}"}}},
			want: []string{"data.aws_iam_policy.ecr text"},
		},
		{
			name:     "an AWS managed policy that a deferred data source reads",
			arnAfter: managedARN,
			arnExpr:  constant,
			others:   known,
			data: []DataSource{{Address: "data.aws_iam_policy.ecr", Type: "aws_iam_policy", Name: "ecr", Deferred: true,
				Values: map[string]string{"arn": "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"}}},
			want: []string{"data.aws_iam_policy.ecr unknown"},
		},
		{
			name:    "a computed ARN from a value that may name any policy",
			arnExpr: `{"references": ["module.shared.policy_arn", "module.shared"]}`,
			unknown: computed,
			others:  known,
			want:    []string{"- unknown"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			changes := parseRaw(t, attachmentPlan(c.arnAfter, c.arnExpr, c.unknown, c.others))
			var got []string
			for _, s := range PolicySources(changes, c.data) {
				if s.Address != "aws_iam_role_policy_attachment.a" || s.Path != "policy_arn" || s.Unread {
					t.Errorf("source = %+v, want a read source at policy_arn of the attachment", s)
				}
				if !s.Unknown && s.Text == "" {
					t.Errorf("source %s has no text", describe(s))
				}
				got = append(got, describe(s))
			}
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

// TestPolicySources_PolicyARNCount checks a reference to an aws_iam_policy
// with count. A keyed reference names its instance. A keyless one names
// each instance, and the known ARN decides which, or the plan can't decide.
func TestPolicySources_PolicyARNCount(t *testing.T) {
	policies := managedPolicyChange("aws_iam_policy.p[0]", `"name": "app-a", "policy": "`+allowECR+`"`, `"arn": true`) + "," +
		managedPolicyChange("aws_iam_policy.p[1]", `"name": "app-b", "policy": "`+allowECR+`"`, `"arn": true`)
	cases := map[string]struct {
		expr string
		want []string
	}{
		"keyed":   {`{"references": ["aws_iam_policy.p[1].arn", "aws_iam_policy.p[1]", "aws_iam_policy.p"]}`, []string{"aws_iam_policy.p[1] text"}},
		"keyless": {`{"references": ["aws_iam_policy.p", "count.index"]}`, []string{"aws_iam_policy.p[0] text maybe", "aws_iam_policy.p[1] text maybe"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			changes := parseRaw(t, attachmentPlan("", c.expr, `"policy_arn": true`, policies))
			var got []string
			for _, s := range PolicySources(changes, nil) {
				got = append(got, describe(s))
			}
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}

// TestPolicySources_PolicyAttachmentRoles checks that an
// aws_iam_policy_attachment with roles reads the attached policy's text,
// links to each role, and reads it for its users too.
func TestPolicySources_PolicyAttachmentRoles(t *testing.T) {
	changes := parseRaw(t, `{
		"resource_changes": [
			`+role("aws_iam_role.task", "task", `"name": "app-task"`)+`,
			`+managedPolicyChange("aws_iam_policy.p", `"name": "app-reads", "policy": "`+allowECR+`"`, `"arn": true`)+`,
			{"address": "aws_iam_policy_attachment.shared", "type": "aws_iam_policy_attachment", "name": "shared",
			 "change": {"actions": ["create"],
				"after": {"name": "shared", "roles": ["app-other", "app-task"], "users": ["ci"]},
				"after_unknown": {"id": true, "policy_arn": true}}}
		],
		"configuration": {"root_module": {"resources": [
			{"address": "aws_iam_policy_attachment.shared", "mode": "managed", "type": "aws_iam_policy_attachment", "name": "shared",
			 "expressions": {"name": {}, "roles": {}, "users": {},
				"policy_arn": {"references": ["aws_iam_policy.p.arn", "aws_iam_policy.p"]}}}
		]}}
	}`)
	sources := PolicySources(changes, nil)
	if len(sources) != 2 {
		t.Fatalf("sources = %+v, want one for roles and one for users", sources)
	}
	roles, users := sources[0], sources[1]
	if roles.Link.Type != "aws_iam_role" || roles.Unread || roles.Unknown || roles.Policy != "aws_iam_policy.p" {
		t.Errorf("roles source = %+v, want the text of aws_iam_policy.p", roles)
	}
	if got := roles.Link.Match(changeAt(t, changes, "aws_iam_role.task", "create")); got != LinkYes {
		t.Errorf("roles link match = %v, want yes", got)
	}
	if users.Link.Type != "aws_iam_user" || users.Unread || users.Unknown || users.Policy != "aws_iam_policy.p" {
		t.Errorf("users source = %+v, want the text of aws_iam_policy.p", users)
	}
}

// TestPolicySources_ManagedPolicyARNs checks the managed_policy_arns of a
// role. A known ARN names its policy by value. A computed ARN names the
// referenced aws_iam_policy whose ARN is unknown. A list that terraform
// computes whole is one source with unknown text.
func TestPolicySources_ManagedPolicyARNs(t *testing.T) {
	policies := managedPolicyChange("aws_iam_policy.old", `"arn": "arn:aws:iam::123456789012:policy/app-old", "name": "app-old", "policy": "`+allowECR+`"`, ``) + "," +
		managedPolicyChange("aws_iam_policy.new", `"name": "app-new", "policy": "`+allowECR+`"`, `"arn": true`)
	plan := func(after, unknown string) string {
		return `{
			"resource_changes": [` + policies + `,
				{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
				 "change": {"actions": ["create"], "after": {"name": "app-task"` + after + `}, "after_unknown": {"arn": true` + unknown + `}}}
			],
			"configuration": {"root_module": {"resources": [
				{"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
				 "expressions": {"name": {}, "managed_policy_arns": {"references": [
					"aws_iam_policy.old.arn", "aws_iam_policy.old", "aws_iam_policy.new.arn", "aws_iam_policy.new"]}}}
			]}}
		}`
	}
	cases := map[string]struct {
		after, unknown string
		want           []string
	}{
		"known and computed ARNs": {
			after:   `, "managed_policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::123456789012:policy/app-old", null]`,
			unknown: `, "managed_policy_arns": [false, false, true]`,
			want: []string{
				"managed_policy_arns.0 - unknown outside",
				"managed_policy_arns.1 aws_iam_policy.old text",
				"managed_policy_arns aws_iam_policy.new text",
			},
		},
		"a list computed whole": {
			unknown: `, "managed_policy_arns": true`,
			want:    []string{"managed_policy_arns - unknown"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			changes := parseRaw(t, plan(c.after, c.unknown))
			role := changeAt(t, changes, "aws_iam_role.task", "create")
			var got []string
			for _, s := range PolicySources(changes, nil) {
				if s.Link.Match(role) != LinkYes || s.Kind != KindIdentity {
					t.Errorf("source %+v does not attach to the role", s)
				}
				got = append(got, s.Path+" "+describe(s))
			}
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
		})
	}
}
