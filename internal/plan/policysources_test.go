package plan

import (
	"os"
	"strings"
	"testing"
)

// parseFixture parses a plan fixture under testdata.
func parseFixture(t *testing.T, path string) []*ResourceChange {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := Parse(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

// changeAt returns the change at an address with the given action.
func changeAt(t *testing.T, changes []*ResourceChange, addr, action string) *ResourceChange {
	t.Helper()
	for _, rc := range changes {
		if rc.Address == addr && rc.Change == action {
			return rc
		}
	}
	t.Fatalf("no %s change at %s", action, addr)
	return nil
}

func TestPolicySources_RolePolicyKnownAndComputed(t *testing.T) {
	changes := parseFixture(t, "testdata/policysources/role_policy.json")
	role := changeAt(t, changes, "aws_iam_role.task", "create")

	sources := PolicySources(changes, nil)
	if len(sources) != 2 {
		t.Fatalf("got %d sources, want 2: %+v", len(sources), sources)
	}

	logs, secrets := sources[0], sources[1]
	if logs.Address != "aws_iam_role_policy.task_logs" || secrets.Address != "aws_iam_role_policy.task_secrets" {
		t.Fatalf("addresses = %q, %q", logs.Address, secrets.Address)
	}
	for _, s := range sources {
		if s.Kind != KindIdentity {
			t.Errorf("%s: kind = %q, want %q", s.Address, s.Kind, KindIdentity)
		}
		if got := s.Link.Match(role); got != LinkYes {
			t.Errorf("%s: link match = %v, want %v", s.Address, got, LinkYes)
		}
	}
	wantText := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:PutLogEvents","Resource":"*"}]}`
	if logs.Unknown || logs.Text != wantText {
		t.Errorf("task_logs text = %q, unknown = %v", logs.Text, logs.Unknown)
	}
	if !secrets.Unknown || secrets.Text != "" {
		t.Errorf("task_secrets text = %q, unknown = %v, want the unknown marker", secrets.Text, secrets.Unknown)
	}
}

// parseRaw parses an inline plan.
func parseRaw(t *testing.T, raw string) []*ResourceChange {
	t.Helper()
	changes, err := Parse([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

// sourcesAt returns the sources that a resource address sets.
func sourcesAt(sources []PolicySource, addr string) []PolicySource {
	var out []PolicySource
	for _, s := range sources {
		if s.Address == addr {
			out = append(out, s)
		}
	}
	return out
}

const allowLogs = `{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"logs:PutLogEvents\",\"Resource\":\"*\"}]}`
const allowLogsText = `{"Statement":[{"Effect":"Allow","Action":"logs:PutLogEvents","Resource":"*"}]}`

func TestPolicySources_RoleInlinePolicy(t *testing.T) {
	changes := parseRaw(t, `{
		"resource_changes": [
			{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
			 "change": {"actions": ["create"],
				"after": {"name": "app-task", "inline_policy": [
					{"name": "logs", "policy": "`+allowLogs+`"},
					{"name": "secrets", "policy": null}
				]},
				"after_unknown": {"arn": true, "inline_policy": [{}, {"policy": true}]}}},
			{"address": "aws_iam_role.other", "type": "aws_iam_role", "name": "other",
			 "change": {"actions": ["create"],
				"after": {"name": "app-other"},
				"after_unknown": {"arn": true, "inline_policy": true}}}
		],
		"configuration": {"root_module": {"resources": [
			{"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
			 "expressions": {"name": {"constant_value": "app-task"}, "inline_policy": [
				{"name": {"constant_value": "logs"}, "policy": {}},
				{"name": {"constant_value": "secrets"}, "policy": {"references": ["data.aws_iam_policy_document.s.json"]}}
			 ]}},
			{"address": "aws_iam_role.other", "mode": "managed", "type": "aws_iam_role", "name": "other",
			 "expressions": {"name": {"constant_value": "app-other"}}}
		]}}
	}`)
	task := changeAt(t, changes, "aws_iam_role.task", "create")
	other := changeAt(t, changes, "aws_iam_role.other", "create")

	sources := PolicySources(changes, nil)
	if len(sources) != 2 {
		t.Fatalf("got %d sources, want 2, since an inline_policy the configuration omits is no source: %+v", len(sources), sources)
	}
	logs, secrets := sources[0], sources[1]
	if logs.Address != "aws_iam_role.task" || logs.Path != "inline_policy.0.policy" || logs.Unknown || logs.Text != allowLogsText {
		t.Errorf("logs = %+v", logs)
	}
	if secrets.Address != "aws_iam_role.task" || secrets.Path != "inline_policy.1.policy" || !secrets.Unknown {
		t.Errorf("secrets = %+v, want the unknown marker", secrets)
	}
	for _, s := range sources {
		if s.Kind != KindIdentity {
			t.Errorf("%s: kind = %q", s.Path, s.Kind)
		}
		if got := s.Link.Match(task); got != LinkYes {
			t.Errorf("%s: match task = %v, want yes", s.Path, got)
		}
		if got := s.Link.Match(other); got != LinkNo {
			t.Errorf("%s: match other = %v, want no", s.Path, got)
		}
	}
}

func TestPolicySources_RoleInlinePolicyComputedWhole(t *testing.T) {
	// A configured inline_policy whose whole list is computed is one unknown
	// source.
	changes := parseRaw(t, `{
		"resource_changes": [
			{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
			 "change": {"actions": ["create"], "after": {"name": "app-task"},
				"after_unknown": {"inline_policy": true}}}
		],
		"configuration": {"root_module": {"resources": [
			{"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task",
			 "expressions": {"inline_policy": [{"policy": {"references": ["local.p"]}}]}}
		]}}
	}`)
	sources := PolicySources(changes, nil)
	if len(sources) != 1 || !sources[0].Unknown || sources[0].Path != "inline_policy" {
		t.Fatalf("sources = %+v, want one unknown inline_policy source", sources)
	}
}

// rolePolicyPlan is a plan with the given roles and one
// aws_iam_role_policy.p whose role attribute has the given after value and
// configuration expression.
func rolePolicyPlan(roles, roleAfter, roleExpr string) string {
	return `{
		"resource_changes": [` + roles + `,
			{"address": "aws_iam_role_policy.p", "type": "aws_iam_role_policy", "name": "p",
			 "change": {"actions": ["create"],
				"after": {"policy": "` + allowLogs + `"` + roleAfter + `},
				"after_unknown": {"id": true}}}
		],
		"configuration": {"root_module": {"resources": [
			{"address": "aws_iam_role_policy.p", "mode": "managed", "type": "aws_iam_role_policy", "name": "p",
			 "expressions": {"policy": {}, "role": ` + roleExpr + `}}
		]}}
	}`
}

// role is a resource change entry of an aws_iam_role.
func role(addr, name, after string) string {
	return `{"address": "` + addr + `", "type": "aws_iam_role", "name": "` + name + `",
		"change": {"actions": ["create"], "after": {` + after + `}, "after_unknown": {"arn": true}}}`
}

func TestPolicyLink_Match(t *testing.T) {
	cases := []struct {
		name      string
		roles     string
		roleAfter string
		roleExpr  string
		want      map[string]LinkMatch
	}{
		{
			name:     "a reference to the role decides even with an unknown name",
			roles:    role("aws_iam_role.task", "task", `"name_prefix": "app-"`) + "," + role("aws_iam_role.other", "other", `"name": "app-other"`),
			roleExpr: `{"references": ["aws_iam_role.task.id", "aws_iam_role.task"]}`,
			want:     map[string]LinkMatch{"aws_iam_role.task": LinkYes, "aws_iam_role.other": LinkNo},
		},
		{
			name:      "a known name matches the role with that name",
			roles:     role("aws_iam_role.task", "task", `"name": "app-task"`) + "," + role("aws_iam_role.other", "other", `"name": "app-other"`),
			roleAfter: `, "role": "app-task"`,
			roleExpr:  `{"constant_value": "app-task"}`,
			want:      map[string]LinkMatch{"aws_iam_role.task": LinkYes, "aws_iam_role.other": LinkNo},
		},
		{
			name:      "a known ARN matches the role with that arn",
			roles:     role("aws_iam_role.task", "task", `"name": "app-task", "arn": "arn:aws:iam::123456789012:role/app-task"`) + "," + role("aws_iam_role.other", "other", `"name": "app-other"`),
			roleAfter: `, "role": "arn:aws:iam::123456789012:role/app-task"`,
			roleExpr:  `{"constant_value": "arn:aws:iam::123456789012:role/app-task"}`,
			want:      map[string]LinkMatch{"aws_iam_role.task": LinkYes, "aws_iam_role.other": LinkMaybe},
		},
		{
			name:      "a known name against a role whose name is unknown is undecidable",
			roles:     role("aws_iam_role.task", "task", `"name_prefix": "app-"`),
			roleAfter: `, "role": "app-task"`,
			roleExpr:  `{"constant_value": "app-task"}`,
			want:      map[string]LinkMatch{"aws_iam_role.task": LinkMaybe},
		},
		{
			name:     "a variable with an unknown value is undecidable",
			roles:    role("aws_iam_role.task", "task", `"name": "app-task"`),
			roleExpr: `{"references": ["var.role_name"]}`,
			want:     map[string]LinkMatch{"aws_iam_role.task": LinkMaybe},
		},
		{
			name:     "an attribute of another resource type is undecidable",
			roles:    role("aws_iam_role.task", "task", `"name": "app-task"`),
			roleExpr: `{"references": ["aws_iam_instance_profile.ip.role", "aws_iam_instance_profile.ip"]}`,
			want:     map[string]LinkMatch{"aws_iam_role.task": LinkMaybe},
		},
		{
			name:     "a reference that also reads a variable is undecidable",
			roles:    role("aws_iam_role.task", "task", `"name_prefix": "app-"`),
			roleExpr: `{"references": ["var.use_task", "aws_iam_role.task.id", "aws_iam_role.task"]}`,
			want:     map[string]LinkMatch{"aws_iam_role.task": LinkMaybe},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changes := parseRaw(t, rolePolicyPlan(tc.roles, tc.roleAfter, tc.roleExpr))
			sources := PolicySources(changes, nil)
			if len(sources) != 1 {
				t.Fatalf("got %d sources, want 1", len(sources))
			}
			for addr, want := range tc.want {
				if got := sources[0].Link.Match(changeAt(t, changes, addr, "create")); got != want {
					t.Errorf("match %s = %v, want %v", addr, got, want)
				}
			}
		})
	}
}

func TestPolicyLink_MatchOtherType(t *testing.T) {
	// A role policy never attaches to a user, even one with the same name.
	link := PolicyLink{Type: "aws_iam_role", Attribute: "role", Value: "app-task"}
	user := &ResourceChange{Type: "aws_iam_user", Name: "task", Address: "aws_iam_user.task",
		AttributeValues: map[string]string{"name": "app-task"}}
	if got := link.Match(user); got != LinkNo {
		t.Errorf("match user = %v, want no", got)
	}
}

func TestPolicySources_Actions(t *testing.T) {
	const after = `{"name": "logs", "role": "app-task", "policy": "` + allowLogs + `"}`
	const before = `{"name": "logs", "role": "app-task", "policy": "{\"Statement\":[]}"}`
	cases := []struct {
		name    string
		actions string
		before  string
		after   string
		want    []string
	}{
		{"create", `["create"]`, `null`, after, []string{allowLogsText}},
		{"update", `["update"]`, before, after, []string{allowLogsText}},
		{"replace delete first", `["delete", "create"]`, before, after, []string{allowLogsText}},
		{"replace create first", `["create", "delete"]`, before, after, []string{allowLogsText}},
		{"delete", `["delete"]`, before, `null`, nil},
		{"no-op", `["no-op"]`, after, after, []string{allowLogsText}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changes := parseRaw(t, `{"resource_changes": [
				{"address": "aws_iam_role_policy.p", "type": "aws_iam_role_policy", "name": "p",
				 "change": {"actions": `+tc.actions+`, "before": `+tc.before+`, "after": `+tc.after+`, "after_unknown": {}}}
			]}`)
			sources := PolicySources(changes, nil)
			if len(sources) != len(tc.want) {
				t.Fatalf("got %d sources, want %d: %+v", len(sources), len(tc.want), sources)
			}
			for i, s := range sources {
				if s.Unknown || s.Text != tc.want[i] {
					t.Errorf("source %d: text = %q, unknown = %v", i, s.Text, s.Unknown)
				}
			}
		})
	}
}

func TestPolicySources_CountAndForEach(t *testing.T) {
	cases := []struct {
		name     string
		keys     [2]string
		roleExpr string
		names    [2]string
		want     [2][2]LinkMatch // want[policy][role]
	}{
		{
			name:     "count with a keyless reference and known names",
			keys:     [2]string{"[0]", "[1]"},
			roleExpr: `["aws_iam_role.task", "count.index"]`,
			names:    [2]string{"app-a", "app-b"},
			want:     [2][2]LinkMatch{{LinkYes, LinkNo}, {LinkNo, LinkYes}},
		},
		{
			name:     "count with a keyless reference and unknown names",
			keys:     [2]string{"[0]", "[1]"},
			roleExpr: `["aws_iam_role.task", "count.index"]`,
			want:     [2][2]LinkMatch{{LinkMaybe, LinkMaybe}, {LinkMaybe, LinkMaybe}},
		},
		{
			name:     "for_each with a keyless reference and known names",
			keys:     [2]string{`["a"]`, `["b"]`},
			roleExpr: `["aws_iam_role.task", "each.key"]`,
			names:    [2]string{"app-a", "app-b"},
			want:     [2][2]LinkMatch{{LinkYes, LinkNo}, {LinkNo, LinkYes}},
		},
		{
			name:     "a keyed reference with unknown names",
			keys:     [2]string{`["a"]`, `["b"]`},
			roleExpr: `["aws_iam_role.task[\"b\"].id", "aws_iam_role.task[\"b\"]", "aws_iam_role.task"]`,
			want:     [2][2]LinkMatch{{LinkNo, LinkYes}, {LinkNo, LinkYes}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var entries []string
			for i, key := range tc.keys {
				// The key goes inside a JSON string, so its quotes need escapes.
				jsonKey := strings.ReplaceAll(key, `"`, `\"`)
				after := `"name_prefix": "app-"`
				policyAfter := `"policy": "` + allowLogs + `"`
				if tc.names[i] != "" {
					after = `"name": "` + tc.names[i] + `"`
					policyAfter += `, "role": "` + tc.names[i] + `"`
				}
				entries = append(entries, role("aws_iam_role.task"+jsonKey, "task", after),
					`{"address": "aws_iam_role_policy.p`+jsonKey+`", "type": "aws_iam_role_policy", "name": "p",
					  "change": {"actions": ["create"], "after": {`+policyAfter+`}, "after_unknown": {}}}`)
			}
			changes := parseRaw(t, `{"resource_changes": [`+strings.Join(entries, ",")+`],
				"configuration": {"root_module": {"resources": [
					{"address": "aws_iam_role_policy.p", "mode": "managed", "type": "aws_iam_role_policy", "name": "p",
					 "expressions": {"policy": {}, "role": {"references": `+tc.roleExpr+`}}}
				]}}}`)
			sources := PolicySources(changes, nil)
			if len(sources) != 2 {
				t.Fatalf("got %d sources, want 2", len(sources))
			}
			for p, s := range sources {
				if s.Address != "aws_iam_role_policy.p"+tc.keys[p] {
					t.Fatalf("source %d address = %q", p, s.Address)
				}
				for r, key := range tc.keys {
					if got := s.Link.Match(changeAt(t, changes, "aws_iam_role.task"+key, "create")); got != tc.want[p][r] {
						t.Errorf("%s match aws_iam_role.task%s = %v, want %v", s.Address, key, got, tc.want[p][r])
					}
				}
			}
		})
	}
}

func TestPolicySources_ModulePath(t *testing.T) {
	// References are relative to the module instance of the source, so the
	// policy in module.app["eu"] attaches to the role of that instance only.
	changes := parseRaw(t, `{
		"resource_changes": [
			{"address": "module.app[\"eu\"].aws_iam_role.task", "module_address": "module.app[\"eu\"]",
			 "type": "aws_iam_role", "name": "task",
			 "change": {"actions": ["create"], "after": {"name_prefix": "eu-"}, "after_unknown": {"name": true}}},
			{"address": "module.app[\"us\"].aws_iam_role.task", "module_address": "module.app[\"us\"]",
			 "type": "aws_iam_role", "name": "task",
			 "change": {"actions": ["create"], "after": {"name_prefix": "us-"}, "after_unknown": {"name": true}}},
			{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
			 "change": {"actions": ["create"], "after": {"name_prefix": "root-"}, "after_unknown": {"name": true}}},
			{"address": "module.app[\"eu\"].aws_iam_role_policy.p", "module_address": "module.app[\"eu\"]",
			 "type": "aws_iam_role_policy", "name": "p",
			 "change": {"actions": ["create"], "after": {"policy": "`+allowLogs+`"}, "after_unknown": {"role": true}}}
		],
		"configuration": {"root_module": {
			"resources": [
				{"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task", "expressions": {}}
			],
			"module_calls": {"app": {"module": {"resources": [
				{"address": "aws_iam_role.task", "mode": "managed", "type": "aws_iam_role", "name": "task", "expressions": {}},
				{"address": "aws_iam_role_policy.p", "mode": "managed", "type": "aws_iam_role_policy", "name": "p",
				 "expressions": {"policy": {}, "role": {"references": ["aws_iam_role.task.name", "aws_iam_role.task"]}}}
			]}}}
		}}
	}`)
	sources := sourcesAt(PolicySources(changes, nil), `module.app["eu"].aws_iam_role_policy.p`)
	if len(sources) != 1 {
		t.Fatalf("got %d sources, want 1", len(sources))
	}
	want := map[string]LinkMatch{
		`module.app["eu"].aws_iam_role.task`: LinkYes,
		`module.app["us"].aws_iam_role.task`: LinkNo,
		`aws_iam_role.task`:                  LinkNo,
	}
	for addr, w := range want {
		if got := sources[0].Link.Match(changeAt(t, changes, addr, "create")); got != w {
			t.Errorf("match %s = %v, want %v", addr, got, w)
		}
	}
}

func TestParseResourceRef(t *testing.T) {
	cases := []struct {
		ref, typ, name, key string
		ok                  bool
	}{
		{"aws_iam_role.task", "aws_iam_role", "task", "", true},
		{"aws_iam_role.task.id", "aws_iam_role", "task", "", true},
		{"aws_iam_role.task[0].arn", "aws_iam_role", "task", "[0]", true},
		{`aws_iam_role.task["a.b]"]`, "aws_iam_role", "task", `["a.b]"]`, true},
		{"var.role", "", "", "", false},
		{"count.index", "", "", "", false},
		{"data.aws_iam_role.r", "", "", "", false},
		{"module.m.role", "", "", "", false},
		{`aws_iam_role.task["a`, "", "", "", false},
	}
	for _, tc := range cases {
		typ, name, key, ok := parseResourceRef(tc.ref)
		if typ != tc.typ || name != tc.name || key != tc.key || ok != tc.ok {
			t.Errorf("parseResourceRef(%q) = %q, %q, %q, %v", tc.ref, typ, name, key, ok)
		}
	}
}
