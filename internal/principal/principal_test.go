package principal

import (
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

func TestValidate(t *testing.T) {
	needs := []iam.Need{{Sid: "FetchSecrets", Principal: "task", Actions: []string{"secretsmanager:GetSecretValue"}}}
	cases := []struct {
		name    string
		entries map[string]Entry
		err     string
	}{
		{"no map", nil, ""},
		{"a role", map[string]Entry{"task": {Address: "aws_iam_role.task"}}, ""},
		{"a role in a module", map[string]Entry{"task": {Address: `module.app["eu"].aws_iam_role.task[0]`}}, ""},
		{"no address", map[string]Entry{"task": {}}, `principals["task"]: address is required, or name or arn`},
		{"a role name", map[string]Entry{"task": {Name: "ops-admin"}}, ""},
		{"a role arn", map[string]Entry{"task": {ARN: "arn:aws:iam::123456789012:role/ops-admin"}}, ""},
		{"a role arn with a path", map[string]Entry{"task": {ARN: "arn:aws:iam::123456789012:role/service/ops-admin"}}, ""},
		{"an address and a name", map[string]Entry{"task": {Address: "aws_iam_role.task", Name: "ops-admin"}}, "set only one of address, name and arn"},
		{"a name and an arn", map[string]Entry{"task": {Name: "ops-admin", ARN: "arn:aws:iam::123456789012:role/ops-admin"}}, "set only one of address, name and arn"},
		{"a user arn", map[string]Entry{"task": {ARN: "arn:aws:iam::123456789012:user/ci"}}, ""},
		{"a user arn with a path", map[string]Entry{"task": {ARN: "arn:aws:iam::123456789012:user/ci/deployer"}}, ""},
		{"a user arn with the user type", map[string]Entry{"task": {ARN: "arn:aws:iam::123456789012:user/ci", Type: TypeUser}}, ""},
		{"a user arn with the role type", map[string]Entry{"task": {ARN: "arn:aws:iam::123456789012:user/ci", Type: TypeRole}}, `gives an IAM user, and type is "role"`},
		{"a user name", map[string]Entry{"task": {Name: "ci", Type: TypeUser}}, ""},
		{"a role name with the role type", map[string]Entry{"task": {Name: "ops-admin", Type: TypeRole}}, ""},
		{"an unknown type", map[string]Entry{"task": {Name: "ops", Type: "group"}}, `type "group" must be "role" or "user"`},
		{"a policy arn", map[string]Entry{"task": {ARN: "arn:aws:iam::123456789012:policy/ops"}}, "is not the ARN of an IAM role or user"},
		{"an arn of another service", map[string]Entry{"task": {ARN: "arn:aws:sts::123456789012:assumed-role/ops-admin/s"}}, "is not the ARN of an IAM role or user"},
		{"an arn without an account", map[string]Entry{"task": {ARN: "arn:aws:iam:::role/ops-admin"}}, "is not the ARN of an IAM role or user"},
		{"a wildcard arn", map[string]Entry{"task": {ARN: "arn:aws:iam::123456789012:role/ops-*"}}, "has a wildcard"},
		{"a wildcard name", map[string]Entry{"task": {Name: "ops-?"}}, "has a wildcard"},
		{"an arn as the name", map[string]Entry{"task": {Name: "arn:aws:iam::123456789012:role/ops-admin"}}, "set it as arn"},
		{"a name with a path", map[string]Entry{"task": {Name: "service/ops-admin"}}, "has a path"},
		{"a user", map[string]Entry{"task": {Address: "aws_iam_user.ci"}}, ""},
		{"a user with the role type", map[string]Entry{"task": {Address: "aws_iam_user.ci", Type: TypeRole}}, `gives an IAM user, and type is "role"`},
		{"a group", map[string]Entry{"task": {Address: "aws_iam_group.ops"}}, "has the type aws_iam_group"},
		{"another type", map[string]Entry{"task": {Address: "aws_iam_policy.p"}}, "has the type aws_iam_policy"},
		{"a data source", map[string]Entry{"task": {Address: "data.aws_iam_role.task"}}, "is not the terraform address of a resource"},
		{"an unused key", map[string]Entry{"task": {Address: "aws_iam_role.task"}, "deploy": {Address: "aws_iam_role.deploy"}}, `principals["deploy"]: no need has the principal "deploy"`},
		{"an empty key", map[string]Entry{"": {Address: "aws_iam_role.task"}}, "not empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Validate(c.entries, needs)
			switch {
			case c.err == "" && err != nil:
				t.Errorf("unexpected error %v", err)
			case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
				t.Errorf("error %v, want one containing %q", err, c.err)
			}
		})
	}
}

func TestFind(t *testing.T) {
	changes := []*plan.ResourceChange{
		{Address: "aws_iam_role.task", Type: "aws_iam_role", Change: "delete"},
		{Address: "aws_iam_role.task", Type: "aws_iam_role", Change: "create"},
		{Address: "aws_iam_role.gone", Type: "aws_iam_role", Change: "delete"},
	}
	rc, err := Find(changes, "task", "aws_iam_role.task")
	if err != nil || rc != changes[1] {
		t.Errorf("Find(task) = %v, %v; want the create of the replace", rc, err)
	}
	if _, err := Find(changes, "gone", "aws_iam_role.gone"); err == nil || !strings.Contains(err.Error(), "deletes") {
		t.Errorf("Find(gone) error = %v, want one that says the plan deletes it", err)
	}
	if _, err := Find(changes, "x", "aws_iam_role.x"); err == nil || !strings.Contains(err.Error(), "matches no resource change") {
		t.Errorf("Find(x) error = %v", err)
	}
}

// TestFindOutside checks that a role given by its name or ARN must be
// outside the plan. A role of the plan with the known name, or with the
// known ARN, is an error that gives its address. A role of the plan whose
// known ARN differs is another role.
func TestFindOutside(t *testing.T) {
	changes := []*plan.ResourceChange{
		{Address: "aws_iam_role.task", Type: "aws_iam_role", Change: "create", AttributeValues: map[string]string{"name": "app-task"}},
		{Address: "aws_iam_role.kept", Type: "aws_iam_role", Change: "no-op",
			AttributeValues: map[string]string{"name": "app-kept", "arn": "arn:aws:iam::123456789012:role/app-kept"}},
		{Address: "aws_iam_role.prefixed", Type: "aws_iam_role", Change: "create"},
		{Address: "aws_iam_user.ci", Type: "aws_iam_user", Change: "create", AttributeValues: map[string]string{"name": "ci"}},
	}
	cases := []struct {
		entry Entry
		err   string
	}{
		{Entry{Name: "ops-admin"}, ""},
		{Entry{ARN: "arn:aws:iam::123456789012:role/ops-admin"}, ""},
		{Entry{Name: "app-task"}, `the role of "name": "app-task" is in the plan as aws_iam_role.task: map it with "address": "aws_iam_role.task"`},
		{Entry{Name: "App-Task"}, "aws_iam_role.task"},
		{Entry{ARN: "arn:aws:iam::123456789012:role/app-task"}, "aws_iam_role.task"},
		{Entry{ARN: "arn:aws:iam::123456789012:role/app-kept"}, "aws_iam_role.kept"},
		{Entry{Name: "app-kept"}, "aws_iam_role.kept"},
		{Entry{ARN: "arn:aws:iam::210987654321:role/app-kept"}, ""},
		// A user of the plan is another principal than a role of the same
		// name, and a user entry is checked against the users of the plan.
		{Entry{Name: "ci"}, ""},
		{Entry{Name: "app-task", Type: TypeUser}, ""},
		{Entry{Name: "ci", Type: TypeUser}, `the user of "name": "ci" is in the plan as aws_iam_user.ci`},
		{Entry{ARN: "arn:aws:iam::123456789012:user/ci"}, "aws_iam_user.ci"},
	}
	for _, c := range cases {
		err := FindOutside(changes, "ops", c.entry)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%+v: unexpected error %v", c.entry, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%+v: error %v, want one containing %q", c.entry, err, c.err)
		}
	}
}

// TestEntryOutside checks the role or user that a name or arn entry gives:
// an ARN gives its kind and the last part of its path as the name, and a
// name entry is a role unless its type is user.
func TestEntryOutside(t *testing.T) {
	if got := (Entry{Name: "ops-admin"}).Outside(); got != (plan.OutsidePrincipal{Type: "aws_iam_role", Name: "ops-admin"}) {
		t.Errorf("name entry = %+v", got)
	}
	arn := "arn:aws:iam::123456789012:role/service/ops-admin"
	if got := (Entry{ARN: arn}).Outside(); got != (plan.OutsidePrincipal{Type: "aws_iam_role", Name: "ops-admin", ARN: arn}) {
		t.Errorf("arn entry = %+v", got)
	}
	user := "arn:aws:iam::123456789012:user/ci/deployer"
	if got := (Entry{ARN: user}).Outside(); got != (plan.OutsidePrincipal{Type: "aws_iam_user", Name: "deployer", ARN: user}) {
		t.Errorf("user arn entry = %+v", got)
	}
	if got := (Entry{Name: "ci", Type: TypeUser}).Outside(); got != (plan.OutsidePrincipal{Type: "aws_iam_user", Name: "ci"}) {
		t.Errorf("user name entry = %+v", got)
	}
}
