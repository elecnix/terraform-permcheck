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
		{"no address", map[string]Entry{"task": {}}, `principals["task"]: address is required`},
		{"a user", map[string]Entry{"task": {Address: "aws_iam_user.ci"}}, "users aren't supported yet"},
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
