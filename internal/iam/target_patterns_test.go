package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// TestSecretPattern_SuffixIsSixCharacters checks that a secret's pattern
// matches the hyphen and six random characters AWS appends, and nothing
// longer. With name-* the secret "app" would overlap a grant on
// app-production-*, a set of other secrets.
func TestSecretPattern_SuffixIsSixCharacters(t *testing.T) {
	secret := &plan.ResourceChange{
		Type: "aws_secretsmanager_secret", Name: "s", Change: "create",
		AttributeValues: map[string]string{"name": "app"},
	}
	targets := resourceTargets(secret, []*plan.ResourceChange{secret})
	cases := []struct {
		grant string
		want  bool
	}{
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:app-production-*", false},
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:app-*", true},
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:app-AbCdEf", true},
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:app", false},
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:*", true},
	}
	for _, c := range cases {
		policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":"secretsmanager:CreateSecret","Resource":"`+c.grant+`"}]}`)
		if got := policy.worstVerdict("secretsmanager:CreateSecret", targets, false) == Covered; got != c.want {
			t.Errorf("grant %s covers secret app = %v, want %v", c.grant, got, c.want)
		}
	}
}

// TestRoleTargets_PathAndName checks that a referenced role's ARN comes from
// its planned path and name. A role named app is not role/myapp.
func TestRoleTargets_PathAndName(t *testing.T) {
	roleWith := func(values map[string]string) []*plan.ResourceChange {
		fn := lambdaReferencing("aws_iam_role.r.arn", "aws_iam_role.r")
		r := &plan.ResourceChange{Type: "aws_iam_role", Name: "r", Change: "create", Address: "aws_iam_role.r", AttributeValues: values}
		return []*plan.ResourceChange{fn, r}
	}
	cases := []struct {
		name   string
		values map[string]string
		grant  string
		want   bool
	}{
		{"name only overlaps nothing longer", map[string]string{"name": "app", "path": "/"}, "arn:aws:iam::111111111111:role/myapp", false},
		{"root path", map[string]string{"name": "app", "path": "/"}, "arn:aws:iam::111111111111:role/app", true},
		{"planned path", map[string]string{"name": "app", "path": "/svc/"}, "arn:aws:iam::111111111111:role/svc/app", true},
		{"planned path excludes the root", map[string]string{"name": "app", "path": "/svc/"}, "arn:aws:iam::111111111111:role/app", false},
		{"unknown path may be any", map[string]string{"name": "app"}, "arn:aws:iam::111111111111:role/svc/app", true},
		{"unknown path keeps the name", map[string]string{"name": "app"}, "arn:aws:iam::111111111111:role/myapp", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			changes := roleWith(c.values)
			policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"iam:PassRole","Resource":"`+c.grant+`"}]}`)
			got := len(passRoleMissing(changes[0], policy, changes, false)) == 0
			if got != c.want {
				t.Errorf("covered = %v, want %v (targets %v)", got, c.want, roleTargets(changes[0], "role", changes))
			}
		})
	}
}
