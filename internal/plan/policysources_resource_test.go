package plan

import (
	"strings"
	"testing"
)

// secretPoliciesPlan has two secrets, app and other, and a secret policy for each
// way its secret_arn can name a secret: a reference, a known ARN, and a
// variable. The secret app also sets its policy inline, and other leaves
// its computed policy attribute out of the configuration.
const secretPoliciesPlan = `{
	"resource_changes": [
		{"address": "aws_secretsmanager_secret.app", "type": "aws_secretsmanager_secret", "name": "app",
		 "change": {"actions": ["create"], "after": {"name": "app-db", "policy": "{\"Statement\":[]}"}, "after_unknown": {"arn": true}}},
		{"address": "aws_secretsmanager_secret.other", "type": "aws_secretsmanager_secret", "name": "other",
		 "change": {"actions": ["create"], "after": {"name": "other-db"}, "after_unknown": {"arn": true, "policy": true}}},
		{"address": "aws_secretsmanager_secret_policy.by_ref", "type": "aws_secretsmanager_secret_policy", "name": "by_ref",
		 "change": {"actions": ["create"], "after": {"policy": "{}"}, "after_unknown": {"secret_arn": true}}},
		{"address": "aws_secretsmanager_secret_policy.by_arn", "type": "aws_secretsmanager_secret_policy", "name": "by_arn",
		 "change": {"actions": ["create"], "after": {"policy": "{}", "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"}, "after_unknown": {}}},
		{"address": "aws_secretsmanager_secret_policy.by_var", "type": "aws_secretsmanager_secret_policy", "name": "by_var",
		 "change": {"actions": ["create"], "after": {"policy": "{}"}, "after_unknown": {"secret_arn": true}}}
	],
	"configuration": {"root_module": {"resources": [
		{"address": "aws_secretsmanager_secret.app", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "app",
		 "expressions": {"name": {}, "policy": {}}},
		{"address": "aws_secretsmanager_secret.other", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "other",
		 "expressions": {"name": {}}},
		{"address": "aws_secretsmanager_secret_policy.by_ref", "mode": "managed", "type": "aws_secretsmanager_secret_policy", "name": "by_ref",
		 "expressions": {"policy": {}, "secret_arn": {"references": ["aws_secretsmanager_secret.app.arn", "aws_secretsmanager_secret.app"]}}},
		{"address": "aws_secretsmanager_secret_policy.by_arn", "mode": "managed", "type": "aws_secretsmanager_secret_policy", "name": "by_arn",
		 "expressions": {"policy": {}, "secret_arn": {}}},
		{"address": "aws_secretsmanager_secret_policy.by_var", "mode": "managed", "type": "aws_secretsmanager_secret_policy", "name": "by_var",
		 "expressions": {"policy": {}, "secret_arn": {"references": ["var.secret_arn"]}}}
	]}}
}`

// TestPolicySources_SecretsManager checks that this version reads both
// Secrets Manager source types, and resolves each one to the secret it
// attaches to.
func TestPolicySources_SecretsManager(t *testing.T) {
	sources := PolicySources(parseRaw(t, secretPoliciesPlan), nil)
	var got []string
	for _, s := range sources {
		line := s.Address + " " + s.Path + " " + string(s.Kind) + " " + s.Service + " text=" + s.Text
		if s.Unknown || s.Unread {
			line += " unknown"
		}
		for _, r := range s.Resources {
			to := r.ARN
			if r.Change != nil {
				to = r.Change.Address
			}
			line += " -> " + to + " " + r.Match.String()
		}
		if s.ResourceUnknown {
			line += " -> unknown"
		}
		got = append(got, line)
	}
	want := []string{
		`aws_secretsmanager_secret.app policy resource secretsmanager text={"Statement":[]} -> aws_secretsmanager_secret.app yes`,
		`aws_secretsmanager_secret_policy.by_ref policy resource secretsmanager text={} -> aws_secretsmanager_secret.app yes`,
		`aws_secretsmanager_secret_policy.by_arn policy resource secretsmanager text={} -> arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf yes`,
		`aws_secretsmanager_secret_policy.by_var policy resource secretsmanager text={} -> unknown`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
