package policy

import (
	"strings"
	"testing"
)

// otherSecretARN is a secret that the resource policy isn't attached to.
const otherSecretARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:other-db-AbCdEf"

// onSecret returns the policy on the secret app-db, whose ARN the plan
// doesn't know, and its verdict for GetSecretValue on target in both modes.
func onSecret(t *testing.T, raw, target string) (Result, Result) {
	t.Helper()
	d := mustPolicy(t, raw).OnResource(secretTargets, nil)
	const action = "secretsmanager:GetSecretValue"
	return d.Coverage(action, []string{target}, nil, false), d.Coverage(action, []string{target}, nil, true)
}

func TestOnResource(t *testing.T) {
	covered := Result{Verdict: Covered}
	missing := Result{Verdict: Missing}
	scope := Result{Verdict: Unverified, Reason: ReasonResourceScope}
	cases := []struct {
		name               string
		statements, target string
		want, wantStrict   Result
	}{
		{
			name:       "Resource * grants the attached secret",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}`,
			target:     secretARN, want: covered, wantStrict: covered,
		},
		{
			name:       "Resource * doesn't grant another secret",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}`,
			target:     otherSecretARN, want: missing, wantStrict: missing,
		},
		{
			name:       "a statement without Resource applies to the attached secret",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue"}`,
			target:     otherSecretARN, want: missing, wantStrict: missing,
		},
		{
			name:       "a narrower Allow stays narrow",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"` + secretARN + `"}`,
			target:     strings.Replace(secretARN, "AbCdEf", "ZyXwVu", 1), want: missing, wantStrict: missing,
		},
		{
			name:       "an Allow on another secret grants nothing",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"` + otherSecretARN + `"}`,
			target:     secretARN, want: missing, wantStrict: missing,
		},
		{
			name: "a Deny on * applies to the attached secret",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"},
				{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}`,
			target: secretARN, want: missing, wantStrict: missing,
		},
		{
			name: "a NotResource that excludes the secret doesn't apply",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"},
				{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","NotResource":"arn:aws:secretsmanager:*:*:secret:app-*"}`,
			target: secretARN, want: covered, wantStrict: covered,
		},
		{
			name: "a NotResource on another secret denies the attached one",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"},
				{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","NotResource":"` + otherSecretARN + `"}`,
			target: secretARN, want: missing, wantStrict: missing,
		},
		{
			// The NotResource list may or may not hold the secret, so the
			// Deny can't be shown to apply.
			name: "a NotResource that may exclude the secret isn't definite",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"},
				{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","NotResource":"arn:aws:secretsmanager:*:*:secret:app-db-Ab*"}`,
			target: secretARN, want: covered, wantStrict: covered,
		},
		{
			// Neither name pattern contains the other, so the overlap has no
			// pattern of its own, and the grant is one the tool can't check.
			name:       "a partial overlap is unverified",
			statements: `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:123456789012:secret:app-*-AbCdEf"}`,
			target:     secretARN, want: covered, wantStrict: scope,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, gotStrict := onSecret(t, `{"Statement":[`+c.statements+`]}`, c.target)
			if got != c.want || gotStrict != c.wantStrict {
				t.Errorf("Coverage = %+v, strict %+v; want %+v, strict %+v", got, gotStrict, c.want, c.wantStrict)
			}
		})
	}
}

// A statement on the whole secret takes the need's resource when the caller
// passes it, so a Deny on the secret covers a need on secret:app-db-*, which
// is wider than the secret's pattern.
func TestOnResource_AsNeedResource(t *testing.T) {
	need := "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-*"
	d := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"},
		{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`)
	const action = "secretsmanager:GetSecretValue"
	if got := d.OnResource(secretTargets, nil).Coverage(action, []string{need}, nil, false); got.Verdict != Covered {
		t.Errorf("on the secret's pattern: Coverage = %+v, want covered: the Deny doesn't cover the whole need", got)
	}
	if got := d.OnResource(secretTargets, []string{need}).Coverage(action, []string{need}, nil, false); got.Verdict != Missing {
		t.Errorf("as the need's resource: Coverage = %+v, want missing", got)
	}
}

func TestMayGrant(t *testing.T) {
	d := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"},
		{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`).MayGrant(ReasonResourceScope)
	if len(d.Statements) != 1 || d.Statements[0].Effect != "Allow" {
		t.Fatalf("statements = %+v, want the Allow only", d.Statements)
	}
	want := Result{Verdict: Unverified, Reason: ReasonResourceScope}
	if got := d.Coverage("secretsmanager:GetSecretValue", []string{secretARN}, nil, true); got != want {
		t.Errorf("strict: Coverage = %+v, want %+v", got, want)
	}
	// A statement that already carries condition keeps it.
	again := d.MayGrant(ReasonCondition).MayGrant(ReasonResourceScope)
	if got := again.Coverage("secretsmanager:GetSecretValue", []string{secretARN}, nil, true); got.Reason != ReasonCondition {
		t.Errorf("reason = %v, want condition", got.Reason)
	}
}

func TestARNOverlap(t *testing.T) {
	cases := []struct {
		a, b               string
		overlap, decidable bool
	}{
		{"arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-*", secretTargets[0], true, true},
		{"arn:aws:secretsmanager:us-east-1:123456789012:secret:other-*", secretTargets[0], false, true},
		{"arn:aws:secretsmanager:*", secretTargets[0], true, false},
		{"arn:aws:secretsmanager:us-east-1:123456789012:secret:${aws:username}", secretTargets[0], true, false},
		{"*", secretTargets[0], true, true},
	}
	for _, c := range cases {
		overlap, decidable := ARNOverlap(c.a, c.b)
		if overlap != c.overlap || decidable != c.decidable {
			t.Errorf("ARNOverlap(%q, %q) = %v, %v; want %v, %v", c.a, c.b, overlap, decidable, c.overlap, c.decidable)
		}
	}
}
