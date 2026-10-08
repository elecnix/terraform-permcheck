package policy

import "testing"

func TestCoverage_Verdicts(t *testing.T) {
	scoped := `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs:us-east-1:111122223333:example-a"}]}`
	everywhere := `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}`
	denied := `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"},{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}]}`
	targetA := []string{"arn:*:sqs:*:*:example-a"}
	targetB := []string{"arn:*:sqs:*:*:example-b"}

	cases := []struct {
		name    string
		policy  string
		targets []string
		strict  bool
		want    Verdict
	}{
		{"no grant, target unknown", `{"Statement":[]}`, nil, false, Missing},
		{"no grant, target known", `{"Statement":[]}`, targetA, false, Missing},
		{"grant everywhere, target unknown", everywhere, nil, true, Covered},
		{"scoped grant, target unknown", scoped, nil, false, Covered},
		{"scoped grant, target unknown, strict", scoped, nil, true, Unverified},
		{"scoped grant on the target", scoped, targetA, true, Covered},
		{"scoped grant on another target", scoped, targetB, false, Missing},
		{"definite deny, target unknown", denied, nil, false, Missing},
		{"definite deny, target known", denied, targetA, false, Missing},
	}
	for _, c := range cases {
		doc := mustPolicy(t, c.policy)
		if got := doc.Coverage("sqs:SendMessage", c.targets, c.strict); got != c.want {
			t.Errorf("%s: Coverage = %v, want %v", c.name, got, c.want)
		}
	}
}
