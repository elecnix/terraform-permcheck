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
		if got := doc.Coverage("sqs:SendMessage", c.targets, nil, c.strict).Verdict; got != c.want {
			t.Errorf("%s: Coverage = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCoverage_PolicyVariableIsNotALiteral(t *testing.T) {
	// A ${...} variable expands at evaluation time, so the grant is not a
	// literal of a fixed shape even though it holds no wildcard; counting the
	// colon inside ${aws:username} would drop a grant that can apply.
	const doc = `{"Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction",
		"Resource":"arn:aws:lambda:us-east-1:111111111111:function:${aws:username}:live"}]}`
	target := []string{"arn:*:lambda:*:*:function:app-fn:live"}

	parsed, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Before the fix the shape shortcut skipped this grant and the verdict was
	// Missing. Undecidable overlap counts as coverage at this layer, in both
	// modes, which is the same treatment every other ${...} pattern gets.
	for _, strict := range []bool{false, true} {
		if got := parsed.Coverage("lambda:InvokeFunction", target, nil, strict).Verdict; got != Covered {
			t.Errorf("strict=%v verdict = %v, want Covered", strict, got)
		}
	}
}
