package policy

import "testing"

func TestGlobIntersect(t *testing.T) {
	cases := []struct {
		a, b      string
		want      bool
		decidable bool
	}{
		// Identical literals
		{"arn:aws:secretsmanager:us-east-1:111:/secret", "arn:aws:secretsmanager:us-east-1:111:/secret", true, true},
		// One side is "*"
		{"*", "arn:anything", true, true},
		{"arn:anything", "*", true, true},
		{"arn:aws:s3::bucket/*", "*", true, true},
		// Disjoint literals never intersect
		{"example-a-*", "example-b-*", false, true},
		{"arn:aws:secretsmanager:us-east-1", "arn:aws:secretsmanager:eu-west-1", false, true},
		// A literal never intersects a disjoint literal with identical length
		{"a", "b", false, true},
		// Shared prefix with a wildcard on both sides
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*", "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-b-*", false, true},
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:example-*", "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-b-*", true, true},
		// Target with wildcards for unknown region/account vs a precise grant.
		// Note: at RAW level a '*' matches any string including colons, so the
		// two patterns below genuinely share a common string (the stars absorb
		// the region/account colons). The ARN-aware arnIntersect splits on ':'
		// and is what rejects them. Both are asserted here at the raw level.
		{"arn:*:secretsmanager:*:*:secret:example-b-*", "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-b-*", true, true},
		// Wildcard *after* a literal that must match a fixed prefix
		{"arn:*:secretsmanager:*:*:secret:example-b-*", "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-b-abc12", true, true},
		// '?' matches exactly one character
		{"a?c", "abc", true, true},
		{"a?c", "aXc", true, true},
		{"a?c", "ac", false, true},
		{"a?c", "abac", false, true},
		// Empty patterns
		{"", "", true, true},
		{"", "abc", false, true},
		// Multi-* patterns
		{"a*b*c", "aXbYc", true, true},
		{"a*b*c", "aXbYd", false, true},
		// Undecidable constructs: unmodeled, treated as "may intersect"
		{"arn:[aws]*", "arn:aws:x", true, false},
		{"arn:${aws:username}:x", "arn:alice:x", true, false},
	}

	for _, c := range cases {
		t.Run(c.a+" vs "+c.b, func(t *testing.T) {
			yes, dec := globIntersect(c.a, c.b)
			if yes != c.want || dec != c.decidable {
				t.Errorf("globIntersect(%q, %q) = (%v, %v), want (%v, %v)", c.a, c.b, yes, dec, c.want, c.decidable)
			}
		})
	}
}

func TestArnIntersect(t *testing.T) {
	exampleB := "arn:*:secretsmanager:*:*:secret:example-b-*"
	cases := []struct {
		grant  string
		target string
		want   bool
	}{
		// A grant scoped to example-a never covers example-b (the fix).
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*", exampleB, false},
		// Matching secret name covers, even with wildcard region/account.
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:example-b-*", exampleB, true},
		{"arn:*:secretsmanager:*:*:secret:example-b-*", exampleB, true},
		{"*", exampleB, true},
		// A different service prefix never covers.
		{"arn:aws:ec2:us-east-1:111111111111:secret:example-b-*", exampleB, false},
		// A shorter name literal (without the trailing -*) never covers.
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:example-b", exampleB, false},
		// Undecidable segment (bracket expr) -> treated as overlap.
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:[example]-b-*", exampleB, true},
		// A wildcard inside the resource segment still needs the prefix to match.
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:example-*-x", exampleB, true},
		// A grant on the fully-expanded generated ARN (name + random suffix)
		// still intersects the version's `name-*` target.
		{"arn:aws:secretsmanager:us-east-1:111111111111:secret:example-b-abcdef", exampleB, true},
	}
	for _, c := range cases {
		if got := arnIntersect(c.grant, c.target); got != c.want {
			t.Errorf("arnIntersect(%q, %q) = %v, want %v", c.grant, c.target, got, c.want)
		}
	}
}

func TestCoversTarget(t *testing.T) {
	// Policy grants both value actions on secret example-a's ARN only.
	policy, err := Parse([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "A",
			"Effect": "Allow",
			"Action": ["secretsmanager:PutSecretValue", "secretsmanager:GetSecretValue"],
			"Resource": "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	// Same action on a different secret's ARN pattern is NOT covered.
	if policy.CoversTarget("secretsmanager:PutSecretValue", []string{"arn:*:secretsmanager:*:*:secret:example-b-*"}) {
		t.Error("expected action on example-b NOT covered by example-a grant")
	}
	// Same action on the granted ARN IS covered.
	if !policy.CoversTarget("secretsmanager:PutSecretValue", []string{"arn:*:secretsmanager:*:*:secret:example-a-*"}) {
		t.Error("expected action on example-a covered by example-a grant")
	}
	// A different action is not covered even on the granted ARN.
	if policy.CoversTarget("secretsmanager:DescribeSecret", []string{"arn:*:secretsmanager:*:*:secret:example-a-*"}) {
		t.Error("expected DescribeSecret NOT covered (not granted)")
	}
}

func TestCoversTargetServiceWildcard(t *testing.T) {
	policy, err := Parse([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "secretsmanager:*",
			"Resource": "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	// Service wildcard is action-covered but still resource-scoped.
	if policy.CoversTarget("secretsmanager:PutSecretValue", []string{"arn:*:secretsmanager:*:*:secret:example-b-*"}) {
		t.Error("expected service-wildcard action on example-b NOT covered by example-a grant")
	}
	if !policy.CoversTarget("secretsmanager:PutSecretValue", []string{"arn:*:secretsmanager:*:*:secret:example-a-*"}) {
		t.Error("expected service-wildcard action on example-a covered")
	}
}

func TestCoversTargetWildcardResource(t *testing.T) {
	policy, err := Parse([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "secretsmanager:PutSecretValue",
			"Resource": "*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if !policy.CoversTarget("secretsmanager:PutSecretValue", []string{"arn:*:secretsmanager:*:*:secret:example-b-*"}) {
		t.Error("expected any action covered when Resource is *")
	}
}
