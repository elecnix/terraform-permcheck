package iam

import (
	"errors"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// typeKeyedResolver serves a distinct schema per terraform resource type.
type typeKeyedResolver map[string]SchemaLike

func (r typeKeyedResolver) Resolve(t string) (SchemaLike, error) {
	s, ok := r[t]
	if !ok {
		return nil, errors.New("no schema")
	}
	return s, nil
}

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
	policy, err := ParsePolicy([]byte(`{
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
	policy, err := ParsePolicy([]byte(`{
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
	policy, err := ParsePolicy([]byte(`{
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

// secretVersionSchema is the create permission set the source parser extracts
// for aws_secretsmanager_secret_version.
func secretVersionSchema() fakeSchema {
	return fakeSchema{
		perms: map[string][]string{
			"create": {"secretsmanager:PutSecretValue", "secretsmanager:GetSecretValue"},
		},
	}
}

func TestValidate_ResourceScopedCoverage(t *testing.T) {
	// Two secrets, a version on secret b only, policy grants the value actions
	// on secret a's ARN only. The version's create permissions must be reported
	// missing — the grant never applies to secret b.
	schema := secretVersionSchema()
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{
			Type:            "aws_secretsmanager_secret",
			Name:            "a",
			Change:          "create",
			AttributeValues: map[string]string{"name": "example-a"},
		},
		{
			Type:            "aws_secretsmanager_secret",
			Name:            "b",
			Change:          "create",
			AttributeValues: map[string]string{"name": "example-b"},
		},
		{
			Type:            "aws_secretsmanager_secret_version",
			Name:            "b",
			Change:          "create",
			AttributeValues: map[string]string{},
			References:      map[string][]string{"secret_id": {"aws_secretsmanager_secret.b.id", "aws_secretsmanager_secret.b"}},
		},
	}

	policy, err := ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["secretsmanager:PutSecretValue", "secretsmanager:GetSecretValue"],
			"Resource": "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	missing, err := Validate(changes, policy, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// The version's PutSecretValue/GetSecretValue must be missing, targeted at
	// the version resource.
	if !hasActionOn(missing, "secretsmanager:PutSecretValue", "aws_secretsmanager_secret_version", "b") {
		t.Errorf("expected PutSecretValue missing on aws_secretsmanager_secret_version.b, got %+v", missing)
	}
	if !hasActionOn(missing, "secretsmanager:GetSecretValue", "aws_secretsmanager_secret_version", "b") {
		t.Errorf("expected GetSecretValue missing on aws_secretsmanager_secret_version.b, got %+v", missing)
	}
}

func TestValidate_ResourceScopedCoverage_CoveredByMatchingARN(t *testing.T) {
	// Policy grants on example-b-* → the version on secret b IS covered.
	schema := secretVersionSchema()
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret", Name: "b", Change: "create", AttributeValues: map[string]string{"name": "example-b"}},
		{
			Type:       "aws_secretsmanager_secret_version",
			Name:       "b",
			Change:     "create",
			References: map[string][]string{"secret_id": {"aws_secretsmanager_secret.b"}},
		},
	}

	policy, err := ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["secretsmanager:PutSecretValue", "secretsmanager:GetSecretValue"],
			"Resource": "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-b-*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	missing, err := Validate(changes, policy, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hasActionOn(missing, "secretsmanager:PutSecretValue", "aws_secretsmanager_secret_version", "b") {
		t.Errorf("expected no PutSecretValue finding when grant matches target ARN, got %+v", missing)
	}
}

func TestValidate_ResourceScopedCoverage_UnknownTargetFallsBackToActionOnly(t *testing.T) {
	// When the target ARN can't be derived (no references / static HCL mode),
	// action-only matching must be preserved: a grant on example-a-* still
	// counts as covering a version whose target secret is unknown.
	schema := secretVersionSchema()
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret_version", Name: "b", Change: "create"},
	}

	policy, err := ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "secretsmanager:PutSecretValue",
			"Resource": "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	missing, err := Validate(changes, policy, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hasActionOn(missing, "secretsmanager:PutSecretValue", "aws_secretsmanager_secret_version", "b") {
		t.Errorf("expected action-only matching when target unknown, got %+v", missing)
	}
}

func TestValidate_ResourceScopedCoverage_ActionUncoveredUnaltered(t *testing.T) {
	// A policy that grants nothing still reports unconditional management
	// actions missing, unchanged by the resource-scoped check.
	schema := secretVersionSchema()
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret_version", Name: "b", Change: "create"},
	}

	missing, err := Validate(changes, denyAll{}, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "secretsmanager:PutSecretValue") {
		t.Errorf("expected PutSecretValue missing with deny-all policy, got %+v", missing)
	}
}

func TestValidate_ResourceScopedCoverage_ReferencedIndexedSecret(t *testing.T) {
	// A version whose secret_id references a count-indexed secret must still
	// derive the target ARN from the secret's configured name.
	resolver := typeKeyedResolver{
		"aws_secretsmanager_secret":         fakeSchema{perms: map[string][]string{"create": {"secretsmanager:DescribeSecret"}}},
		"aws_secretsmanager_secret_version": secretVersionSchema(),
	}

	changes := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret", Name: "b[0]", Change: "create", AttributeValues: map[string]string{"name": "example-b"}},
		{
			Type:       "aws_secretsmanager_secret_version",
			Name:       "b[0]",
			Change:     "create",
			References: map[string][]string{"secret_id": {"aws_secretsmanager_secret.b[0].id"}},
		},
	}

	policy, err := ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["secretsmanager:PutSecretValue", "secretsmanager:GetSecretValue"],
			"Resource": "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	missing, err := Validate(changes, policy, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	// The example-a grant must not cover the version on example-b.
	if !hasActionOn(missing, "secretsmanager:PutSecretValue", "aws_secretsmanager_secret_version", "b") {
		t.Errorf("expected PutSecretValue missing on indexed version b[0], got %+v", missing)
	}
}

func TestValidate_ResourceScopedCoverage_SecretItself(t *testing.T) {
	// aws_secretsmanager_secret resources are targets too: a grant on
	// example-a must not cover a secret named example-b, and DescribeSecret
	// (its create permission) must be reported missing for secret b only.
	schema := fakeSchema{
		perms: map[string][]string{
			"create": {"secretsmanager:DescribeSecret"},
		},
	}
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret", Name: "a", Change: "create", AttributeValues: map[string]string{"name": "example-a"}},
		{Type: "aws_secretsmanager_secret", Name: "b", Change: "create", AttributeValues: map[string]string{"name": "example-b"}},
	}

	policy, err := ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "secretsmanager:DescribeSecret",
			"Resource": "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	missing, err := Validate(changes, policy, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	// Secret b is not covered by the example-a grant.
	if !hasActionOn(missing, "secretsmanager:DescribeSecret", "aws_secretsmanager_secret", "b") {
		t.Errorf("expected DescribeSecret missing for secret b, got %+v", missing)
	}
	// Secret a IS covered by its own grant.
	if hasActionOn(missing, "secretsmanager:DescribeSecret", "aws_secretsmanager_secret", "a") {
		t.Errorf("expected DescribeSecret covered for secret a, got %+v", missing)
	}
}

func TestValidate_ResourceScopedCoverage_LiteralARNTarget(t *testing.T) {
	// A version whose secret_id is a literal ARN (imported/external secret)
	// derives the target directly from the plan value.
	schema := secretVersionSchema()
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{
			Type: "aws_secretsmanager_secret_version", Name: "b", Change: "create",
			AttributeValues: map[string]string{"secret_id": "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-b-abcdef"},
		},
	}

	policy, err := ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "secretsmanager:PutSecretValue",
			"Resource": "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	missing, err := Validate(changes, policy, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasActionOn(missing, "secretsmanager:PutSecretValue", "aws_secretsmanager_secret_version", "b") {
		t.Errorf("expected PutSecretValue missing for version on literal example-b ARN, got %+v", missing)
	}
}

func hasActionOn(missing []MissingAction, action, resType, resName string) bool {
	for _, m := range missing {
		if m.Action == action && m.ResourceType == resType && stripResourceIndex(m.ResourceName) == resName {
			return true
		}
	}
	return false
}
