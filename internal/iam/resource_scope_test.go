package iam

import (
	"errors"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// typeKeyedResolver serves a distinct schema per terraform resource type.
type typeKeyedResolver map[string]fakeSchema

func (r typeKeyedResolver) Resolve(t string) (*Schema, error) {
	s, ok := r[t]
	if !ok {
		return nil, errors.New("no schema")
	}
	return s.schema(), nil
}

// secretVersionSchema is the create permission set the source parser extracts
// for aws_secretsmanager_secret_version.
func secretVersionSchema() fakeSchema {
	return actionsSchema(map[string][]string{
		"create": {"secretsmanager:PutSecretValue", "secretsmanager:GetSecretValue"},
	})
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

	policy, err := policy.Parse([]byte(`{
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

	policy, err := policy.Parse([]byte(`{
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

	policy, err := policy.Parse([]byte(`{
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

	missing, err := Validate(changes, grantNothing(), resolver, FilterConfig{})
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
		"aws_secretsmanager_secret":         actionsSchema(map[string][]string{"create": {"secretsmanager:DescribeSecret"}}),
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

	policy, err := policy.Parse([]byte(`{
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
	schema := actionsSchema(map[string][]string{
		"create": {"secretsmanager:DescribeSecret"},
	})
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret", Name: "a", Change: "create", AttributeValues: map[string]string{"name": "example-a"}},
		{Type: "aws_secretsmanager_secret", Name: "b", Change: "create", AttributeValues: map[string]string{"name": "example-b"}},
	}

	policy, err := policy.Parse([]byte(`{
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

	policy, err := policy.Parse([]byte(`{
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
