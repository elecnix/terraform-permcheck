package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// TestApplyExclusions_ModuleAddress verifies that a resource pattern is
// matched against the full address, module included. A pattern written
// without a module names the root module only; a type pattern still matches
// the type in every module.
func TestApplyExclusions_ModuleAddress(t *testing.T) {
	root := MissingAction{ResourceType: "aws_sqs_queue", ResourceName: "q", Change: "delete", Action: "sqs:DeleteQueue"}
	prod := MissingAction{ModuleAddress: "module.prod", ResourceType: "aws_sqs_queue", ResourceName: "q", Change: "delete", Action: "sqs:DeleteQueue"}
	indexed := MissingAction{ModuleAddress: `module.app["eu"]`, ResourceType: "aws_sqs_queue", ResourceName: "q[0]", Change: "delete", Action: "sqs:DeleteQueue"}
	all := []MissingAction{root, prod, indexed}

	for _, tc := range []struct {
		pattern string
		want    []string // addresses excluded
	}{
		{"aws_sqs_queue.q", []string{"aws_sqs_queue.q"}},
		{"aws_sqs_queue.*", []string{"aws_sqs_queue.q"}},
		{"module.prod.aws_sqs_queue.q", []string{"module.prod.aws_sqs_queue.q"}},
		{"module.*.aws_sqs_queue.q", []string{"module.prod.aws_sqs_queue.q", `module.app["eu"].aws_sqs_queue.q[0]`}},
		{"*aws_sqs_queue.q", []string{"aws_sqs_queue.q", "module.prod.aws_sqs_queue.q", `module.app["eu"].aws_sqs_queue.q[0]`}},
		{"aws_sqs_queue", []string{"aws_sqs_queue.q", "module.prod.aws_sqs_queue.q", `module.app["eu"].aws_sqs_queue.q[0]`}},
	} {
		_, excluded := ApplyExclusions(all, []Exclusion{{Permission: "sqs:DeleteQueue", Resource: tc.pattern}})
		var got []string
		for _, e := range excluded {
			got = append(got, e.Address())
		}
		if len(got) != len(tc.want) {
			t.Errorf("%q excluded %v, want %v", tc.pattern, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%q excluded %v, want %v", tc.pattern, got, tc.want)
				break
			}
		}
	}
}

// TestValidate_NoOpIsContextOnly verifies that an unchanged resource needs
// no permission, yet a change referencing it still derives its target ARN
// from it.
func TestValidate_NoOpIsContextOnly(t *testing.T) {
	resolver := typeKeyedResolver{
		"aws_secretsmanager_secret":         actionsSchema(map[string][]string{"create": {"secretsmanager:CreateSecret"}}),
		"aws_secretsmanager_secret_version": secretVersionSchema(),
	}
	changes := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret", Name: "b", Change: plan.NoOp, AttributeValues: map[string]string{"name": "example-b"}},
		{
			Type:       "aws_secretsmanager_secret_version",
			Name:       "b",
			Change:     "create",
			References: map[string][]string{"secret_id": {"aws_secretsmanager_secret.b.id"}},
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
	for _, m := range missing {
		if m.ResourceType == "aws_secretsmanager_secret" {
			t.Errorf("no-op secret reported: %+v", m)
		}
	}
	if !hasActionOn(missing, "secretsmanager:PutSecretValue", "aws_secretsmanager_secret_version", "b") {
		t.Errorf("expected PutSecretValue missing on the version of the unchanged secret, got %+v", missing)
	}
}

// TestValidate_CarriesModuleAddress verifies that a finding names the module
// of the resource change it comes from.
func TestValidate_CarriesModuleAddress(t *testing.T) {
	resolver := typeKeyedResolver{
		"aws_sqs_queue": actionsSchema(map[string][]string{"delete": {"sqs:DeleteQueue"}}),
	}
	changes := []*plan.ResourceChange{{ModuleAddress: "module.prod", Type: "aws_sqs_queue", Name: "q", Change: "delete"}}
	policy, err := ParsePolicy([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	missing, err := Validate(changes, policy, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].Address() != "module.prod.aws_sqs_queue.q" {
		t.Errorf("missing = %+v, want sqs:DeleteQueue on module.prod.aws_sqs_queue.q", missing)
	}
}
