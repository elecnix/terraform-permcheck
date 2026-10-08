package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// role is a planned aws_iam_role instance.
func role(module, name, key, roleName string) *plan.ResourceChange {
	addr := "aws_iam_role." + name + key
	if module != "" {
		addr = module + "." + addr
	}
	return &plan.ResourceChange{
		Type: "aws_iam_role", Name: name, Change: "create",
		Address: addr, ModuleAddress: module,
		AttributeValues: map[string]string{"name": roleName, "path": "/"},
	}
}

// lambdaReferencing is a root-module aws_lambda_function whose role is
// computed from the references.
func lambdaReferencing(refs ...string) *plan.ResourceChange {
	return &plan.ResourceChange{
		Type: "aws_lambda_function", Name: "f", Change: "create", Address: "aws_lambda_function.f",
		Attributes: map[string]bool{"role": false},
		References: map[string][]string{"role": refs},
	}
}

const passOnlyAllowed = `{"Version":"2012-10-17","Statement":[
	{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111111111111:role/allowed"}]}`

func TestPassRole_ReferenceResolution(t *testing.T) {
	cases := []struct {
		name    string
		changes []*plan.ResourceChange
		missing bool
	}{
		{
			// The root lambda references the root role. A same-named role in
			// a module does not stand in for it.
			name: "same module only",
			changes: []*plan.ResourceChange{
				lambdaReferencing("aws_iam_role.r.arn", "aws_iam_role.r"),
				role("", "r", "", "denied"),
				role("module.m", "r", "", "allowed"),
			},
			missing: true,
		},
		{
			name: "module role ignored when root role allowed",
			changes: []*plan.ResourceChange{
				lambdaReferencing("aws_iam_role.r.arn", "aws_iam_role.r"),
				role("", "r", "", "allowed"),
				role("module.m", "r", "", "denied"),
			},
		},
		{
			// An indexed reference picks that instance only.
			name: "instance index kept",
			changes: []*plan.ResourceChange{
				lambdaReferencing("aws_iam_role.r[1].arn", "aws_iam_role.r[1]", "aws_iam_role.r"),
				role("", "r", "[0]", "allowed"),
				role("", "r", "[1]", "denied"),
			},
			missing: true,
		},
		{
			name: "other instance not consulted",
			changes: []*plan.ResourceChange{
				lambdaReferencing(`aws_iam_role.r["a"].arn`, `aws_iam_role.r["a"]`, "aws_iam_role.r"),
				role("", "r", `["a"]`, "allowed"),
				role("", "r", `["b"]`, "denied"),
			},
		},
		{
			// A reference without an index, such as r[count.index], may
			// reach every instance, so each must be covered.
			name: "every resolved target covered",
			changes: []*plan.ResourceChange{
				lambdaReferencing("aws_iam_role.r", "count.index"),
				role("", "r", "[0]", "allowed"),
				role("", "r", "[1]", "denied"),
			},
			missing: true,
		},
	}
	policy := mustPolicy(t, passOnlyAllowed)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := passRoleMissing(c.changes[0], policy, c.changes, false)
			if (len(got) > 0) != c.missing {
				t.Errorf("missing = %+v, want missing %v", got, c.missing)
			}
		})
	}
}

// TestSecretVersion_EverySecretCovered checks the same rules for the
// resource-scoped targets of Validate: a secret version that may write to two
// secrets needs a grant on both.
func TestSecretVersion_EverySecretCovered(t *testing.T) {
	secret := func(key, name string) *plan.ResourceChange {
		return &plan.ResourceChange{
			Type: "aws_secretsmanager_secret", Name: "s", Change: "create",
			Address:         "aws_secretsmanager_secret.s" + key,
			AttributeValues: map[string]string{"name": name},
		}
	}
	version := &plan.ResourceChange{
		Type: "aws_secretsmanager_secret_version", Name: "v", Change: "create",
		Address:    "aws_secretsmanager_secret_version.v",
		References: map[string][]string{"secret_id": {"aws_secretsmanager_secret.s"}},
	}
	changes := []*plan.ResourceChange{version, secret("[0]", "app-a"), secret("[1]", "app-b")}
	resolver := typeKeyedResolver{"aws_secretsmanager_secret_version": actionsSchema(map[string][]string{"create": {"secretsmanager:PutSecretValue"}})}
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"secretsmanager:PutSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:111111111111:secret:app-a-??????"}]}`)
	missing, err := Validate(changes, policy, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasActionOn(missing, "secretsmanager:PutSecretValue", "aws_secretsmanager_secret_version", "v") {
		t.Errorf("want PutSecretValue missing for secret app-b, got %+v", missing)
	}
}
