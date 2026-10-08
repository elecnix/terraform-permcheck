package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

func mustPolicy(t *testing.T, doc string) *policy.Document {
	t.Helper()
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidate_SQSGrantOnOtherQueueIsMissing(t *testing.T) {
	resolver := fakeResolver{actionsSchema(map[string][]string{
		"create": {"sqs:CreateQueue", "sqs:ListQueueTags"},
	})}
	changes := []*plan.ResourceChange{{
		Type: "aws_sqs_queue", Name: "new", Change: "create",
		AttributeValues: map[string]string{"name": "example-new-queue"},
	}}

	other := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs:us-east-1:111122223333:example-other-queue"}]}`)
	missing, err := Validate(changes, other, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasActionOn(missing, "sqs:ListQueueTags", "aws_sqs_queue", "new") {
		t.Errorf("expected sqs:ListQueueTags missing, got %+v", missing)
	}

	same := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs:us-east-1:111122223333:example-new-queue"}]}`)
	missing, err = Validate(changes, same, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("grant on the target queue must cover, got %+v", missing)
	}
}

func lambdaChange(role string) *plan.ResourceChange {
	return &plan.ResourceChange{
		Type: "aws_lambda_function", Name: "fn", Change: "create",
		AttributeValues: map[string]string{"role": role},
	}
}

func TestPassRoleMissing_GrantOnDifferentRole(t *testing.T) {
	rc := lambdaChange("arn:aws:iam::111122223333:role/example-fn-role")
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:*","Resource":"*"},
		{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/example-other-role"}]}`)

	missing := impliedMissing(rc, policy, newChangeSet([]*plan.ResourceChange{rc}), false)
	if !hasActionOn(missing, "iam:PassRole", "aws_lambda_function", "fn") {
		t.Fatalf("expected iam:PassRole missing, got %+v", missing)
	}
	if missing[0].ConditionAttribute != "" {
		t.Errorf("a known role makes PassRole unconditional, got gate %q", missing[0].ConditionAttribute)
	}
}

func TestPassRoleMissing_Covered(t *testing.T) {
	rc := lambdaChange("arn:aws:iam::111122223333:role/example-fn-role")
	for name, doc := range map[string]string{
		"exact":    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/example-fn-role"}]}`,
		"wildcard": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`,
		"prefix":   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::111122223333:role/example-fn-*"}]}`,
	} {
		if m := impliedMissing(rc, mustPolicy(t, doc), newChangeSet([]*plan.ResourceChange{rc}), false); len(m) != 0 {
			t.Errorf("%s: expected covered, got %+v", name, m)
		}
	}
}

func TestPassRoleMissing_NoGrantAtAll(t *testing.T) {
	rc := lambdaChange("arn:aws:iam::111122223333:role/example-fn-role")
	if m := impliedMissing(rc, grantNothing(), nil, false); len(m) != 1 {
		t.Errorf("expected PassRole missing without any grant, got %+v", m)
	}
}

func TestPassRoleMissing_ManagedRoleReference(t *testing.T) {
	role := &plan.ResourceChange{
		Type: "aws_iam_role", Name: "fn", Change: "create",
		AttributeValues: map[string]string{"name": "example-fn-role"},
	}
	fn := &plan.ResourceChange{
		Type: "aws_lambda_function", Name: "fn", Change: "create",
		AttributeValues: map[string]string{},
		References:      map[string][]string{"role": {"aws_iam_role.fn.arn", "aws_iam_role.fn"}},
	}
	all := []*plan.ResourceChange{role, fn}

	other := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/example-other-role"}]}`)
	if m := impliedMissing(fn, other, newChangeSet(all), false); len(m) != 1 {
		t.Errorf("expected PassRole missing for other role, got %+v", m)
	}
	pathed := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/app/example-fn-role"}]}`)
	if m := impliedMissing(fn, pathed, newChangeSet(all), false); len(m) != 0 {
		t.Errorf("a role under a path must still match, got %+v", m)
	}
}

// A role the plan does not show still needs a PassRole grant on some role.
// A policy with none provably misses it.
func TestPassRoleMissing_UnknownRoleWithoutAnyGrant(t *testing.T) {
	set := &plan.ResourceChange{
		Type: "aws_lambda_function", Name: "fn", Change: "create",
		AttributeValues: map[string]string{},
		Attributes:      map[string]bool{"role": true},
	}
	m := impliedMissing(set, grantNothing(), nil, false)
	if !hasActionOn(m, "iam:PassRole", "aws_lambda_function", "fn") {
		t.Fatalf("a set role with no PassRole grant must be missing, got %+v", m)
	}
	if m[0].ConditionAttribute != "" || m[0].ResourceScopeUnverified {
		t.Errorf("want a plain missing finding, got %+v", m[0])
	}

	referenced := &plan.ResourceChange{
		Type: "aws_lambda_function", Name: "fn", Change: "create",
		References: map[string][]string{"role": {"var.role_arn"}},
	}
	if m := impliedMissing(referenced, grantNothing(), nil, false); !hasAction(m, "iam:PassRole") {
		t.Errorf("a referenced role with no PassRole grant must be missing, got %+v", m)
	}

	// A grant on some role may cover the unknown one.
	scoped := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/app-*"}]}`)
	if m := impliedMissing(set, scoped, nil, false); len(m) != 0 {
		t.Errorf("a scoped grant on an unknown role is not provably missing, got %+v", m)
	}
}

// When the plan does not say which attributes are set, the resource may
// pass no role, so nothing is reported.
func TestPassRoleMissing_UnknownPresenceIsSilent(t *testing.T) {
	rc := &plan.ResourceChange{Type: "aws_lambda_function", Name: "fn", Change: "create", AttributeValues: map[string]string{}}
	if m := impliedMissing(rc, grantNothing(), nil, false); len(m) != 0 {
		t.Errorf("unknown presence must not be reported, got %+v", m)
	}
}

func TestPassRoleMissing_DeleteNeedsNoPassRole(t *testing.T) {
	rc := lambdaChange("arn:aws:iam::111122223333:role/example-fn-role")
	rc.Change = "delete"
	if m := impliedMissing(rc, grantNothing(), nil, false); len(m) != 0 {
		t.Errorf("delete must not require PassRole, got %+v", m)
	}
}
