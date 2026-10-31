package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// TestLambdaInvocation_QualifierIsPartOfTheTarget checks that a grant on a
// function's bare ARN does not cover an invocation that carries a qualifier.
// aws_lambda_invocation defaults the qualifier to $LATEST, and IAM checks that
// call against function:<name>:$LATEST. Matching the action name alone passes
// the plan and fails the apply with a 403.
func TestLambdaInvocation_QualifierIsPartOfTheTarget(t *testing.T) {
	const bare = "arn:aws:lambda:us-east-1:111111111111:function:app-fn"
	cases := []struct {
		name   string
		values map[string]string
		grant  string
		want   bool
	}{
		{"default qualifier, bare grant", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare, false},
		{"default qualifier, exact grant", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare + ":$LATEST", true},
		{"default qualifier, any-qualifier grant", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare + ":*", true},
		{"default qualifier, other function", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare + "-other:$LATEST", false},
		{"default qualifier, prefix of the name", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare + "x:$LATEST", false},
		{"default qualifier, star", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, "*", true},
		{"alias, grant on $LATEST", map[string]string{"function_name": "app-fn", "qualifier": "live"}, bare + ":$LATEST", false},
		{"alias, grant on the alias", map[string]string{"function_name": "app-fn", "qualifier": "live"}, bare + ":live", true},
		{"no qualifier, bare grant", map[string]string{"function_name": "app-fn"}, bare, true},
		{"no qualifier, qualified grant", map[string]string{"function_name": "app-fn"}, bare + ":$LATEST", false},
		{"function given as an ARN", map[string]string{"function_name": bare, "qualifier": "$LATEST"}, bare, false},
		{"function given as an ARN, exact grant", map[string]string{"function_name": bare, "qualifier": "$LATEST"}, bare + ":$LATEST", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := &plan.ResourceChange{
				Type: "aws_lambda_invocation", Name: "i", Change: "create",
				AttributeValues: c.values,
			}
			targets := resourceTargets(inv, newChangeSet([]*plan.ResourceChange{inv}))
			doc := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"`+c.grant+`"}]}`)
			got := doc.WorstVerdict("lambda:InvokeFunction", targets, nil, false).Verdict == policy.Covered
			if got != c.want {
				t.Errorf("grant %s covers the invocation = %v, want %v (targets %v)", c.grant, got, c.want, targets)
			}
		})
	}
}

// TestLambdaInvocation_UnknownFunctionFallsBackToTheAction checks that a
// function name the plan does not show leaves coverage to the action alone,
// as it does for every type whose target cannot be derived.
func TestLambdaInvocation_UnknownFunctionFallsBackToTheAction(t *testing.T) {
	inv := &plan.ResourceChange{
		Type: "aws_lambda_invocation", Name: "i", Change: "create",
		AttributeValues: map[string]string{"qualifier": "$LATEST"},
	}
	if targets := resourceTargets(inv, newChangeSet([]*plan.ResourceChange{inv})); targets != nil {
		t.Errorf("targets = %v, want nil", targets)
	}
}
