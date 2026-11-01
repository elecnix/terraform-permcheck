package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// TestLambdaInvocation_QualifierIsPartOfTheTarget checks which grant covers an
// invocation. A qualifier that names a version or an alias becomes part of the
// ARN, function:<name>:<qualifier>, and a grant on the bare function ARN does
// not match it -- matching the action name alone passes the plan and fails the
// apply with a 403. $LATEST is the exception: it is the default version, so an
// unqualified invoke and an explicit "$LATEST" both authorize against the bare
// function ARN.
func TestLambdaInvocation_QualifierIsPartOfTheTarget(t *testing.T) {
	const bare = "arn:aws:lambda:us-east-1:111111111111:function:app-fn"
	cases := []struct {
		name   string
		values map[string]string
		grant  string
		want   bool
	}{
		{"$LATEST, bare grant", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare, true},
		{"$LATEST, $LATEST grant", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare + ":$LATEST", false},
		// A trailing ":*" is treated as matching the unqualified ARN too, which is
		// permissive rather than exact: the matcher cannot prove it does not.
		{"$LATEST, any-qualifier grant", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare + ":*", true},
		{"$LATEST, other function", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare + "-other:$LATEST", false},
		{"$LATEST, prefix of the name", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, bare + "x:$LATEST", false},
		{"$LATEST, star", map[string]string{"function_name": "app-fn", "qualifier": "$LATEST"}, "*", true},
		{"alias, grant on $LATEST", map[string]string{"function_name": "app-fn", "qualifier": "live"}, bare + ":$LATEST", false},
		{"alias, grant on the alias", map[string]string{"function_name": "app-fn", "qualifier": "live"}, bare + ":live", true},
		{"version, grant on the version", map[string]string{"function_name": "app-fn", "qualifier": "7"}, bare + ":7", true},
		{"no qualifier, bare grant", map[string]string{"function_name": "app-fn"}, bare, true},
		{"no qualifier, qualified grant", map[string]string{"function_name": "app-fn"}, bare + ":$LATEST", false},
		{"function given as an ARN, $LATEST qualifier", map[string]string{"function_name": bare, "qualifier": "$LATEST"}, bare, true},
		{"function given as an ARN, $LATEST grant", map[string]string{"function_name": bare, "qualifier": "$LATEST"}, bare + ":$LATEST", false},
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
