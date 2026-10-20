package policy

import "testing"

// The condition the issue's policy carries, and the context the issue's
// plan gives.
const issueCondition = `{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:example-other-consumer"}}`

// issueContext is the request context the issue's plan gives.
var issueContext = Conditions{"lambda:FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer"}

// TestCoverage_ConditionCannotMatchIsMissing checks the provable part: a
// condition that cannot match the plan's value means the grant does not
// apply, so the action is missing.
func TestCoverage_ConditionCannotMatchIsMissing(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":`+issueCondition+`}]}`)

	res := doc.Coverage("lambda:CreateEventSourceMapping", nil, issueContext, false)
	if res.Verdict != Missing {
		t.Errorf("Coverage = %v, want %v", res.Verdict, Missing)
	}
}

// TestCoverage_ConditionCanMatchIsCovered checks that a condition the
// policy's value can match leaves the action covered.
func TestCoverage_ConditionCanMatchIsCovered(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:example-*"}}}]}`)

	res := doc.Coverage("lambda:CreateEventSourceMapping", nil, issueContext, false)
	if res.Verdict != Covered {
		t.Errorf("Coverage = %v, want %v", res.Verdict, Covered)
	}
}

// TestCoverage_UnevaluableConditionIsUnverifiedUnderStrict checks the
// unverifiable part: a condition the tool cannot evaluate covers by
// default and is unverified under --strict-resources.
func TestCoverage_UnevaluableConditionIsUnverifiedUnderStrict(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)

	res := doc.Coverage("lambda:CreateEventSourceMapping", nil, issueContext, false)
	if res.Verdict != Covered {
		t.Errorf("without strict mode an unevaluable condition covers, got %v", res.Verdict)
	}

	res = doc.Coverage("lambda:CreateEventSourceMapping", nil, issueContext, true)
	if res.Verdict != Unverified {
		t.Errorf("strict mode must report the unevaluable condition, got %v", res.Verdict)
	}
	if res.Reason != ReasonCondition {
		t.Errorf("reason = %v, want %v", res.Reason, ReasonCondition)
	}
}

// TestCoverage_ResourceScopeReasonIsKept checks that the resource-scope
// reason is still reported for a grant scoped to resources whose ARN the
// plan does not show.
func TestCoverage_ResourceScopeReasonIsKept(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"arn:aws:lambda:*:*:function:app-*"}]}`)

	res := doc.Coverage("lambda:CreateFunction", nil, nil, true)
	if res.Verdict != Unverified {
		t.Errorf("strict mode must report the scoped grant unverified, got %v", res.Verdict)
	}
	if res.Reason != ReasonResourceScope {
		t.Errorf("reason = %v, want %v", res.Reason, ReasonResourceScope)
	}
}

// TestCoverage_ConditionalDenyIsNeverDefinite pins that evaluating a
// condition does not turn a conditional Deny into a definite one.
func TestCoverage_ConditionalDenyIsNeverDefinite(t *testing.T) {
	// The condition names the very value the plan supplies, so the Deny
	// would apply if the tool treated a conditional Deny as definite.
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*"},
		{"Effect":"Deny","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer"}}}]}`)

	res := doc.Coverage("lambda:CreateEventSourceMapping", nil, issueContext, false)
	if res.Verdict != Covered {
		t.Errorf("a conditional Deny must not count as a definite deny, got %v", res.Verdict)
	}
}

// TestCoverage_UnconditionalGrantSettlesTheAction checks that a grant on
// every resource with no condition covers, whatever else the policy holds.
func TestCoverage_UnconditionalGrantSettlesTheAction(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"arn:aws:lambda:*:*:function:app-*"},
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*"}]}`)

	res := doc.Coverage("lambda:CreateEventSourceMapping", nil, issueContext, true)
	if res.Verdict != Covered {
		t.Errorf("a grant on every resource covers, got %v", res.Verdict)
	}
}
