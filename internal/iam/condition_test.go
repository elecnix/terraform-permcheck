package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// The issue's plan and policy: a Lambda event source mapping whose function
// the policy's condition excludes.
const (
	mappedFunctionARN = "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer"
	otherFunctionARN  = "arn:aws:lambda:us-east-1:111122223333:function:example-other-consumer"
)

// eventSourceMappingResolver requires the actions of an event source
// mapping.
var eventSourceMappingResolver = fakeResolver{actionsSchema(map[string][]string{
	"create": {"lambda:CreateEventSourceMapping"},
})}

// eventSourceMappingChange is the issue's resource change, with the
// function_name the plan shows.
func eventSourceMappingChange(functionName string) []*plan.ResourceChange {
	rc := &plan.ResourceChange{
		Type: "aws_lambda_event_source_mapping", Name: "events", Change: "create",
	}
	if functionName != "" {
		rc.AttributeValues = map[string]string{"function_name": functionName}
	}
	return []*plan.ResourceChange{rc}
}

// TestValidate_ConditionExcludesThePlannedFunction is the issue's
// reproduction: a grant whose condition names another function does not
// cover the mapping, so the action is missing.
func TestValidate_ConditionExcludesThePlannedFunction(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":{"ArnLike":{"lambda:FunctionArn":"`+otherFunctionARN+`"}}}]}`)

	missing, err := Validate(eventSourceMappingChange(mappedFunctionARN), policy, eventSourceMappingResolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].Action != "lambda:CreateEventSourceMapping" {
		t.Fatalf("a condition that excludes the planned function must be missing, got %+v", missing)
	}
	if missing[0].ConditionUnverified || missing[0].ResourceScopeUnverified {
		t.Errorf("a provable gap is missing, not unverified, got %+v", missing[0])
	}
}

// TestValidate_ConditionMatchesThePlannedFunction is the control: the same
// policy with a condition that covers the function leaves the action
// covered.
func TestValidate_ConditionMatchesThePlannedFunction(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:example-*"}}}]}`)

	missing, err := Validate(eventSourceMappingChange(mappedFunctionARN), policy, eventSourceMappingResolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("a condition that covers the planned function leaves the action covered, got %+v", missing)
	}
}

// TestValidate_ConditionOnAnUnknownKeyIsUnverified checks the strict-mode
// half: a condition the tool cannot evaluate is covered by default and
// unverified under --strict-resources.
func TestValidate_ConditionOnAnUnknownKeyIsUnverified(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)

	missing, err := Validate(eventSourceMappingChange(mappedFunctionARN), policy, eventSourceMappingResolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("without strict mode an unevaluable condition covers, got %+v", missing)
	}

	missing, err = Validate(eventSourceMappingChange(mappedFunctionARN), policy, eventSourceMappingResolver, strictFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 {
		t.Fatalf("strict mode must report the unevaluable condition, got %+v", missing)
	}
	if !missing[0].ConditionUnverified {
		t.Errorf("strict mode must report the grant unverified on the condition, got %+v", missing[0])
	}
	if missing[0].ResourceScopeUnverified {
		t.Errorf("the reason is the condition, not the resource scope, got %+v", missing[0])
	}
}

// TestValidate_ConditionOnAValueThePlanDoesNotShow checks the same for a
// key the plan knows about but whose value it cannot show: the function name
// is computed at apply time.
func TestValidate_ConditionOnAValueThePlanDoesNotShow(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":{"ArnLike":{"lambda:FunctionArn":"`+otherFunctionARN+`"}}}]}`)

	// The plan does not show the function, so the tool cannot compare the
	// condition with it.
	missing, err := Validate(eventSourceMappingChange(""), policy, eventSourceMappingResolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("without strict mode an uncomputed function covers, got %+v", missing)
	}

	missing, err = Validate(eventSourceMappingChange(""), policy, eventSourceMappingResolver, strictFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || !missing[0].ConditionUnverified {
		t.Errorf("strict mode must report the uncomputed function unverified, got %+v", missing)
	}
}

// TestValidate_ConditionOnABareFunctionName checks that a function name
// that is not an ARN is unknown, not a mismatch: terraform's function_name
// may hold a name rather than an ARN.
func TestValidate_ConditionOnABareFunctionName(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":{"ArnLike":{"lambda:FunctionArn":"`+otherFunctionARN+`"}}}]}`)

	missing, err := Validate(eventSourceMappingChange("example-new-consumer"), policy, eventSourceMappingResolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("a bare function name is not comparable, so it must not be a gap, got %+v", missing)
	}
}

// TestValidate_ConditionalDenyStaysNonDefinite pins that evaluating a
// condition does not turn a conditional Deny into a definite one: the tool
// cannot know whether the condition holds.
func TestValidate_ConditionalDenyStaysNonDefinite(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*"},
		{"Effect":"Deny","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		 "Condition":{"ArnLike":{"lambda:FunctionArn":"`+mappedFunctionARN+`"}}}]}`)

	missing, err := Validate(eventSourceMappingChange(mappedFunctionARN), policy, eventSourceMappingResolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("a conditional Deny must not count as a definite deny, got %+v", missing)
	}
}

// TestValidate_UnconditionalGrantStillCovers checks that a grant without a
// condition is unaffected.
func TestValidate_UnconditionalGrantStillCovers(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*"}]}`)

	missing, err := Validate(eventSourceMappingChange(mappedFunctionARN), policy, eventSourceMappingResolver, strictFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("an unconditional grant covers, got %+v", missing)
	}
}

// TestConditionValues checks the table end to end: the value comes from the
// plan attribute the rule names, and only an ARN counts.
func TestConditionValues(t *testing.T) {
	rule := resourceRules["aws_lambda_event_source_mapping"]

	values := conditionValues(&plan.ResourceChange{
		AttributeValues: map[string]string{"function_name": mappedFunctionARN},
	}, rule, "lambda:CreateEventSourceMapping")
	if got := values["lambda:FunctionArn"]; got != mappedFunctionARN {
		t.Errorf("condition value = %q, want %q", got, mappedFunctionARN)
	}

	// A bare function name is not an ARN, so the key stays unknown.
	values = conditionValues(&plan.ResourceChange{
		AttributeValues: map[string]string{"function_name": "example-new-consumer"},
	}, rule, "lambda:CreateEventSourceMapping")
	if len(values) != 0 {
		t.Errorf("a bare function name must not be a condition value, got %+v", values)
	}

	// Another action has no condition key.
	values = conditionValues(&plan.ResourceChange{
		AttributeValues: map[string]string{"function_name": mappedFunctionARN},
	}, rule, "lambda:GetEventSourceMapping")
	if len(values) != 0 {
		t.Errorf("an action with no condition key must have no values, got %+v", values)
	}
}
