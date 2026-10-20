package policy

import "testing"

// The ARN the issue's plan carries, and one the policy excludes.
const (
	mappedFunctionARN = "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer"
	otherFunctionARN  = "arn:aws:lambda:us-east-1:111122223333:function:example-other-consumer"
)

// functionContext is the request context the issue's plan gives: the
// mapping's function_name.
var functionContext = Conditions{"lambda:FunctionArn": mappedFunctionARN}

// conditionBlockOf decodes a Condition block for a test.
func conditionBlockOf(t *testing.T, raw string) conditionBlock {
	t.Helper()
	var block conditionBlock
	if err := block.UnmarshalJSON([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	return block
}

func TestMatchCondition_ArnOperators(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		context   Conditions
		want      conditionResult
	}{
		{
			name:      "ArnLike matching",
			condition: `{"ArnLike":{"lambda:FunctionArn":"` + mappedFunctionARN + `"}}`,
			context:   functionContext,
			want:      condHolds,
		},
		{
			name:      "ArnLike provably excluding",
			condition: `{"ArnLike":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`,
			context:   functionContext,
			want:      condFails,
		},
		{
			name:      "ArnLike wildcard that could match",
			condition: `{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:example-*"}}`,
			context:   functionContext,
			want:      condHolds,
		},
		{
			name:      "ArnLike wildcard that provably excludes",
			condition: `{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:other-*"}}`,
			context:   functionContext,
			want:      condFails,
		},
		{
			name:      "ArnEquals matching",
			condition: `{"ArnEquals":{"lambda:FunctionArn":"` + mappedFunctionARN + `"}}`,
			context:   functionContext,
			want:      condHolds,
		},
		{
			name:      "ArnEquals provably excluding",
			condition: `{"ArnEquals":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`,
			context:   functionContext,
			want:      condFails,
		},
		{
			name:      "ArnEquals is case-sensitive",
			condition: `{"ArnEquals":{"lambda:FunctionArn":"ARN:AWS:LAMBDA:us-east-1:111122223333:function:example-new-consumer"}}`,
			context:   functionContext,
			want:      condFails,
		},
		{
			name:      "a different account cannot match",
			condition: `{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:999988887777:function:example-*"}}`,
			context:   functionContext,
			want:      condFails,
		},
		{
			name:      "a different region cannot match",
			condition: `{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:eu-west-1:111122223333:function:example-*"}}`,
			context:   functionContext,
			want:      condFails,
		},
		{
			name:      "a bare function name is not an ARN",
			condition: `{"ArnLike":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`,
			context:   Conditions{"lambda:FunctionArn": "example-new-consumer"},
			want:      condUnknown,
		},
		{
			name:      "the plan does not supply the key",
			condition: `{"ArnLike":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`,
			context:   Conditions{},
			want:      condUnknown,
		},
		{
			name:      "the condition names another key",
			condition: `{"ArnLike":{"aws:SourceArn":"` + otherFunctionARN + `"}}`,
			context:   functionContext,
			want:      condUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchCondition(conditionBlockOf(t, tt.condition), tt.context)
			if got != tt.want {
				t.Errorf("matchCondition = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchCondition_StringOperators(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		context   Conditions
		want      conditionResult
	}{
		{
			name:      "StringEquals matching",
			condition: `{"StringEquals":{"lambda:FunctionArn":"` + mappedFunctionARN + `"}}`,
			context:   functionContext,
			want:      condHolds,
		},
		{
			name:      "StringEquals provably excluding",
			condition: `{"StringEquals":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`,
			context:   functionContext,
			want:      condFails,
		},
		{
			name:      "StringEquals is case-sensitive",
			condition: `{"StringEquals":{"lambda:FunctionArn":"EXAMPLE-NEW-CONSUMER"}}`,
			context:   Conditions{"lambda:FunctionArn": "example-new-consumer"},
			want:      condFails,
		},
		{
			// A wildcard pattern cannot be shown to be disjoint from
			// anything, so StringLike never proves a mismatch.
			name:      "StringLike matching",
			condition: `{"StringLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:example-*"}}`,
			context:   functionContext,
			want:      condHolds,
		},
		{
			name:      "StringLike never proves a mismatch",
			condition: `{"StringLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:other-*"}}`,
			context:   functionContext,
			want:      condHolds,
		},
		{
			name:      "StringLike with a plain value that differs",
			condition: `{"StringLike":{"lambda:FunctionArn":"other"}}`,
			context:   Conditions{"lambda:FunctionArn": "example-new-consumer"},
			want:      condHolds,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchCondition(conditionBlockOf(t, tt.condition), tt.context)
			if got != tt.want {
				t.Errorf("matchCondition = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchCondition_UnmodelledOperatorsAreUnknown(t *testing.T) {
	tests := []struct {
		name      string
		condition string
	}{
		{"StringLikeIfExists", `{"StringLikeIfExists":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`},
		{"ArnLikeIfExists", `{"ArnLikeIfExists":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`},
		{"ForAnyValue:ArnLike", `{"ForAnyValue:ArnLike":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`},
		{"ForAllValues:StringEquals", `{"ForAllValues:StringEquals":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`},
		{"ForAnyValue:StringEquals", `{"ForAnyValue:StringEquals":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`},
		{"Bool", `{"Bool":{"aws:SecureTransport":"false"}}`},
		{"NumericEquals", `{"NumericEquals":{"s3:max-keys":"10"}}`},
		{"DateEquals", `{"DateEquals":{"aws:CurrentTime":"2026-01-01T00:00:00Z"}}`},
		{"Null", `{"Null":{"lambda:FunctionArn":"false"}}`},
		{"StringNotEquals", `{"StringNotEquals":{"lambda:FunctionArn":"` + otherFunctionARN + `"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The context holds the key, so an unmodelled operator on
			// it is the only thing that keeps the verdict unknown.
			got := matchCondition(conditionBlockOf(t, tt.condition), functionContext)
			if got != condUnknown {
				t.Errorf("matchCondition = %v, want %v", got, condUnknown)
			}
		})
	}
}

func TestMatchCondition_KeyNamesAreCaseInsensitive(t *testing.T) {
	block := conditionBlockOf(t, `{"ArnLike":{"LAMBDA:functionarn":"`+otherFunctionARN+`"}}`)
	if got := matchCondition(block, functionContext); got != condFails {
		t.Errorf("matchCondition = %v, want %v", got, condFails)
	}
	upper := Conditions{"LAMBDA:FunctionARN": mappedFunctionARN}
	if got := matchCondition(block, upper); got != condFails {
		t.Errorf("matchCondition = %v, want %v", got, condFails)
	}
}

func TestMatchCondition_ListOfValues(t *testing.T) {
	// One value that can match holds the key, so the condition holds.
	block := conditionBlockOf(t, `{"ArnLike":{"lambda:FunctionArn":[`+
		`"`+otherFunctionARN+`","`+mappedFunctionARN+`"]}}`)
	if got := matchCondition(block, functionContext); got != condHolds {
		t.Errorf("matchCondition = %v, want %v", got, condHolds)
	}

	// Every value excluded means the condition cannot hold.
	block = conditionBlockOf(t, `{"ArnLike":{"lambda:FunctionArn":[`+
		`"`+otherFunctionARN+`","arn:aws:lambda:us-east-1:111122223333:function:third-consumer"]}}`)
	if got := matchCondition(block, functionContext); got != condFails {
		t.Errorf("matchCondition = %v, want %v", got, condFails)
	}

	// A value the tool cannot compare leaves the key unknown.
	block = conditionBlockOf(t, `{"ArnLike":{"lambda:FunctionArn":[`+
		`"arn:aws:lambda:us-east-1:111122223333:function:other-*","${aws:username}"]}}`)
	if got := matchCondition(block, functionContext); got != condUnknown {
		t.Errorf("matchCondition = %v, want %v", got, condUnknown)
	}
}

func TestMatchCondition_SeveralOperators(t *testing.T) {
	// A condition is a conjunction: one operator that cannot hold decides
	// the whole condition.
	block := conditionBlockOf(t, `{"StringEquals":{"aws:RequestedRegion":"us-east-1"},
		"ArnLike":{"lambda:FunctionArn":"`+otherFunctionARN+`"}}`)
	if got := matchCondition(block, functionContext); got != condFails {
		t.Errorf("matchCondition = %v, want %v", got, condFails)
	}

	// An operator the tool does not model leaves the condition unknown.
	block = conditionBlockOf(t, `{"Bool":{"aws:SecureTransport":"false"},
		"ArnLike":{"lambda:FunctionArn":"`+otherFunctionARN+`"}}`)
	if got := matchCondition(block, functionContext); got != condFails {
		t.Errorf("matchCondition = %v, want %v", got, condFails)
	}

	// A key the plan does not supply leaves the condition unknown.
	block = conditionBlockOf(t, `{"ArnLike":{"lambda:FunctionArn":"`+otherFunctionARN+`"}}`)
	if got := matchCondition(block, Conditions{}); got != condUnknown {
		t.Errorf("matchCondition = %v, want %v", got, condUnknown)
	}
}

func TestDecodeCondition_UnreadableBlockIsStillConditional(t *testing.T) {
	// A Condition that is not an object cannot be read, but the statement
	// is still conditional, so a Deny is still not definite.
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"*","Condition":"nonsense"}]}`)
	if !doc.Covers("sqs:SendMessage") {
		t.Error("a Deny with an unreadable Condition must not count as a definite deny")
	}

	// A Condition whose operator block is not an object is unreadable too.
	doc = mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":"nonsense"}}]}`)
	if !doc.Covers("sqs:SendMessage") {
		t.Error("a Deny with an unreadable Condition block must not count as a definite deny")
	}
}

func TestDecodeCondition_UnreadableValueLeavesTheKeyUnknown(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"a:b":42}}}]}`)
	block := doc.Statements[0].Condition
	keys, ok := block.keys["StringEquals"]
	if !ok {
		t.Fatal("the operator block must still be readable")
	}
	value, ok := keys["a:b"]
	if !ok {
		t.Fatal("the key must still be found")
	}
	if value.readable {
		t.Error("a number value must not be readable")
	}
	if got := matchCondition(block, Conditions{"a:b": "x"}); got != condUnknown {
		t.Errorf("matchCondition = %v, want %v", got, condUnknown)
	}
}

func TestMatchCondition_UndecidablePatternsAreUnknown(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		context   Conditions
	}{
		{
			// A policy variable the tool cannot expand.
			name:      "policy variable",
			condition: `{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:${aws:username}"}}`,
			context:   functionContext,
		},
		{
			// A cross-segment wildcard: the components do not line up.
			name:      "cross-segment wildcard",
			condition: `{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:*"}}`,
			context:   functionContext,
		},
		{
			// A pattern that is not an ARN at all.
			name:      "not an ARN",
			condition: `{"ArnLike":{"lambda:FunctionArn":"example-*"}}`,
			context:   functionContext,
		},
		{
			// The plan's value is not an ARN.
			name:      "the plan's value is not an ARN",
			condition: `{"ArnLike":{"lambda:FunctionArn":"arn:aws:lambda:us-east-1:111122223333:function:example-*"}}`,
			context:   Conditions{"lambda:FunctionArn": "example-new-consumer"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchCondition(conditionBlockOf(t, tt.condition), tt.context)
			if got != condUnknown {
				t.Errorf("matchCondition = %v, want %v", got, condUnknown)
			}
		})
	}
}

func TestMatchCondition_ResourcePartMayHoldColons(t *testing.T) {
	// A log group ARN has colons in its resource part. The six components
	// are compared on their own, so a pattern naming the same group
	// matches.
	value := "arn:aws:logs:us-east-1:111122223333:log-group:my-group:*"
	block := conditionBlockOf(t, `{"ArnLike":{"aws:ResourceArn":"arn:aws:logs:us-east-1:111122223333:log-group:my-group:*"}}`)
	if got := matchCondition(block, Conditions{"aws:ResourceArn": value}); got != condHolds {
		t.Errorf("matchCondition = %v, want %v", got, condHolds)
	}
	block = conditionBlockOf(t, `{"ArnLike":{"aws:ResourceArn":"arn:aws:logs:us-east-1:111122223333:log-group:other-group:*"}}`)
	if got := matchCondition(block, Conditions{"aws:ResourceArn": value}); got != condFails {
		t.Errorf("matchCondition = %v, want %v", got, condFails)
	}
}

func TestStatement_Conditional(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{}},
		{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"a:b":"c"}}}]}`)
	if doc.Statements[0].conditional() {
		t.Error("a statement with no Condition is not conditional")
	}
	if doc.Statements[1].conditional() {
		t.Error("an empty Condition block sets no condition")
	}
	if !doc.Statements[2].conditional() {
		t.Error("a statement with a Condition is conditional")
	}
}
