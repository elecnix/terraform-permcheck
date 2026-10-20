package policy

import "testing"

// TestArnPatternsIntersect checks the ARN comparison on its own. The
// pattern is the policy's value, the value is the plan's.
//
// A decidable false means the pattern provably cannot match, which is what
// turns a grant into a reported gap. An undecidable answer must never be
// false: the tool reports only provable gaps.
func TestArnPatternsIntersect(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		value     string
		may       bool
		decidable bool
	}{
		{
			name:      "identical",
			pattern:   "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       true,
			decidable: true,
		},
		{
			name:      "wildcard matches",
			pattern:   "arn:aws:lambda:us-east-1:111122223333:function:example-*",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       true,
			decidable: true,
		},
		{
			name:      "a different function cannot match",
			pattern:   "arn:aws:lambda:us-east-1:111122223333:function:example-other-consumer",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       false,
			decidable: true,
		},
		{
			name:      "a different account cannot match",
			pattern:   "arn:aws:lambda:us-east-1:999988887777:function:example-*",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       false,
			decidable: true,
		},
		{
			name:      "a different region cannot match",
			pattern:   "arn:aws:lambda:eu-west-1:111122223333:function:example-*",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       false,
			decidable: true,
		},
		{
			name:      "a different service cannot match",
			pattern:   "arn:aws:s3:us-east-1:111122223333:function:example-*",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       false,
			decidable: true,
		},
		{
			name:      "the resource part may hold colons",
			pattern:   "arn:aws:logs:us-east-1:111122223333:log-group:my-group:*",
			value:     "arn:aws:logs:us-east-1:111122223333:log-group:my-group:log-stream:one",
			may:       true,
			decidable: true,
		},
		{
			name:      "a different log group cannot match",
			pattern:   "arn:aws:logs:us-east-1:111122223333:log-group:other-group:*",
			value:     "arn:aws:logs:us-east-1:111122223333:log-group:my-group:log-stream:one",
			may:       false,
			decidable: true,
		},
		{
			name:      "a policy variable is undecidable",
			pattern:   "arn:aws:lambda:us-east-1:111122223333:function:${aws:username}",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       true,
			decidable: false,
		},
		{
			name:      "a cross-segment wildcard is undecidable",
			pattern:   "arn:aws:lambda:*",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       true,
			decidable: false,
		},
		{
			name:      "a pattern that is not an ARN is undecidable",
			pattern:   "example-*",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       true,
			decidable: false,
		},
		{
			name:      "a value that is not an ARN is undecidable",
			pattern:   "arn:aws:lambda:us-east-1:111122223333:function:example-*",
			value:     "example-new-consumer",
			may:       true,
			decidable: false,
		},
		{
			name:      "a star pattern matches everything",
			pattern:   "*",
			value:     "arn:aws:lambda:us-east-1:111122223333:function:example-new-consumer",
			may:       true,
			decidable: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			may, decidable := arnPatternsIntersect(tt.pattern, tt.value)
			if may != tt.may || decidable != tt.decidable {
				t.Errorf("arnPatternsIntersect(%q, %q) = (%v, %v), want (%v, %v)",
					tt.pattern, tt.value, may, decidable, tt.may, tt.decidable)
			}
		})
	}
}
