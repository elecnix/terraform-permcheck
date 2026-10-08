package iam

import "testing"

// TestCovers_DenyOnEveryARN checks that a Deny whose Resource matches every
// ARN counts as definite when the target is unknown, like "*" does.
func TestCovers_DenyOnEveryARN(t *testing.T) {
	for _, resource := range []string{"*", "arn:*", "arn:aws:*", "arn:*:*"} {
		doc := mustPolicy(t, `{"Statement":[
			{"Effect":"Allow","Action":"kms:*","Resource":"*"},
			{"Effect":"Deny","Action":"kms:ScheduleKeyDeletion","Resource":"`+resource+`"}]}`)
		if doc.Covers("kms:ScheduleKeyDeletion") {
			t.Errorf("a Deny on %s must deny an unknown target", resource)
		}
	}
	for _, resource := range []string{"arn:aws:kms:*", "arn:aws:kms:us-east-1:*:key/*"} {
		doc := mustPolicy(t, `{"Statement":[
			{"Effect":"Allow","Action":"kms:*","Resource":"*"},
			{"Effect":"Deny","Action":"kms:ScheduleKeyDeletion","Resource":"`+resource+`"}]}`)
		if !doc.Covers("kms:ScheduleKeyDeletion") {
			t.Errorf("a Deny on %s cannot be shown to cover an unknown target", resource)
		}
	}
}

// TestCoversTarget_DenyNamingThePartition checks that a Deny that names the
// partition, with wildcards for the rest, applies to a target whose
// partition the plan does not show. The tool takes the policy to be written
// for the partition it deploys to.
func TestCoversTarget_DenyNamingThePartition(t *testing.T) {
	cases := []struct {
		resource string
		denied   bool
	}{
		{"arn:aws:sqs:*:*:*", true},
		{"arn:aws-us-gov:sqs:*:*:*", true},
		{"arn:aws:sqs:*:*:example-*", true},
		{"arn:*:sqs:*:*:*", true},
		{"arn:aws:*", true},
		{"arn:aws:sqs:us-east-1:*:*", false},
		{"arn:aws:sqs:*:111111111111:*", false},
		{"arn:aws:sqs:*:*:other-*", false},
		{"arn:aws:sns:*:*:*", false},
	}
	for _, c := range cases {
		doc := mustPolicy(t, `{"Statement":[
			{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
			{"Effect":"Deny","Action":"sqs:DeleteQueue","Resource":"`+c.resource+`"}]}`)
		if got := !doc.CoversTarget("sqs:DeleteQueue", queueTargets); got != c.denied {
			t.Errorf("Deny on %s: denied = %v, want %v", c.resource, got, c.denied)
		}
	}
}
