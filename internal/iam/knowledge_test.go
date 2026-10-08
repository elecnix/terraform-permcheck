package iam

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// A callback is an action AWS checks, not one a producer emits, so its name
// is checked against the AWS service reference. IAM matches action names
// without regard to case.
func TestCallbacks_EveryNameIsAnIAMAction(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/aws/service-reference-actions.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string][]string `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, rule := range resourceRules {
		if rule.callbacks == nil {
			continue
		}
		for _, cb := range rule.callbacks.callbacks {
			svc, name, _ := strings.Cut(cb.action, ":")
			names, ok := doc.Services[svc]
			if !ok {
				t.Errorf("callback %q is in a service the fixture does not list; add it", cb.action)
				continue
			}
			if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, name) }) {
				t.Errorf("callback %q is not an IAM action of %s", cb.action, svc)
			}
			if cb.targetService != svc {
				t.Errorf("callback %q is selected by %s ARNs", cb.action, cb.targetService)
			}
		}
	}
}

// Each action name has one row, so two rules cannot disagree about it.
func TestRules_OneRowPerName(t *testing.T) {
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seen[r.action] {
			t.Errorf("rule %q appears twice", r.action)
		}
		seen[r.action] = true
		if _, ok := serviceClasses[actionService(r.action)]; ok {
			t.Errorf("rule %q is in a service that serviceClasses already classifies", r.action)
		}
	}
}

func TestRules_EveryRowClassifiesAsItSays(t *testing.T) {
	for _, r := range rules {
		if got := actionClass(r.action); got != r.class {
			t.Errorf("actionClass(%q) = %d, want %d", r.action, got, r.class)
		}
	}
}

// Only an aws_s3_bucket_* type can own an action, and only an S3 one: decide
// hands actions over from aws_s3_bucket alone.
func TestRules_OwnerIsAnS3Subresource(t *testing.T) {
	for _, r := range rules {
		if r.ownedBy == "" {
			continue
		}
		if !strings.HasPrefix(r.ownedBy, "aws_s3_bucket_") || actionService(r.action) != "s3" {
			t.Errorf("rule %q is owned by %q, want an S3 action owned by an aws_s3_bucket_* type", r.action, r.ownedBy)
		}
	}
}

func TestActionClass_UnknownIsManagement(t *testing.T) {
	for _, a := range []string{"ec2:RunInstances", "nosuchservice:Thing", "noservice"} {
		if got := actionClass(a); got != ClassManagement {
			t.Errorf("actionClass(%q) = %d, want ClassManagement", a, got)
		}
	}
}

func TestDecide_BestEffortDowngradesOnlyManagement(t *testing.T) {
	tests := []struct {
		action string
		want   Class
	}{
		{"s3:CreateBucket", ClassOptional},
		{"s3:GetObject", ClassDataPlane},
		{"s3:PutBucketVersioning", ClassOptional},
	}
	for _, tt := range tests {
		if got := decide("aws_s3_bucket", tt.action, true, false, nil).class; got != tt.want {
			t.Errorf("decide(aws_s3_bucket, %q, bestEffort).class = %d, want %d", tt.action, got, tt.want)
		}
	}
}
