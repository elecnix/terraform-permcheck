package iam

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// Golden lists of the actions each producer emits, for the services that have
// rules. The CloudFormation list comes from every schema in the registry, the
// parser list from every resource in the provider checkout.
var emittedActionFixtures = []string{
	"../../testdata/cfn/emitted-actions.json",
	"../../testdata/provider-aws/emitted-actions.json",
}

// producerNames returns the actions some producer emits, and the services
// that every fixture covers.
func producerNames(t *testing.T) (actions, services map[string]bool) {
	t.Helper()
	actions = make(map[string]bool)
	for i, path := range emittedActionFixtures {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Services []string `json:"services"`
			Actions  []string `json:"actions"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, a := range doc.Actions {
			actions[a] = true
		}
		covered := make(map[string]bool, len(doc.Services))
		for _, s := range doc.Services {
			if i == 0 || services[s] {
				covered[s] = true
			}
		}
		services = covered
	}
	return actions, services
}

// A rule can only fire on a name a producer emits. A row that names anything
// else is a misspelling or dead, so it fails here instead of drifting.
func TestRules_EveryNameIsEmitted(t *testing.T) {
	emitted, services := producerNames(t)
	for _, r := range rules {
		a := r.action
		if !services[actionService(a)] {
			t.Errorf("rule %q is in a service the emitted-actions fixtures do not cover; add it to both and rebuild them", a)
			continue
		}
		if !emitted[a] {
			t.Errorf("rule %q is not an action CloudFormation or the parser emits", a)
		}
	}
}

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

func TestServiceClasses_EveryServiceIsEmitted(t *testing.T) {
	emitted, services := producerNames(t)
	for svc := range serviceClasses {
		if !services[svc] {
			t.Errorf("service %q is not covered by the emitted-actions fixtures", svc)
			continue
		}
		found := false
		for a := range emitted {
			if actionService(a) == svc {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no producer emits an action of service %q", svc)
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
		if got := actionClass(a); got != classManagement {
			t.Errorf("actionClass(%q) = %d, want classManagement", a, got)
		}
	}
}

func TestDecide_BestEffortDowngradesOnlyManagement(t *testing.T) {
	tests := []struct {
		action string
		want   permissionClass
	}{
		{"s3:CreateBucket", classOptional},
		{"s3:GetObject", classDataPlane},
		{"s3:PutBucketVersioning", classOptional},
	}
	for _, tt := range tests {
		if got := decide("aws_s3_bucket", tt.action, true, false, nil).class; got != tt.want {
			t.Errorf("decide(aws_s3_bucket, %q, bestEffort).class = %d, want %d", tt.action, got, tt.want)
		}
	}
}
