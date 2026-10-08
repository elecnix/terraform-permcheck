package iam_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/permdata"
)

// The knowledge rules classify the actions a producer emits. These tests
// check each rule against what the producers emit: the provider-source
// parser through the embedded permissions table, which covers every
// service, and CloudFormation through a golden list of the services that
// have rules. They live in an external test package because permdata
// imports iam.

// cfnEmittedActions is the CloudFormation list, built from every schema in
// the registry.
const cfnEmittedActions = "../../testdata/cfn/emitted-actions.json"

// producerNames returns the actions some producer emits, and the services
// every producer covers: the services of the CloudFormation list.
func producerNames(t *testing.T) (actions, services map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile(cfnEmittedActions)
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
	actions = make(map[string]bool)
	for _, a := range doc.Actions {
		actions[a] = true
	}
	services = make(map[string]bool, len(doc.Services))
	for _, s := range doc.Services {
		services[s] = true
	}

	table, err := permdata.Embedded().Table()
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range table.Schemas {
		for op := range schema.Ops {
			for _, a := range schema.Actions(op) {
				actions[a] = true
			}
		}
	}
	return actions, services
}

func service(action string) string {
	svc, _, _ := strings.Cut(action, ":")
	return svc
}

// A rule can only fire on a name a producer emits. A row that names anything
// else is a misspelling or dead, so it fails here instead of drifting.
func TestRules_EveryNameIsEmitted(t *testing.T) {
	emitted, services := producerNames(t)
	for _, a := range iam.RuleActions() {
		if !services[service(a)] {
			t.Errorf("rule %q is in a service %s does not cover; add the service and rebuild it", a, cfnEmittedActions)
			continue
		}
		if !emitted[a] {
			t.Errorf("rule %q is not an action CloudFormation or the parser emits", a)
		}
	}
}

func TestServiceClasses_EveryServiceIsEmitted(t *testing.T) {
	emitted, services := producerNames(t)
	for _, svc := range iam.ClassifiedServices() {
		if !services[svc] {
			t.Errorf("service %q is not covered by %s", svc, cfnEmittedActions)
			continue
		}
		found := false
		for a := range emitted {
			if service(a) == svc {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no producer emits an action of service %q", svc)
		}
	}
}
