package iam_test

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// The condition keys of the actions the tool uses them for, from the AWS
// Service Authorization Reference. A key the tool names must be one AWS
// lists for that action, or the tool would check a condition AWS never
// evaluates.
const conditionKeysFixture = "../../testdata/aws/service-reference-condition-keys.json"

// serviceReferenceConditionKeys reads the fixture: per service, the
// condition keys each action accepts.
func serviceReferenceConditionKeys(t *testing.T) map[string]map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(conditionKeysFixture)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]map[string][]string `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Services
}

// TestConditionKeys_EveryKeyIsARealConditionKey checks every condition key
// the table names against the AWS service reference: the key must be one the
// action accepts, and the action must be one the service lists.
func TestConditionKeys_EveryKeyIsARealConditionKey(t *testing.T) {
	reference := serviceReferenceConditionKeys(t)
	for _, row := range iam.ConditionKeyRules() {
		for _, action := range row.Actions {
			svc, name, _ := strings.Cut(action, ":")
			actions, ok := reference[svc]
			if !ok {
				t.Errorf("%s: the fixture lists no service %q; add it to %s", row.ResourceType, svc, conditionKeysFixture)
				continue
			}
			keys, ok := actions[name]
			if !ok {
				t.Errorf("%s: the fixture lists no action %q of %q; add it to %s", row.ResourceType, name, svc, conditionKeysFixture)
				continue
			}
			if !slices.ContainsFunc(keys, func(k string) bool { return strings.EqualFold(k, row.Name) }) {
				t.Errorf("%s: %q is not a condition key of %q (the reference lists %s)", row.ResourceType, row.Name, action, strings.Join(keys, ", "))
			}
		}
	}
}

// TestConditionKeys_EveryActionIsEmitted checks that the actions a
// condition key gates are actions the tool actually asks for, so a table row
// cannot drift away from the schema.
func TestConditionKeys_EveryActionIsEmitted(t *testing.T) {
	emitted, _ := producerNames(t)
	for _, row := range iam.ConditionKeyRules() {
		for _, action := range row.Actions {
			if !emitted[action] {
				t.Errorf("%s: %q is not an action CloudFormation or the parser emits", row.ResourceType, action)
			}
		}
	}
}

// TestConditionKeys_EveryRowNamesAnAttribute checks that a condition key
// names the plan attribute holding its value, so the value is there when
// the plan knows it.
func TestConditionKeys_EveryRowNamesAnAttribute(t *testing.T) {
	for _, row := range iam.ConditionKeyRules() {
		if row.Attribute == "" {
			t.Errorf("%s: condition key %q names no attribute", row.ResourceType, row.Name)
		}
	}
}
