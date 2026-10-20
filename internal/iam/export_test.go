package iam

// RuleActions returns the action each classification rule names, for the
// external tests.
func RuleActions() []string {
	names := make([]string, len(rules))
	for i, r := range rules {
		names[i] = r.action
	}
	return names
}

// ClassifiedServices returns the services serviceClasses classifies whole.
func ClassifiedServices() []string {
	var services []string
	for svc := range serviceClasses {
		services = append(services, svc)
	}
	return services
}

// ConditionKeyRule is one row of the condition key table, for the external
// tests.
type ConditionKeyRule struct {
	// ResourceType is the terraform resource type the row is about.
	ResourceType string
	// Actions lists the actions the condition key gates.
	Actions []string
	// Name is the condition key, as AWS names it.
	Name string
	// Attribute is the plan attribute holding the key's value.
	Attribute string
}

// ConditionKeyRules returns every row of the condition key table.
func ConditionKeyRules() []ConditionKeyRule {
	var out []ConditionKeyRule
	for resType, rule := range resourceRules {
		for _, ck := range rule.conditionKeys {
			out = append(out, ConditionKeyRule{
				ResourceType: resType,
				Actions:      ck.actions,
				Name:         ck.key.name,
				Attribute:    ck.key.attribute,
			})
		}
	}
	return out
}
