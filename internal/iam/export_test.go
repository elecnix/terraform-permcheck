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
