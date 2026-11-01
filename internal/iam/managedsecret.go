package iam

import "github.com/elecnix/terraform-permcheck/internal/plan"

// Managed secrets.
//
// Some resources make their service create a Secrets Manager secret in the
// caller's account. AWS checks the secretsmanager: actions against the caller
// on that secret, but the provider never calls them and no schema lists them.
// The service names the secret under a fixed prefix, so a grant scoped to that
// prefix covers it.

// managedSecret describes the secret a service keeps for a resource.
type managedSecret struct {
	// prefix is the start of the secret's name, such as "events!connection/".
	// The service appends the resource's name, a slash and an identifier.
	prefix string
	// actions lists the secretsmanager: actions the caller needs, by change.
	actions map[string][]string
}

// managedSecretRequirements returns the secretsmanager: actions AWS checks on
// the secret that rc makes the service create or change. A delete needs none.
func managedSecretRequirements(rc *plan.ResourceChange) []targeted {
	secret := resourceRules[rc.Type].managedSecret
	if secret == nil {
		return nil
	}
	pattern := "arn:*:secretsmanager:*:*:secret:" + secret.prefix
	if name := rc.AttributeValues["name"]; name != "" {
		pattern += name + "/"
	}
	pattern += "*"
	var reqs []targeted
	for _, action := range secret.actions[rc.Change] {
		reqs = append(reqs, targeted{
			Requirement: Requirement{Action: action},
			targets:     [][]string{{pattern}},
		})
	}
	return reqs
}
