package iam

import (
	"fmt"
	"strings"
)

// Need is a permission a principal needs that no terraform resource implies,
// such as a CI step that calls ecr:DescribeImages or an application that
// reads a secret at startup. Needs come from the "needs" list of the config
// file and are checked against the same policy as the plan.
type Need struct {
	// Sid names the need in the report. Required.
	Sid string `json:"sid"`
	// Principal optionally names the role or user the need belongs to. A need
	// with a principal is checked only when --principal selects it, so one
	// config can hold the needs of several roles. A need without one is
	// checked on every run.
	Principal string `json:"principal,omitempty"`
	// Actions are the IAM actions the principal calls. Required.
	Actions []string `json:"actions"`
	// Resources optionally lists the ARNs or ARN patterns the actions act on.
	// Each one must be covered. "*" means the action must be granted on every
	// resource. Empty means any grant of the action counts.
	Resources []string `json:"resources,omitempty"`
	// Reason is an optional note on why the principal needs the actions.
	Reason string `json:"reason,omitempty"`
}

// validateNeeds checks the needs list of a config file.
//
// Two needs that run together must have different sids, or the report shows
// two findings with the same source. A need without a principal runs with
// every principal, so its sid must be unique in the whole list. Needs under
// two different principals never run together, so they may share a sid.
func validateNeeds(needs []Need) error {
	seen := map[string]bool{}     // principal and sid
	unnamed := map[string]bool{}  // sids of needs without a principal
	anyNamed := map[string]bool{} // sids of needs with a principal
	for i, n := range needs {
		if strings.TrimSpace(n.Sid) == "" {
			return fmt.Errorf("needs[%d]: sid is required", i)
		}
		key := n.Principal + "\x00" + n.Sid
		if seen[key] {
			return fmt.Errorf("needs[%d]: duplicate sid %q", i, n.Sid)
		}
		if (n.Principal == "" && anyNamed[n.Sid]) || (n.Principal != "" && unnamed[n.Sid]) {
			return fmt.Errorf("needs[%d]: duplicate sid %q: a need without a principal runs with every principal, so its sid must be unique", i, n.Sid)
		}
		seen[key] = true
		if n.Principal == "" {
			unnamed[n.Sid] = true
		} else {
			anyNamed[n.Sid] = true
		}
		if len(n.Actions) == 0 {
			return fmt.Errorf("needs[%d] (%s): actions is required", i, n.Sid)
		}
		for _, a := range n.Actions {
			if !strings.Contains(a, ":") || strings.ContainsAny(a, "*?") {
				return fmt.Errorf("needs[%d] (%s): action %q must be a single service:Action name", i, n.Sid, a)
			}
		}
		for _, r := range n.Resources {
			if r != "*" && !strings.HasPrefix(r, "arn:") {
				return fmt.Errorf("needs[%d] (%s): resource %q must be \"*\" or an ARN", i, n.Sid, r)
			}
		}
	}
	return nil
}

// SelectNeeds returns the needs that apply to principal: every need without
// a principal, plus the needs whose principal equals it. It returns an error
// when principal is set and no need names it, so a typo does not pass
// silently.
func SelectNeeds(needs []Need, principal string) ([]Need, error) {
	var out []Need
	named := false
	for _, n := range needs {
		switch n.Principal {
		case "":
			out = append(out, n)
		case principal:
			out = append(out, n)
			named = true
		}
	}
	if principal != "" && !named {
		return nil, fmt.Errorf("no needs declared for principal %q", principal)
	}
	return out, nil
}

// CheckNeeds reports each need action the policy does not grant, one
// finding per uncovered resource. A need with no resources is checked by
// action, as a resource change with an unknown ARN is: any Allow counts
// unless a definite Deny overrides it, and strict mode reports a grant
// limited to some resources as unverified. A need on "*" needs a grant on
// every resource. Every case goes through Coverage.
func CheckNeeds(needs []Need, policy *PolicyDocument, strict bool) []MissingAction {
	var missing []MissingAction
	for _, n := range needs {
		for _, action := range n.Actions {
			add := func(resource string, unverified bool) {
				missing = append(missing, MissingAction{
					Action:                  action,
					Service:                 strings.Split(action, ":")[0],
					Class:                   classTag(ClassManagement),
					Need:                    n.Sid,
					NeedResource:            resource,
					ResourceScopeUnverified: unverified,
				})
			}
			if len(n.Resources) == 0 {
				switch policy.Coverage(action, nil, strict) {
				case Missing:
					add("", false)
				case Unverified:
					add("", true)
				}
				continue
			}
			for _, r := range n.Resources {
				// A need on "*" needs a grant on every resource, so a grant
				// limited to some resources falls short of it: the strict
				// verdict decides it.
				if r == "*" {
					if policy.Coverage(action, nil, true) != Covered {
						add(r, false)
					}
					continue
				}
				if policy.Coverage(action, []string{r}, strict) != Covered {
					add(r, false)
				}
			}
		}
	}
	return missing
}
