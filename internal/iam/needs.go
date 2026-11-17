package iam

import (
	"fmt"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/policy"
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

// ValidateNeeds checks the needs list of a config file.
//
// Two needs that run together must have different sids, or the report shows
// two findings with the same source. A need without a principal runs with
// every principal, so its sid must be unique in the whole list. Needs under
// two different principals never run together, so they may share a sid.
func ValidateNeeds(needs []Need) error {
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
// a principal, plus the needs whose principal equals it. Without principal,
// it also returns the needs whose principal is in mapped, the labels that
// the config's principals map gives a role in the plan. It returns an error
// when principal is set and no need names it, so a typo does not pass
// silently.
func SelectNeeds(needs []Need, principal string, mapped map[string]bool) ([]Need, error) {
	var out []Need
	named := false
	for _, n := range needs {
		switch {
		case n.Principal == "":
			out = append(out, n)
		case n.Principal == principal:
			out = append(out, n)
			named = true
		case principal == "" && mapped[n.Principal]:
			out = append(out, n)
		}
	}
	if principal != "" && !named {
		return nil, fmt.Errorf("no needs declared for principal %q", principal)
	}
	return out, nil
}

// Grants decides whether a principal's policies grant an action. A
// *policy.Document is one: the policy a run reads from its --policy-*
// source. The policy set of a mapped principal is another.
type Grants interface {
	// Coverage reports whether the policies grant action on a resource
	// matching any of the target ARN patterns, as
	// policy.Document.Coverage does.
	Coverage(action string, targets []string, conds policy.Conditions, strict bool) policy.Result
	// CoverageOfEveryResource reports whether the policies grant action on
	// every resource, as policy.Document.CoverageOfEveryResource does.
	CoverageOfEveryResource(action string, strict bool) policy.Result
	// GrantedResources lists the resources the policies grant action on,
	// when they grant it only on some, as
	// policy.Document.GrantedResources does.
	GrantedResources(action string) []string
}

// CheckNeeds reports each need action the policy does not grant, one
// finding per uncovered resource. A need with no resources is checked by
// action, as a resource change with an unknown ARN is: any Allow counts
// unless a definite Deny overrides it, and strict mode reports a grant
// limited to some resources as unverified. A need on "*" needs a grant on
// every resource. Every case goes through Coverage.
func CheckNeeds(needs []Need, doc *policy.Document, strict bool) []MissingAction {
	return CheckNeedsWith(needs, func(string) Grants { return doc }, strict)
}

// CheckNeedsWith checks the needs as CheckNeeds does, against the policies
// that grantsFor returns for each action. The policies of a mapped principal
// depend on the action, since a resource policy applies only to the actions
// of its service.
func CheckNeedsWith(needs []Need, grantsFor func(action string) Grants, strict bool) []MissingAction {
	var missing []MissingAction
	for _, n := range needs {
		for _, action := range n.Actions {
			doc := grantsFor(action)
			add := func(resource string, res policy.Result) {
				m := newFinding(action, ClassManagement, res)
				m.Need = n.Sid
				m.NeedResource = resource
				m.Reason = n.Reason
				// A grant limited to other resources is the likely cause of a
				// miss on a resource the need names: say where it does apply.
				if res.Verdict == policy.Missing && resource != "" {
					m.GrantedOn = doc.GrantedResources(action)
				}
				missing = append(missing, m)
			}
			if len(n.Resources) == 0 {
				if v := doc.Coverage(action, nil, nil, strict); v.Verdict != policy.Covered {
					add("", v)
				}
				continue
			}
			for _, r := range n.Resources {
				// A need on "*" needs a grant on every resource, so a grant
				// limited to some resources falls short of it even without
				// strict mode. A grant on every resource whose condition the
				// tool cannot evaluate counts as covered, and strict mode
				// reports it unverified.
				if r == "*" {
					if res := doc.CoverageOfEveryResource(action, strict); res.Verdict != policy.Covered {
						add(r, res)
					}
					continue
				}
				if v := doc.Coverage(action, []string{r}, nil, strict); v.Verdict != policy.Covered {
					add(r, v)
				}
			}
		}

		// A dependent action (see dependentActions) is checked once per need,
		// and not at all when the need lists it, which reports it on its own.
		// Its findings follow those of the need's own actions.
		listed := make(map[string]bool, len(n.Actions))
		for _, action := range n.Actions {
			listed[action] = true
		}
		for _, action := range n.Actions {
			for _, dep := range dependentActions[action] {
				if listed[dep.action] {
					continue
				}
				listed[dep.action] = true
				if res := dependencyVerdict(dep.action, grantsFor(dep.action), strict); res.Verdict != policy.Covered {
					m := newFinding(dep.action, ClassManagement, res)
					m.Need = n.Sid
					m.Reason = n.Reason
					m.DependsOn = action
					missing = append(missing, m)
				}
			}
		}
	}
	return missing
}
