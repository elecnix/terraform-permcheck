package iam

import "github.com/elecnix/terraform-permcheck/internal/plan"

// Implied requirements.
//
// Some permissions are checked by AWS at apply time though the provider never
// calls them, so no schema lists them: iam:PassRole on the role a resource
// hands to a service, and the callback a web ACL association makes into its
// target's service. impliedRequirements describes each one as a requirement
// with the resources it acts on. Validate appends them to the schema's
// requirements, and every requirement then goes through the same gates,
// classification, coverage check and filters.

// targeted is a requirement with the resources its action acts on.
type targeted struct {
	Requirement
	// targets lists the resources the action acts on, one list of ARN
	// patterns per resource. Nil means the plan does not show them, and the
	// action alone decides coverage.
	targets [][]string
	// knownTargetsOnly drops a missing verdict when targets is nil. The
	// resource may act on no target at all, so only a grant checked against
	// a known target, or a grant scoped elsewhere under --strict-resources,
	// counts against the policy.
	knownTargetsOnly bool
}

// withTargets pairs each requirement with the same targets.
func withTargets(reqs []Requirement, targets [][]string) []targeted {
	out := make([]targeted, len(reqs))
	for i, r := range reqs {
		out[i] = targeted{Requirement: r, targets: targets}
	}
	return out
}

// impliedRequirements returns the requirements AWS adds to resource change
// rc beyond the calls the provider makes.
func impliedRequirements(rc *plan.ResourceChange, set *changeSet) []targeted {
	return append(passRoleRequirements(rc, set), crossServiceRequirements(rc, set)...)
}

// verdict returns the policy's verdict on a requirement: whether the policy
// grants its action on each of its targets.
func (t targeted) verdict(policy *PolicyDocument, strict bool) Verdict {
	v := policy.worstVerdict(t.Action, t.targets, strict)
	if v == Missing && t.knownTargetsOnly && len(t.targets) == 0 {
		return Covered
	}
	return v
}

// actionPaths is an action with every path that reaches it.
type actionPaths struct {
	action string
	paths  []targeted
}

// pathsByAction groups requirements by action, in the order each action first
// appears.
func pathsByAction(reqs []targeted) []actionPaths {
	var out []actionPaths
	index := make(map[string]int, len(reqs))
	for _, r := range reqs {
		i, ok := index[r.Action]
		if !ok {
			i = len(out)
			index[r.Action] = i
			out = append(out, actionPaths{action: r.Action})
		}
		out[i].paths = append(out[i].paths, r)
	}
	return out
}

// gates returns the gate of each path.
func (a actionPaths) gates() []Gate {
	gates := make([]Gate, len(a.paths))
	for i, p := range a.paths {
		gates[i] = p.Gate
	}
	return gates
}

// verdict returns the worst verdict over the paths that run for rc.
func (a actionPaths) verdict(rc *plan.ResourceChange, policy *PolicyDocument, strict bool) Verdict {
	worst := Covered
	for _, p := range a.paths {
		if !p.holds(rc) {
			continue
		}
		switch p.verdict(policy, strict) {
		case Missing:
			return Missing
		case Unverified:
			worst = Unverified
		}
	}
	return worst
}
