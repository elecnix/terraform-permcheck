package provideraws

import "github.com/elecnix/terraform-permcheck/internal/iam"

// mergeRequirements groups the requirements by action, in the order each
// action first appears. An action reached on several paths is needed when any
// of them runs, so it keeps the gate of each path, without the paths another
// one subsumes (see essentialGates).
func mergeRequirements(reqs []iam.Requirement) []iam.Requirement {
	var actions []string
	gates := make(map[string][]iam.Gate)
	for _, r := range reqs {
		if _, seen := gates[r.Action]; !seen {
			actions = append(actions, r.Action)
		}
		gates[r.Action] = append(gates[r.Action], r.Gate)
	}
	out := make([]iam.Requirement, 0, len(reqs))
	for _, action := range actions {
		out = append(out, requirements(action, gates[action])...)
	}
	return out
}

// requirements returns one requirement per essential path to action. A path
// with no gate whose failure counts makes the action required whatever the
// others say.
func requirements(action string, paths []iam.Gate) []iam.Requirement {
	distinct := essentialGates(paths)
	out := make([]iam.Requirement, len(distinct))
	for i, g := range distinct {
		out[i] = iam.Requirement{Action: action, Gate: g}
	}
	return out
}

// essentialGates drops the repeated paths and the paths another one
// subsumes. A path with no gate runs whenever a gated path runs, so it
// subsumes every gated path that is best-effort when it is.
func essentialGates(paths []iam.Gate) []iam.Gate {
	var always *iam.Gate
	for i, g := range paths {
		if g.Ungated() && (always == nil || !g.BestEffort) {
			always = &paths[i]
		}
	}
	var out []iam.Gate
	for _, g := range paths {
		if always != nil && (!always.BestEffort || g.BestEffort) && g != *always {
			continue
		}
		if !containsGate(out, g) {
			out = append(out, g)
		}
	}
	return out
}

// containsGate reports whether gates already lists g.
func containsGate(gates []iam.Gate, g iam.Gate) bool {
	for _, h := range gates {
		if h == g {
			return true
		}
	}
	return false
}
