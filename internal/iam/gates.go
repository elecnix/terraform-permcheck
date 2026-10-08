package iam

import (
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// Gate is one path on which the provider makes the call behind an action. The
// call runs on that path when each test the gate sets holds. A Gate with
// neither test is a path that always runs.
//
// An action reached on several paths is needed when any of its gates holds.
// A Schema lists one Requirement per path.
type Gate struct {
	// Attribute is the attribute a presence guard (d.GetOk or d.Get) tests,
	// or "" when the path has none.
	Attribute string
	// ValueGuarded is true when the guard compares Attribute's value, so only
	// a configured attribute satisfies it.
	ValueGuarded bool
	// Changed is the attribute a change guard (d.HasChange) tests, or "" when
	// the path has none.
	Changed string
	// BestEffort is true when the provider ignores the call's failure on
	// this path.
	BestEffort bool
}

// Ungated reports whether the path runs without testing any attribute.
func (g Gate) Ungated() bool {
	return g.Attribute == "" && g.Changed == ""
}

// holds reports whether the path runs for this resource change. An unknown
// presence or change counts as holding, so the permission stays reported.
func (g Gate) holds(rc *plan.ResourceChange) bool {
	if g.Attribute != "" && !conditionMet(g.Attribute, g.ValueGuarded, rc) {
		return false
	}
	if g.Changed != "" && rc.ChangedAttributes != nil && !rc.ChangedAttributes[g.Changed] {
		return false
	}
	return true
}

// evaluateGates checks an action against the gates of the paths that reach
// it. One path is the common case. It reports whether
// any path runs for rc, and whether every path that runs is best-effort. It
// also returns the attributes of the paths that decide the action, for the
// [conditional: <attr>] tag: the paths whose failure counts when one of them
// runs, or else the best-effort ones. The tag is empty when one of those
// paths has no gate.
func evaluateGates(gates []Gate, rc *plan.ResourceChange) (needed bool, gateAttr string, bestEffort bool) {
	var running, required []Gate
	for _, g := range gates {
		if !g.holds(rc) {
			continue
		}
		running = append(running, g)
		if !g.BestEffort {
			required = append(required, g)
		}
	}
	if len(running) == 0 {
		return false, "", false
	}
	deciding := running
	if len(required) > 0 {
		deciding = required
	}
	var attrs []string
	for _, g := range deciding {
		if g.Ungated() {
			return true, "", len(required) == 0
		}
		attrs = appendUnique(attrs, gateAttribute(g.Attribute, g.Changed))
	}
	return true, strings.Join(attrs, "|"), len(required) == 0
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
