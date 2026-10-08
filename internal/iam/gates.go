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
// Schemas list those actions in GetGates. An action reached on one path keeps
// its gate in the single-valued maps of SchemaLike.
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

// gatesProvider is the optional part of SchemaLike that lists the actions
// reached on several gated paths.
type gatesProvider interface {
	// GetGates maps op → action → every gate the action is reached under.
	GetGates() map[string]map[string][]Gate
}

// schemaGates returns the multi-path gates of op, or nil when the schema
// lists none.
func schemaGates(schema SchemaLike, op string) map[string][]Gate {
	if g, ok := schema.(gatesProvider); ok {
		return g.GetGates()[op]
	}
	return nil
}

// evaluateGates checks an action reached on several paths. It reports whether
// any path runs for rc, the attributes of the paths that run for the
// [conditional: <attr>] tag (empty when an ungated path runs), and whether
// every path that runs is best-effort.
func evaluateGates(gates []Gate, rc *plan.ResourceChange) (needed bool, gateAttr string, bestEffort bool) {
	var attrs []string
	ungated := false
	bestEffort = true
	for _, g := range gates {
		if !g.holds(rc) {
			continue
		}
		needed = true
		if !g.BestEffort {
			bestEffort = false
		}
		if g.Ungated() {
			ungated = true
			continue
		}
		attrs = appendUnique(attrs, gateAttribute(g.Attribute, g.Changed))
	}
	if !needed {
		return false, "", false
	}
	if ungated {
		return true, "", bestEffort
	}
	return true, strings.Join(attrs, "|"), bestEffort
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
