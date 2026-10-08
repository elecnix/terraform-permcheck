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
	if g.Changed != "" && !attributeChanged(g.Changed, rc) {
		return false
	}
	return true
}

// shownBy reports whether the plan shows the path running for a call of
// action, on evidence rather than because the plan cannot rule it out. A
// presence test needs the plan to show the attribute set. A change test needs
// the plan to show the attribute changed, or with no change data, as in static
// mode, set: there the create writes every attribute the block sets. An
// ungated path tests nothing and shows nothing.
//
// Behind a change test alone the provider usually writes the new value or
// deletes the old one: a Delete call runs when the attribute is now unset, and
// any other call when it is set. So the plan shows a Delete call only when the
// changed attribute is unset, and another call only when it is set.
func (g Gate) shownBy(action string, rc *plan.ResourceChange) bool {
	if g.Ungated() {
		return false
	}
	if g.Attribute != "" {
		if !attributeShown(g.Attribute, g.ValueGuarded, rc) {
			return false
		}
		if g.Changed == "" {
			return true
		}
	}
	changed, known := changeShown(g.Changed, rc)
	if !known {
		return attributeShown(g.Changed, false, rc) && !isDelete(action)
	}
	if !changed {
		return false
	}
	if g.Attribute != "" {
		return true
	}
	return attributeShown(g.Changed, false, rc) != isDelete(action)
}

// isDelete reports whether action names a Delete call.
func isDelete(action string) bool {
	_, name, _ := strings.Cut(action, ":")
	return strings.HasPrefix(name, "Delete")
}

// attributeShown reports whether the plan shows attr as set. It reads the
// same data as conditionMet, but with no data it reports false.
func attributeShown(attr string, valueGuarded bool, rc *plan.ResourceChange) bool {
	top, nested := topAttribute(attr)
	if valueGuarded && rc.Configured != nil {
		return rc.Configured[top]
	}
	if nested {
		if present, known := rc.PathPresent(attr); known {
			return present
		}
	}
	return rc.Attributes[top]
}

// changeShown reports whether the plan shows attr changed, and whether the
// plan has change data for it at all. It reads the same data as
// attributeChanged.
func changeShown(attr string, rc *plan.ResourceChange) (changed, known bool) {
	top, nested := topAttribute(attr)
	if nested {
		if changed, known := rc.PathChanged(attr); known {
			return changed, true
		}
	}
	if rc.ChangedAttributes == nil {
		return false, false
	}
	return rc.ChangedAttributes[top], true
}

// featureUsed reports whether a path to action that is not best-effort runs
// for rc on evidence: the plan sets the attribute that gates it. An optional
// feature the plan uses is not optional for this apply, since the provider
// makes the call and the apply fails without it.
func featureUsed(action string, gates []Gate, rc *plan.ResourceChange) bool {
	for _, g := range gates {
		if !g.BestEffort && g.holds(rc) && g.shownBy(action, rc) {
			return true
		}
	}
	return false
}

// attributeChanged reports whether a change guard on attr passes for this
// resource change. An unknown change counts as a change.
//
// The parser keeps the path a guard names, such as
// stream_mode_details.0.stream_mode. A nested path is read from the plan's
// nested values when the change carries them. Otherwise its first segment
// decides, since a change below an attribute changes the attribute.
func attributeChanged(attr string, rc *plan.ResourceChange) bool {
	top, nested := topAttribute(attr)
	if nested {
		if changed, known := rc.PathChanged(attr); known {
			return changed
		}
	}
	return rc.ChangedAttributes == nil || rc.ChangedAttributes[top]
}

// topAttribute returns the top-level attribute of a dotted path, and whether
// the path goes below it.
func topAttribute(path string) (string, bool) {
	top, _, nested := strings.Cut(path, ".")
	return top, nested
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
