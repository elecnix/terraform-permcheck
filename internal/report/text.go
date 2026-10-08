package report

import (
	"fmt"
	"strings"
)

// text renders the findings for a person. Each group is one action line
// followed by the resources that need it. Unverified groups get a section of
// their own after the missing ones, and unresolved resource types one after
// that. A resource with a known location gets its file and line.
func (r *Report) text() string {
	var b strings.Builder
	if len(r.missing) > 0 {
		fmt.Fprintf(&b, "Missing IAM permissions (%d):\n", len(r.missing))
		writeGroups(&b, r.missing)
	}
	if len(r.unverified) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Unverified IAM permissions (%d), granted only on resources whose ARN the plan does not show:\n", len(r.unverified))
		writeGroups(&b, r.unverified)
	}
	if len(r.unresolved) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		allowed := ""
		if r.unresolvedAllowed {
			allowed = " (allowed)"
		}
		fmt.Fprintf(&b, "Unresolved resource types (%d), no permission data%s:\n", len(r.unresolved), allowed)
		for _, g := range r.unresolved {
			fmt.Fprintf(&b, "  %s\n", g.key)
			writeSources(&b, g.items)
		}
	}
	return b.String()
}

// writeGroups writes one action line per group, each followed by the
// resources that need the action. A condition tag replaces the class tag.
func writeGroups(b *strings.Builder, groups []group[findingKey, finding]) {
	for _, g := range groups {
		line := g.key.action
		if g.key.condition != "" {
			line += fmt.Sprintf(" [conditional: %s]", g.key.condition)
		} else if g.key.class != "" {
			line += " " + g.key.class
		}
		if g.key.unverified {
			line += " " + unverifiedTag
		}
		fmt.Fprintf(b, "  %s\n", line)
		writeSources(b, g.items)
	}
}

// writeSources writes one line per finding naming what needs it, with its
// file and line when known.
func writeSources(b *strings.Builder, findings []finding) {
	for _, f := range findings {
		resourceLine := "    → " + source(f.MissingAction)
		if f.loc != nil {
			resourceLine += fmt.Sprintf(" [%s:%d]", f.loc.Path, f.loc.Line)
		}
		b.WriteString(resourceLine + "\n")
	}
}

// excludedText renders the excluded findings, one entry per (action, reason)
// group. It is empty when the report shows no excluded findings.
func (r *Report) excludedText() string {
	if len(r.excludedGroups) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Excluded (per config) (%d):\n", len(r.excludedGroups))
	for _, g := range r.excludedGroups {
		fmt.Fprintf(&b, "  %s\n", g.key.action)
		if g.key.reason != "" {
			fmt.Fprintf(&b, "    reason: %s\n", g.key.reason)
		}
		for _, e := range g.items {
			fmt.Fprintf(&b, "    → %s\n", source(e.MissingAction))
		}
	}
	return b.String()
}
