package report

import (
	"fmt"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/hcl"
)

// annotations renders the findings as GitHub Actions ::warning:: workflow
// commands, one per group, in first-seen order, then one per unresolved
// resource type. Missing and unverified groups
// stay interleaved; an unverified group gets its own title and tag. The first
// resource in a group with a known location gives the command its file= and
// line= parameters, so GitHub shows the annotation inline in the pull
// request's "Files changed" tab.
func (r *Report) annotations() string {
	var b strings.Builder
	for _, g := range r.groups {
		var sources []string
		for _, f := range g.items {
			sources = append(sources, source(f.MissingAction))
		}

		msg := g.key.action
		if g.key.condition != "" {
			msg += fmt.Sprintf(" [conditional: %s]", g.key.condition)
		}
		title := "Missing IAM permission"
		if g.key.unverified {
			msg += " " + unverifiedTag
			title = "Unverified IAM permission"
		}
		msg += " needed by: " + strings.Join(sources, ", ")

		writeWarning(&b, firstLocated(g.items), title, msg)
	}
	for _, g := range r.unresolved {
		var sources []string
		for _, f := range g.items {
			sources = append(sources, source(f.MissingAction))
		}
		title := "Unresolved resource type"
		if r.unresolvedAllowed {
			title += " (allowed)"
		}
		msg := g.key + " has no permission data, so its permissions were not checked. Resources: " + strings.Join(sources, ", ")
		writeWarning(&b, firstLocated(g.items), title, msg)
	}
	return b.String()
}

// escapeData escapes the message of a workflow command the way the Actions
// toolkit does, so a newline in it cannot end the command and start another.
func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// escapeProperty escapes a property value of a workflow command the way the
// Actions toolkit does. A property also ends at a comma, and its name at a
// colon, so those are escaped too.
func escapeProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

// writeWarning writes one ::warning:: command, with file= and line= when the
// location is known.
func writeWarning(b *strings.Builder, loc *hcl.Location, title, msg string) {
	if loc != nil {
		fmt.Fprintf(b, "::warning file=%s,line=%d,title=%s::%s\n", escapeProperty(loc.Path), loc.Line, escapeProperty(title), escapeData(msg))
	} else {
		fmt.Fprintf(b, "::warning title=%s::%s\n", escapeProperty(title), escapeData(msg))
	}
}

// firstLocated returns the location of the first finding that has one.
func firstLocated(findings []finding) *hcl.Location {
	for _, f := range findings {
		if f.loc != nil {
			return f.loc
		}
	}
	return nil
}

// excludedAnnotations renders the excluded findings as ::notice:: workflow
// commands, one per (action, reason) group.
func (r *Report) excludedAnnotations() string {
	var b strings.Builder
	for _, g := range r.excludedGroups {
		var sources []string
		for _, e := range g.items {
			sources = append(sources, source(e.MissingAction))
		}
		msg := g.key.action + " excluded (per config)"
		if g.key.reason != "" {
			msg += fmt.Sprintf(": %s", g.key.reason)
		}
		msg += " for: " + strings.Join(sources, ", ")
		fmt.Fprintf(&b, "::notice title=Excluded IAM permission::%s\n", escapeData(msg))
	}
	return b.String()
}
