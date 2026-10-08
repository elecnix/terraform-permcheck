package report

import (
	"fmt"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/iam"
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

// writeWarning writes one ::warning:: command, with file= and line= when the
// location is known.
func writeWarning(b *strings.Builder, loc *iam.FileLocation, title, msg string) {
	if loc != nil {
		fmt.Fprintf(b, "::warning file=%s,line=%d,title=%s::%s\n", loc.Path, loc.Line, title, msg)
	} else {
		fmt.Fprintf(b, "::warning title=%s::%s\n", title, msg)
	}
}

// firstLocated returns the location of the first finding that has one.
func firstLocated(findings []finding) *iam.FileLocation {
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
		fmt.Fprintf(&b, "::notice title=Excluded IAM permission::%s\n", msg)
	}
	return b.String()
}
