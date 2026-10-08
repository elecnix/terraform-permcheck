// Package report renders a check result as the text, github-annotations or
// json report of the validate command.
//
// New groups the findings once and resolves each finding's file location
// once. Every format renders from that one Report, so the counts in a report
// always match the groups it lists.
package report

import (
	"fmt"
	"io"

	"github.com/elecnix/terraform-permcheck/internal/check"
	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// Format names an output format of the validate command.
type Format string

// The supported formats.
const (
	Text              Format = "text"
	GitHubAnnotations Format = "github-annotations"
	JSON              Format = "json"
)

// ParseFormat returns the Format named s, or an error when s names none.
func ParseFormat(s string) (Format, error) {
	switch f := Format(s); f {
	case Text, GitHubAnnotations, JSON:
		return f, nil
	}
	return "", fmt.Errorf("unsupported format %q (supported: text, github-annotations, json)", s)
}

// finding is a missing action with its file location resolved.
type finding struct {
	iam.MissingAction
	loc *iam.FileLocation // nil when the location is unknown
}

// findingKey groups the findings that differ only in what needs them.
type findingKey struct {
	action     string
	class      string
	condition  string
	unverified bool
}

// excludedKey groups excluded actions by permission and reason.
type excludedKey struct {
	action string
	reason string
}

// group is a key and the items that share it.
type group[K comparable, T any] struct {
	key   K
	items []T
}

// groupBy partitions items by key. Groups come in the order their key first
// appears, and each group keeps its items in input order. Input order is plan
// order, which is stable for a given plan, so groupBy must not sort: the
// golden files in testdata/report pin the order.
func groupBy[K comparable, T any](items []T, key func(T) K) []group[K, T] {
	var groups []group[K, T]
	index := make(map[K]int)
	for _, it := range items {
		k := key(it)
		i, ok := index[k]
		if !ok {
			i = len(groups)
			index[k] = i
			groups = append(groups, group[K, T]{key: k})
		}
		groups[i].items = append(groups[i].items, it)
	}
	return groups
}

// Report is a check result grouped and located, ready to render.
type Report struct {
	// findings are in input order. The json report lists them one by one,
	// so its missing array counts findings, not groups.
	findings []finding
	// groups holds every finding group in first-seen order. missing and
	// unverified split it in two, keeping that order. The text headers and
	// the summary line count these two slices.
	groups     []group[findingKey, finding]
	missing    []group[findingKey, finding]
	unverified []group[findingKey, finding]

	// excluded is empty unless the report shows excluded findings.
	excluded       []iam.ExcludedAction
	excludedGroups []group[excludedKey, iam.ExcludedAction]

	checked int
	label   string // what checked counts
	needs   int    // declared needs checked
}

// New builds the report of res. locations gives the file and line of each
// resource block; it may be nil. Excluded findings appear in the report only
// when showExcluded is set.
func New(res check.Result, locations iam.Locations, showExcluded bool) *Report {
	r := &Report{checked: res.Checked, label: res.Label, needs: res.Needs}
	for _, m := range res.Missing {
		f := finding{MissingAction: m}
		if loc, ok := locations.Of(m); ok {
			f.loc = &loc
		}
		r.findings = append(r.findings, f)
	}
	r.groups = groupBy(r.findings, func(f finding) findingKey {
		return findingKey{action: f.Action, class: f.Class, condition: f.ConditionAttribute, unverified: f.ResourceScopeUnverified}
	})
	for _, g := range r.groups {
		if g.key.unverified {
			r.unverified = append(r.unverified, g)
		} else {
			r.missing = append(r.missing, g)
		}
	}
	if showExcluded {
		r.excluded = res.Excluded
		r.excludedGroups = groupBy(r.excluded, func(e iam.ExcludedAction) excludedKey {
			return excludedKey{action: e.Action, reason: e.Reason}
		})
	}
	return r
}

// Write renders the report in format f. The json and github-annotations
// reports go to stdout, where a CI step or the workflow runner reads them.
// The text report writes its findings to stderr, for a person, and its
// all-clear line to stdout.
func (r *Report) Write(f Format, stdout, stderr io.Writer) {
	switch f {
	case JSON:
		fmt.Fprint(stdout, r.json())
	case GitHubAnnotations:
		if len(r.findings) > 0 {
			fmt.Fprint(stdout, r.annotations())
			fmt.Fprintf(stdout, "\n%s\n", r.summary())
		} else {
			fmt.Fprintln(stdout, r.allClear())
		}
		fmt.Fprint(stdout, r.excludedAnnotations())
	default:
		if len(r.findings) > 0 {
			fmt.Fprintf(stderr, "%s\n", r.text())
			fmt.Fprintf(stderr, "\n%s\n", r.summary())
		} else {
			fmt.Fprintln(stdout, r.allClear())
		}
		fmt.Fprint(stderr, r.excludedText())
	}
}

// checkedLabel names what the checked count covers, declared needs included.
// The json report carries the plain label, so only the text lines use this.
func (r *Report) checkedLabel() string {
	switch {
	case r.needs == 1:
		return r.label + ", 1 declared need"
	case r.needs > 1:
		return r.label + fmt.Sprintf(", %d declared needs", r.needs)
	}
	return r.label
}

// summary is the closing line of a report with findings. It mentions
// unverified findings only when there are some.
func (r *Report) summary() string {
	line := fmt.Sprintf("%d %s checked, %d distinct missing permissions found", r.checked, r.checkedLabel(), len(r.missing))
	if len(r.unverified) > 0 {
		line += fmt.Sprintf(", %d unverified (resource scope)", len(r.unverified))
	}
	return line + "."
}

// allClear is the line of a report with no findings.
func (r *Report) allClear() string {
	return fmt.Sprintf("All required permissions covered (%d %s checked).", r.checked, r.checkedLabel())
}

// source names what needs the action: the terraform resource change, or the
// declared need and the resource it is on.
func source(m iam.MissingAction) string {
	if m.Need == "" {
		return fmt.Sprintf("%s.%s (%s)", m.ResourceType, m.ResourceName, m.Change)
	}
	s := fmt.Sprintf("needs %q", m.Need)
	if m.NeedResource != "" {
		s += " on " + m.NeedResource
	}
	return s
}

// unverifiedTag marks a finding whose coverage depends on a resource scope the
// tool cannot check (--strict-resources).
const unverifiedTag = "[unverified: resource scope]"
