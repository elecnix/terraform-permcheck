package policy

import "strings"

// Coverage.
//
// Every check of the form "does the policy grant this action for this
// resource?" goes through Coverage: each requirement the iam package checks,
// schema and implied alike, and each declared need. A requirement carries the
// target ARN patterns its action acts on, or none when the plan does not show
// them. Coverage then applies one rule set, so the checks cannot drift apart.

// Verdict is the answer to one coverage question.
type Verdict int

const (
	// Covered means the policy grants the action, or the tool cannot prove
	// that it does not.
	Covered Verdict = iota
	// Missing means the policy provably does not grant the action.
	Missing
	// Unverified means the policy grants the action only on some resources
	// and the target is unknown (--strict-resources).
	Unverified
)

func (v Verdict) String() string {
	switch v {
	case Covered:
		return "covered"
	case Missing:
		return "missing"
	case Unverified:
		return "unverified"
	default:
		return "unknown"
	}
}

// Coverage reports whether the policy grants action on a resource matching
// any of the target ARN patterns. An empty targets list means the target is
// unknown. Then the action alone decides, except that with strict set, a grant
// limited to some resources is Unverified instead of Covered.
func (d *Document) Coverage(action string, targets []string, strict bool) Verdict {
	if len(targets) > 0 {
		if d.CoversTarget(action, targets) {
			return Covered
		}
		return Missing
	}
	if !d.Covers(action) {
		return Missing
	}
	if strict && d.grantsOnlyOnScopedResources(action) {
		return Unverified
	}
	return Covered
}

// CoversTarget reports whether the policy grants action for a resource whose
// ARN matches any of the target patterns.
//
// For each target, an Allow statement that names the action covers it unless
// its Resource provably cannot apply to the target (e.g. a grant on a
// different secret) or its NotResource provably contains the target. Any
// pattern pair whose overlap can't be decided counts as coverage.
//
// A Deny statement that names the action overrides the Allow only when it
// provably applies to the whole target pattern and has no Condition. A Deny
// that only overlaps the target, or whose Condition the tool cannot evaluate,
// does not count: we only fail on provable non-coverage.
//
// A rule can list several ARN forms of one target, such as log-group:<name>
// and log-group:<name>:*. An Allow Resource pattern with as many segments as
// one of those forms is compared with the forms of that length only. Compared
// with a form of another length, the overlap is undecidable and would always
// count as coverage.
func (d *Document) CoversTarget(action string, targets []string) bool {
	for _, t := range targets {
		if d.coversOneTarget(action, t, targets) {
			return true
		}
	}
	return false
}

func (d *Document) coversOneTarget(action, target string, forms []string) bool {
	allowed := false
	for _, s := range d.Statements {
		if !s.matchesAction(action) {
			continue
		}
		switch s.Effect {
		case "Deny":
			if !s.conditional() && s.appliesToAll(target) {
				return false
			}
		case "Allow":
			if s.mayApplyTo(target, forms) {
				allowed = true
			}
		}
	}
	return allowed
}

// targetsLike returns the targets with as many ARN segments as pattern, or
// every target when none has that many.
func targetsLike(pattern string, targets []string) []string {
	n := strings.Count(pattern, ":")
	var like []string
	for _, t := range targets {
		if strings.Count(t, ":") == n {
			like = append(like, t)
		}
	}
	if len(like) == 0 {
		return targets
	}
	return like
}

// WorstVerdict checks action against each target and returns the worst
// verdict. Each target is the list of ARN forms of one resource the change
// acts on, and every one of them must be covered. With no targets, the
// action alone decides.
func (d *Document) WorstVerdict(action string, targets [][]string, strict bool) Verdict {
	if len(targets) == 0 {
		return d.Coverage(action, nil, strict)
	}
	worst := Covered
	for _, forms := range targets {
		switch d.Coverage(action, forms, strict) {
		case Missing:
			return Missing
		case Unverified:
			worst = Unverified
		}
	}
	return worst
}
