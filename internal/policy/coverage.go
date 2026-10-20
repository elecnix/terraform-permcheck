package policy

import "strings"

// Coverage.
//
// Every check of the form "does the policy grant this action for this
// resource?" goes through Coverage: each requirement the iam package checks,
// schema and implied alike, and each declared need. A requirement carries
// the target ARN patterns its action acts on, or none when the plan does not
// show them, and the condition key values the plan supplies. Coverage then
// applies one rule set, so the checks cannot drift apart.

// Verdict is the answer to one coverage question.
type Verdict int

const (
	// Covered means the policy grants the action, or the tool cannot prove
	// that it does not.
	Covered Verdict = iota
	// Missing means the policy provably does not grant the action.
	Missing
	// Unverified means the policy grants the action only where the tool
	// cannot check the grant (--strict-resources).
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

// UnverifiedReason names why the tool could not check a grant.
type UnverifiedReason int

const (
	// ReasonNone is no reason: the verdict is not Unverified.
	ReasonNone UnverifiedReason = iota
	// ReasonResourceScope means the target ARN is unknown and the policy
	// grants the action only on some resources.
	ReasonResourceScope
	// ReasonCondition means a condition on the grant names a key the plan
	// does not supply, or an operator the tool does not model.
	ReasonCondition
)

func (r UnverifiedReason) String() string {
	switch r {
	case ReasonResourceScope:
		return "resource scope"
	case ReasonCondition:
		return "condition"
	default:
		return ""
	}
}

// Value is the discriminator the json report carries for the reason:
// "resource_scope" or "condition". It is what a consumer matches on.
func (r UnverifiedReason) Value() string {
	switch r {
	case ReasonResourceScope:
		return "resource_scope"
	case ReasonCondition:
		return "condition"
	default:
		return ""
	}
}

// Result is a coverage answer: the verdict, and the reason when the tool
// could not verify the grant.
type Result struct {
	// Verdict is the answer.
	Verdict Verdict
	// Reason says why the tool could not check the grant. It is set only
	// when the verdict is Unverified.
	Reason UnverifiedReason
}

// Coverage reports whether the policy grants action on a resource matching
// any of the target ARN patterns. An empty targets list means the target is
// unknown. conds holds the condition key values the plan supplies.
//
// A condition that provably cannot match the plan's value means the grant
// does not apply, so the action is Missing. A condition the tool cannot
// evaluate means the grant may or may not apply: it counts as coverage, and
// with strict set the action is Unverified.
func (d *Document) Coverage(action string, targets []string, conds Conditions, strict bool) Result {
	if len(targets) > 0 {
		covered, conditionUnknown := d.coversTarget(action, targets, conds)
		if !covered {
			return Result{Verdict: Missing}
		}
		if strict && conditionUnknown {
			return Result{Verdict: Unverified, Reason: ReasonCondition}
		}
		return Result{Verdict: Covered}
	}

	granted, scoped, conditionUnknown := d.grantsWithoutTarget(action, conds)
	if !granted && !scoped && !conditionUnknown {
		return Result{Verdict: Missing}
	}
	if strict {
		// The condition reason comes first: it names the finer-grained
		// mechanism the tool could not check.
		if conditionUnknown && !granted {
			return Result{Verdict: Unverified, Reason: ReasonCondition}
		}
		if scoped && !granted {
			return Result{Verdict: Unverified, Reason: ReasonResourceScope}
		}
	}
	return Result{Verdict: Covered}
}

// grantsWithoutTarget reports what the tool concluded about the grants of an
// action whose target resource is unknown.
//
// granted reports that an Allow statement grants the action on every
// resource, with no condition the tool cannot check. scoped reports that a
// grant is limited to some resources, whose ARN the plan does not show.
// conditionUnknown reports that a grant carries a condition the tool cannot
// evaluate, so the grant may or may not apply.
//
// A grant on every resource settles the action: it is granted whatever the
// target, so the other grants do not narrow it.
func (d *Document) grantsWithoutTarget(action string, conds Conditions) (granted, scoped, conditionUnknown bool) {
	for _, s := range d.Statements {
		if !s.matchesAction(action) {
			continue
		}
		switch s.Effect {
		case "Deny":
			if !s.conditional() && s.deniesEveryResource() {
				return false, false, false
			}
		case "Allow":
			switch s.conditionVerdict(conds) {
			case condFails:
				// The grant provably does not apply.
				continue
			case condHolds:
				if s.grantsEveryResource() {
					granted = true
				} else {
					scoped = true
				}
			default:
				// The condition is one the tool cannot evaluate, so
				// the grant may or may not apply.
				conditionUnknown = true
			}
		}
	}
	return granted, scoped, conditionUnknown
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
	covered, _ := d.coversTarget(action, targets, nil)
	return covered
}

// coversTarget reports whether the policy grants action for a resource
// matching any of the target patterns, and whether the grant that reaches it
// carries a condition the tool cannot evaluate.
func (d *Document) coversTarget(action string, targets []string, conds Conditions) (covered, conditionUnknown bool) {
	for _, t := range targets {
		c, u := d.coversOneTarget(action, t, targets, conds)
		if c {
			return true, u
		}
	}
	return false, false
}

// coversOneTarget reports whether the policy grants action for a target, and
// whether the grant carries a condition the tool cannot evaluate.
//
// A grant whose condition holds settles the target: the tool checked it, so
// the target is covered and not unverified.
func (d *Document) coversOneTarget(action, target string, forms []string, conds Conditions) (covered, conditionUnknown bool) {
	allowed := false
	unknown := false
	for _, s := range d.Statements {
		if !s.matchesAction(action) {
			continue
		}
		switch s.Effect {
		case "Deny":
			if !s.conditional() && s.appliesToAll(target) {
				return false, false
			}
		case "Allow":
			if !s.mayApplyTo(target, forms) {
				continue
			}
			switch s.conditionVerdict(conds) {
			case condFails:
				// The grant provably does not apply.
			case condHolds:
				allowed = true
			default:
				// The condition is one the tool cannot evaluate, so
				// the grant may or may not apply.
				unknown = true
			}
		}
	}
	if allowed {
		return true, false
	}
	return unknown, unknown
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
func (d *Document) WorstVerdict(action string, targets [][]string, conds Conditions, strict bool) Result {
	if len(targets) == 0 {
		return d.Coverage(action, nil, conds, strict)
	}
	worst := Result{Verdict: Covered}
	for _, forms := range targets {
		res := d.Coverage(action, forms, conds, strict)
		switch res.Verdict {
		case Missing:
			return res
		case Unverified:
			worst = res
		}
	}
	return worst
}
