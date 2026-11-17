package policy

import (
	"sort"
	"strings"
)

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
	// does not supply, or an operator the tool does not model. A statement
	// that may grant, such as a resource policy statement whose Principal
	// may match, carries this reason too.
	ReasonCondition
	// ReasonPolicyUnknown means the grant comes from a policy source whose
	// text the plan does not show (see UnknownSource).
	ReasonPolicyUnknown
	// ReasonCrossAccount means the need crosses accounts and the resource
	// policy in the other account is not in the plan (see
	// CrossAccountSource). It comes last in the order of firstReason, so a
	// grant the tool read on the resource side, or a resource policy whose
	// text is computed, names the reason first. Between the identity side
	// and the resource side, the identity side's reason comes first.
	ReasonCrossAccount
)

func (r UnverifiedReason) String() string {
	switch r {
	case ReasonResourceScope:
		return "resource scope"
	case ReasonCondition:
		return "condition"
	case ReasonPolicyUnknown:
		return "policy unknown"
	case ReasonCrossAccount:
		return "cross account"
	default:
		return ""
	}
}

// Value is the discriminator the json report carries for the reason:
// "resource_scope", "condition", "policy_unknown" or "cross_account". It is
// what a consumer matches on.
func (r UnverifiedReason) Value() string {
	switch r {
	case ReasonResourceScope:
		return "resource_scope"
	case ReasonCondition:
		return "condition"
	case ReasonPolicyUnknown:
		return "policy_unknown"
	case ReasonCrossAccount:
		return "cross_account"
	default:
		return ""
	}
}

// firstReason returns the reason to report when two apply to the grants that
// reach an action. ReasonNone yields to any reason. Otherwise the order is
// condition, resource scope, policy unknown, cross account. A reason about a
// statement the tool read comes before a reason about a source it could not
// read: the read statement stays unchecked even once the unknown text is
// known, so it names the finer-grained mechanism. Condition comes before
// resource scope for the same reason.
func firstReason(a, b UnverifiedReason) UnverifiedReason {
	if a == ReasonNone {
		return b
	}
	if b == ReasonNone {
		return a
	}
	if reasonRank(b) < reasonRank(a) {
		return b
	}
	return a
}

// reasonRank orders the reasons for firstReason. A lower rank comes first.
func reasonRank(r UnverifiedReason) int {
	switch r {
	case ReasonCondition:
		return 0
	case ReasonResourceScope:
		return 1
	case ReasonPolicyUnknown:
		return 2
	default:
		return 3
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
	// Boundary names the permissions boundary that makes the verdict
	// Missing while the other policies allow the action, such as the
	// address of the aws_iam_policy that holds the boundary's text. It is
	// empty for any other result. Document.Coverage never sets it: the
	// policy set of a mapped principal does.
	Boundary string
}

// Coverage reports whether the policy grants action on a resource matching
// any of the target ARN patterns. An empty targets list means the target is
// unknown. conds holds the condition key values the plan supplies.
//
// A condition that provably cannot match the plan's value means the grant
// does not apply, so the action is Missing. A condition the tool cannot
// evaluate means the grant may or may not apply: it counts as coverage, and
// with strict set the action is Unverified. A statement marked with
// Statement.Unverified behaves the same way, with the reason it carries.
// When several unchecked grants reach the action, firstReason picks the
// reason. A grant the tool checked settles the action, so the verdict is
// then Covered with no reason, in strict mode too.
func (d *Document) Coverage(action string, targets []string, conds Conditions, strict bool) Result {
	if len(targets) > 0 {
		covered, unknown := d.coversTarget(action, targets, conds)
		if !covered {
			return Result{Verdict: Missing}
		}
		if strict && unknown != ReasonNone {
			return Result{Verdict: Unverified, Reason: unknown}
		}
		return Result{Verdict: Covered}
	}

	granted, scoped, unknown := d.grantsWithoutTarget(action, conds)
	if !granted && !scoped && unknown == ReasonNone {
		return Result{Verdict: Missing}
	}
	if strict && !granted {
		// firstReason picks the reason when both a scoped grant and an
		// unchecked one reach the action.
		reason := unknown
		if scoped {
			reason = firstReason(reason, ReasonResourceScope)
		}
		return Result{Verdict: Unverified, Reason: reason}
	}
	return Result{Verdict: Covered}
}

// CoverageOfEveryResource reports whether the policy grants action on every
// resource, as a declared need on "*" requires.
//
// Only an Allow on every resource can cover every resource, so a grant
// limited to some resources is no coverage, with or without a condition. A
// grant on every resource whose condition the tool cannot evaluate may or may
// not apply: it counts as coverage, and with strict set the action is
// Unverified, as in Coverage. An unconditional Deny on every resource
// overrides any grant.
func (d *Document) CoverageOfEveryResource(action string, strict bool) Result {
	granted, unknown := false, ReasonNone
	for _, s := range d.Statements {
		if !s.matchesAction(action) {
			continue
		}
		switch s.Effect {
		case "Deny":
			if !s.conditional() && s.deniesEveryResource() {
				return Result{Verdict: Missing}
			}
		case "Allow":
			if !s.grantsEveryResource() {
				continue
			}
			switch verdict, reason := s.grantVerdict(nil); verdict {
			case condFails:
				// The grant provably does not apply.
			case condHolds:
				granted = true
			default:
				unknown = firstReason(unknown, reason)
			}
		}
	}
	switch {
	case granted:
		return Result{Verdict: Covered}
	case unknown != ReasonNone && strict:
		return Result{Verdict: Unverified, Reason: unknown}
	case unknown != ReasonNone:
		return Result{Verdict: Covered}
	}
	return Result{Verdict: Missing}
}

// grantsWithoutTarget reports what the tool concluded about the grants of an
// action whose target resource is unknown.
//
// granted reports that an Allow statement grants the action on every
// resource, with no condition the tool cannot check. scoped reports that a
// grant is limited to some resources, whose ARN the plan does not show.
// unknown is the reason the tool could not check a grant that may or may not
// apply, such as a condition it cannot evaluate, or ReasonNone when every
// grant was checked.
//
// A grant on every resource settles the action: it is granted whatever the
// target, so the other grants do not narrow it.
func (d *Document) grantsWithoutTarget(action string, conds Conditions) (granted, scoped bool, unknown UnverifiedReason) {
	for _, s := range d.Statements {
		if !s.matchesAction(action) {
			continue
		}
		switch s.Effect {
		case "Deny":
			if !s.conditional() && s.deniesEveryResource() {
				return false, false, ReasonNone
			}
		case "Allow":
			switch verdict, reason := s.grantVerdict(conds); verdict {
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
				// The tool cannot check the grant, so it may or may
				// not apply.
				unknown = firstReason(unknown, reason)
			}
		}
	}
	return granted, scoped, unknown
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
// matching any of the target patterns, and why the tool could not check the
// grant that reaches it. The reason is ReasonNone when a checked grant
// reaches it.
//
// A target reached by a grant whose condition holds is covered and checked.
// A target reached only by a grant the tool cannot check, such as one whose
// condition it cannot evaluate, is covered too, but not checked.
func (d *Document) coversTarget(action string, targets []string, conds Conditions) (covered bool, unknown UnverifiedReason) {
	verified := false
	for _, t := range targets {
		c, u := d.coversOneTarget(action, t, targets, conds)
		verified = verified || c
		unknown = firstReason(unknown, u)
	}
	// A target reached by a checked grant settles the resource, so the
	// unknown one does not make it unverified.
	if verified {
		return true, ReasonNone
	}
	return unknown != ReasonNone, unknown
}

// coversOneTarget reports whether a grant the tool checked reaches the
// target, and why the tool could not check the other grants that reach it.
// The reason is ReasonNone when no unchecked grant reaches it.
//
// A grant whose condition holds settles the target: the tool checked it, so
// the target is covered and not unverified.
func (d *Document) coversOneTarget(action, target string, forms []string, conds Conditions) (verified bool, unknown UnverifiedReason) {
	for _, s := range d.Statements {
		if !s.matchesAction(action) {
			continue
		}
		switch s.Effect {
		case "Deny":
			if !s.conditional() && s.appliesToAll(target) {
				return false, ReasonNone
			}
		case "Allow":
			if !s.mayApplyTo(target, forms) {
				continue
			}
			switch verdict, reason := s.grantVerdict(conds); verdict {
			case condFails:
				// The grant provably does not apply.
			case condHolds:
				// The grant reaches the target and the tool checked
				// it, so the target is covered and not unverified. A
				// later Deny may still override it, so the loop goes
				// on.
				verified = true
			default:
				// The tool cannot check the grant, so it may or may
				// not apply.
				unknown = firstReason(unknown, reason)
			}
		}
	}
	return verified, unknown
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

// GrantedResources returns the Resource patterns of the Allow statements
// that grant action, sorted and without duplicates. A statement whose
// condition provably fails does not grant the action, and one with a
// NotResource has no pattern to list, so neither counts.
//
// It returns nil when the policy grants the action on every resource, or
// when an unconditional Deny covers every resource, or when no statement
// grants it: a miss is then not about the grant being
// limited to other resources, so there is nothing to name.
func (d *Document) GrantedResources(action string) []string {
	seen := map[string]bool{}
	for _, s := range d.Statements {
		if !s.matchesAction(action) {
			continue
		}
		if s.Effect == "Deny" {
			// A Deny on every resource is why the grant falls short, not
			// the resources the grant names.
			if !s.conditional() && s.deniesEveryResource() {
				return nil
			}
			continue
		}
		if s.Effect != "Allow" || s.conditionVerdict(nil) == condFails {
			continue
		}
		if s.grantsEveryResource() {
			return nil
		}
		for _, r := range s.Resource {
			seen[r] = true
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
