package iam

import (
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// Resource-scoped coverage.
//
// A policy grants actions scoped to specific resources via each statement's
// Resource patterns. When the target resource's ARN is derivable at plan time,
// matching on the action name alone is sound but not complete: it reports a
// grant covered even when the statement's Resource can never apply to the
// target (e.g. `secretsmanager:PutSecretValue` on a different secret). This
// file cross-checks action coverage against the statements' Resource patterns
// and reports the action missing when the grant is provably scoped elsewhere.

// targetRule describes how to derive the ARN patterns a terraform resource
// change acts on. Rules are keyed by resource type; a type with no rule never
// participates in resource-scoped coverage and falls back to action-only
// matching.
var targetRules = map[string]func(rc *plan.ResourceChange, all []*plan.ResourceChange) []string{
	// aws_secretsmanager_secret_version acts on the referenced secret named in
	// secret_id (aws_secretsmanager_secret.b). The secret's name is a literal
	// in the plan, so the version's ARN pattern is derivable even though the
	// version's own ARN is computed at apply time.
	"aws_secretsmanager_secret_version": secretVersionTargetARNs,
	// aws_secretsmanager_secret is itself the target; a secret's name carries
	// into its ARN.
	"aws_secretsmanager_secret": secretTargetARNs,
}

// resourceTargetARNs returns the ARN patterns a resource change acts on,
// derivable from plan-time values. It returns nil when the target cannot be
// determined (unknown values, static HCL mode, unlisted resource types), in
// which case coverage falls back to action-only matching.
func resourceTargetARNs(rc *plan.ResourceChange, all []*plan.ResourceChange) []string {
	rule, ok := targetRules[rc.Type]
	if !ok {
		return nil
	}
	return rule(rc, all)
}

// secretTargetARNs derives the ARN pattern of a secretsmanager secret from its
// configured name.
func secretTargetARNs(rc *plan.ResourceChange, _ []*plan.ResourceChange) []string {
	name := rc.AttributeValues["name"]
	if name == "" {
		return nil
	}
	return []string{secretARPattern(name)}
}

// secretVersionTargetARNs derives the ARN pattern(s) a secret version applies
// to from its secret_id: either a literal ARN known at plan time, or a
// reference to a managed secret whose configured name is known.
func secretVersionTargetARNs(rc *plan.ResourceChange, all []*plan.ResourceChange) []string {
	// A literal secret_id value (referencing an imported/external secret).
	if arn := rc.AttributeValues["secret_id"]; arn != "" && isARN(arn) {
		return []string{arn}
	}

	var patterns []string
	for _, ref := range rc.References["secret_id"] {
		resType, resName := targetFromReference(ref)
		if resType == "" {
			continue
		}
		// Reference addresses use the bare local name (aws_secretsmanager_secret.b)
		// or an indexed one (aws_secretsmanager_secret.b[0]); plan change names
		// carry the same index, so strip it from both before comparing.
		resName = stripResourceIndex(resName)
		for _, c := range all {
			if c.Type != resType {
				continue
			}
			if stripResourceIndex(c.Name) != resName {
				continue
			}
			if name := c.AttributeValues["name"]; name != "" {
				patterns = append(patterns, secretARPattern(name))
			}
		}
	}
	return patterns
}

// secretARPattern builds the ARN pattern for a secretsmanager secret named
// name. AWS appends a randomized 6-character suffix after the name, so the
// pattern matches `name-*`.
func secretARPattern(name string) string {
	return "arn:*:secretsmanager:*:*:secret:" + name + "-*"
}

// targetFromReference extracts the terraform resource type and name from a
// plan reference address such as "aws_secretsmanager_secret.b.id" or
// "module.secrets.aws_secretsmanager_secret.b". Returns ("","") when the
// address doesn't identify a managed resource.
func targetFromReference(ref string) (string, string) {
	parts := strings.Split(ref, ".")
	for i, p := range parts {
		if !strings.HasPrefix(p, "aws_") {
			continue
		}
		if i+1 >= len(parts) {
			return "", ""
		}
		return p, parts[i+1]
	}
	return "", ""
}

// isARN reports whether the string is a well-formed AWS ARN.
func isARN(s string) bool {
	parts := strings.SplitN(s, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[1] != ""
}

// coversResourceAction reports whether the policy covers action for the
// resource change rc.
//
// When the target ARN is derivable from plan values AND the policy declares an
// action match (exact action or service wildcard), the coverage check is
// resource-scoped: each Allow statement that grants the action must have a
// Resource pattern that can apply to the target. A grant scoped to a different
// resource (e.g. PutSecretValue on secret example-a while the version targets
// secret example-b) does not cover.
//
// When the target ARN can't be derived (unknown values, static HCL mode,
// resource types without a rule) — or the policy isn't a *PolicyDocument —
// coverage falls back to the legacy action-only matching (exact action or
// service wildcard). This preserves today's behavior wherever the target is
// unknown, per the resource-scope design: only provable non-coverage is
// reported.
func coversResourceAction(policy AllowedProvider, action string, rc *plan.ResourceChange, all []*plan.ResourceChange) bool {
	if !policy.Covers(action) {
		service := strings.Split(action, ":")[0]
		if !policy.Covers(service + ":*") {
			return false
		}
	}

	doc, ok := policy.(*PolicyDocument)
	if !ok {
		// Non-policy provider (test doubles, future formats): no resource
		// constraints to check, action coverage is all there is.
		return true
	}

	targets := resourceTargetARNs(rc, all)
	if len(targets) == 0 {
		// Target unknown — cannot prove the grant is scoped elsewhere.
		return true
	}
	return doc.CoversTarget(action, targets)
}

// CoversTarget reports whether the policy grants action for a resource whose
// ARN matches any of the target patterns. For every Allow statement that
// grants the action, each of its Resource patterns is tested against each
// target pattern via arnIntersect. A statement whose Resource provably cannot
// apply to the target (e.g. a grant on a different secret) does not count as
// covering it; any pattern pair whose overlap can't be decided counts as
// coverage — we only fail on provable non-overlap.
func (d *PolicyDocument) CoversTarget(action string, targets []string) bool {
	for _, s := range d.Statements {
		if s.Effect != "Allow" {
			continue
		}
		if !coversAny(s.Action, action) {
			continue
		}
		for _, res := range s.Resource {
			for _, t := range targets {
				if arnIntersect(res, t) {
					return true
				}
			}
		}
	}
	return false
}

// arnIntersect reports whether two ARN patterns can match a common ARN.
// Patterns like "arn:*:secretsmanager:*:*:secret:example-b-*" and
// "arn:aws:secretsmanager:us-east-1:111111111111:secret:example-a-*" are
// compared segment-by-segment (on ':') so a wildcard covers exactly one
// segment. This prevents a wildcard from "swallowing" colons and synthesizing
// an overlap that no real ARN would satisfy — e.g. region/account wildcards
// must not let a grant on example-a cover a target on example-b.
//
// Returns true when every segment pair may overlap (or the overlap is
// undecidable) and at least one pair provably does; false only when some pair
// provably never overlaps. A pattern with a cross-segment wildcard (e.g.
// "arn:aws:*") or a missing segment is undecidable and counts as overlap, so
// the caller only reports a gap when non-coverage is provable.
func arnIntersect(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	as := strings.Split(a, ":")
	bs := strings.Split(b, ":")
	if (len(as) == 1 && as[0] == "*") || (len(bs) == 1 && bs[0] == "*") {
		return true // "*" matches every ARN
	}
	if len(as) != len(bs) {
		// Cross-segment wildcard or malformed ARN — overlap undecidable.
		return true
	}
	for i := range as {
		may, dec := globIntersect(as[i], bs[i])
		if dec && !may {
			return false
		}
	}
	return true
}

// globIntersect reports whether two glob patterns (supporting * and ?) share
// at least one common string, and whether that result is decidable. A
// decidable answer of true means the patterns can overlap; false means they
// provably never do. When either pattern uses constructs beyond * and ?
// (brackets, ${} interpolation, character classes), the result is undecidable
// and the caller must assume overlap.
func globIntersect(patternA, patternB string) (mayIntersect, decidable bool) {
	if !globDecidable(patternA) || !globDecidable(patternB) {
		return true, false
	}

	type state [2]int
	start := state{0, 0}
	visited := map[state]bool{start: true}
	queue := []state{start}

	push := func(s state) {
		if !visited[s] {
			visited[s] = true
			queue = append(queue, s)
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		ia, ib := cur[0], cur[1]

		if ia == len(patternA) && ib == len(patternB) {
			return true, true
		}

		// Epsilon: a '*' may match the empty string, advancing past it.
		if ia < len(patternA) && patternA[ia] == '*' {
			push(state{ia + 1, ib})
		}
		if ib < len(patternB) && patternB[ib] == '*' {
			push(state{ia, ib + 1})
		}

		// Consume one character matched by both patterns.
		nextA, okA := globConsume(patternA, ia)
		nextB, okB := globConsume(patternB, ib)
		if okA && okB && globShareAnyChar(patternA[ia], patternB[ib]) {
			// Guard against self-loops (two '*'s consuming each other).
			if nextA != ia || nextB != ib {
				push(state{nextA, nextB})
			}
		}
	}

	return false, true
}

// globDecidable reports whether a pattern only uses literal characters, *,
// and ?, i.e. its intersection with another pattern is computable. Anything
// else (bracket expressions, ${} interpolation, character classes) makes the
// overlap undecidable.
func globDecidable(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*', '?':
			// supported
		case '[', ']', '{', '}', '$', '+', '(', ')', '|', '\\':
			return false
		}
	}
	return true
}

// globConsume returns the position after consuming one character at pos, and
// whether a character can be consumed there. A literal or '?' consumes exactly
// one character and advances; a '*' consumes one character while staying put
// (a self-loop).
func globConsume(pattern string, pos int) (next int, ok bool) {
	if pos >= len(pattern) {
		return 0, false
	}
	if pattern[pos] == '*' {
		return pos, true
	}
	return pos + 1, true
}

// globShareAnyChar reports whether two pattern elements at the same position
// can consume a common character.
func globShareAnyChar(a, b byte) bool {
	if a == '*' || b == '*' {
		return true
	}
	if a == '?' || b == '?' {
		return true
	}
	return a == b
}
