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

// targetRules describe how to derive the resources a terraform resource
// change acts on. A rule returns one target per resource, each the list of ARN
// patterns that resource can take, and every target must be covered. Rules
// are keyed by resource type; a type with no rule never participates in
// resource-scoped coverage and falls back to action-only matching.
var targetRules = map[string]func(rc *plan.ResourceChange, set *changeSet) [][]string{
	// aws_secretsmanager_secret_version acts on the referenced secret named in
	// secret_id (aws_secretsmanager_secret.b). The secret's name is a literal
	// in the plan, so the version's ARN pattern is derivable even though the
	// version's own ARN is computed at apply time.
	"aws_secretsmanager_secret_version": secretVersionTargetARNs,
	// aws_secretsmanager_secret is itself the target; a secret's name carries
	// into its ARN.
	"aws_secretsmanager_secret": ownTarget(secretARNPatterns),
	// aws_sqs_queue is its own target; the queue name is the last ARN segment.
	"aws_sqs_queue": ownTarget(sqsQueueARNPatterns),
	// aws_cloudwatch_log_group is its own target; the group name carries into
	// its ARN.
	"aws_cloudwatch_log_group": ownTarget(logGroupARNsOf),
	// aws_cloudwatch_log_stream acts on the group named in log_group_name,
	// either a known value or a reference to a managed log group.
	"aws_cloudwatch_log_stream": logStreamTargetARNs,
}

// resourceTargets returns the targets a resource change acts on, derivable
// from plan-time values: one list of ARN patterns per resource. It returns nil
// when the target cannot be determined (unknown values, static HCL mode,
// unlisted resource types), in which case coverage falls back to action-only
// matching.
func resourceTargets(rc *plan.ResourceChange, set *changeSet) [][]string {
	rule, ok := targetRules[rc.Type]
	if !ok {
		return nil
	}
	return rule(rc, set)
}

// ownTarget returns a target rule for a resource that acts on itself: its one
// target has the ARN patterns arnPatterns builds from it, when they are known.
func ownTarget(arnPatterns func(*plan.ResourceChange) []string) func(*plan.ResourceChange, *changeSet) [][]string {
	return func(rc *plan.ResourceChange, _ *changeSet) [][]string {
		if forms := arnPatterns(rc); forms != nil {
			return [][]string{forms}
		}
		return nil
	}
}

// secretVersionTargetARNs derives the secrets a secret version applies to
// from its secret_id: either a literal ARN known at plan time, or a reference
// to managed secrets whose configured names are known.
func secretVersionTargetARNs(rc *plan.ResourceChange, set *changeSet) [][]string {
	return attributeTargets(rc, set, "secret_id", "aws_secretsmanager_secret", secretARNPatterns)
}

// logStreamTargetARNs derives the ARN patterns a CloudWatch Logs stream acts
// on: its group, in both log-group forms, and the stream itself.
func logStreamTargetARNs(rc *plan.ResourceChange, set *changeSet) [][]string {
	stream := rc.AttributeValues["name"]
	var groups []string
	if group := rc.AttributeValues["log_group_name"]; group != "" {
		groups = []string{group}
	} else {
		for _, c := range referencedChanges(rc, set, "log_group_name", "aws_cloudwatch_log_group") {
			if name := c.AttributeValues["name"]; name != "" {
				groups = append(groups, name)
			}
		}
	}
	var targets [][]string
	for _, group := range groups {
		forms := logGroupARNPatterns(group)
		if stream != "" {
			forms = append(forms, "arn:*:logs:*:*:log-group:"+group+":log-stream:"+stream)
		}
		targets = append(targets, forms)
	}
	return targets
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
