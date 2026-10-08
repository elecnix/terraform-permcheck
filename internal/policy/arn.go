package policy

import "strings"

// ARN algebra.
//
// A target pattern stands for the ARNs a resource may have, and a policy
// Resource pattern for the ARNs a statement names. These functions decide
// whether two such patterns can share an ARN.

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
