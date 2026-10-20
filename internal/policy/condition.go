package policy

import (
	"encoding/json"
	"strings"
)

// Conditions.
//
// A statement's Condition block says when the statement applies. AWS
// evaluates it against the request context; the tool knows only part of that
// context — the values the plan shows. This file decodes the block and
// matches it against the values the plan supplies.
//
// A match has three answers, never two: holds, fails and unknown. "fails" is
// only reported when the tool can prove the condition cannot be met, because
// a false "fails" turns a granted permission into a reported gap. Every
// other case is unknown, and an unknown condition is a grant the tool cannot
// check.

// conditionResult is what matching a condition against the plan's context
// concluded.
type conditionResult int

const (
	// condHolds means the condition matches the context the plan shows, or
	// could match it.
	condHolds conditionResult = iota
	// condFails means the condition provably cannot match.
	condFails
	// condUnknown means the tool cannot decide: the key is not one the
	// plan supplies, the operator is not one it models, or the value is
	// not comparable.
	condUnknown
)

func (r conditionResult) String() string {
	switch r {
	case condHolds:
		return "holds"
	case condFails:
		return "fails"
	default:
		return "unknown"
	}
}

// Conditions holds the condition key values the plan supplies, keyed by
// condition key name. AWS reads context key names without regard to case,
// so the names are compared with strings.EqualFold.
type Conditions map[string]string

// lookup returns the value the plan supplies for a condition key.
func (c Conditions) lookup(key string) (string, bool) {
	for k, v := range c {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// conditionBlock is a decoded Condition block: operators, each with the
// condition keys it names and the values each key is compared against.
//
// A block the tool cannot read is unreadable, not absent: a statement with
// an unreadable condition is still conditional, so its Deny is still not
// definite and its Allow is still a grant.
type conditionBlock struct {
	// operators lists the operators the block names.
	operators []string
	// keys holds, per operator, the condition keys it names. A key the
	// block states in a shape the tool cannot read is absent from the map
	// and its value is unreadable, so one bad key does not poison the
	// others.
	keys map[string]map[string]conditionValue
	// unreadable lists the operators whose block the tool could not read.
	unreadable []string
}

// conditionValue is the value a condition key is compared against: a string,
// or a list of strings.
type conditionValue struct {
	values []string
	// readable reports whether the tool could read the value. A value of
	// another shape (a number, an object) is not readable.
	readable bool
}

// UnmarshalJSON reads a Condition block. It never fails: a block the tool
// cannot read yields an unreadable block, and the statement stays
// conditional.
func (c *conditionBlock) UnmarshalJSON(b []byte) error {
	*c = conditionBlock{keys: map[string]map[string]conditionValue{}}
	var operators map[string]json.RawMessage
	if err := json.Unmarshal(b, &operators); err != nil {
		c.unreadable = []string{""}
		return nil
	}
	for operator, keysRaw := range operators {
		c.operators = append(c.operators, operator)
		var keys map[string]conditionValueField
		if err := json.Unmarshal(keysRaw, &keys); err != nil {
			c.unreadable = append(c.unreadable, operator)
			continue
		}
		readable := map[string]conditionValue{}
		for key, v := range keys {
			readable[key] = v.value
		}
		c.keys[operator] = readable
	}
	return nil
}

// conditionValueField handles the union of string and []string in JSON, and
// records a shape the tool cannot read as unreadable rather than failing the
// whole policy: a condition the tool cannot read is unknown, and an unknown
// condition never becomes a reported gap.
type conditionValueField struct {
	value conditionValue
}

func (c *conditionValueField) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		c.value = conditionValue{values: []string{s}, readable: true}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err == nil {
		c.value = conditionValue{values: ss, readable: true}
		return nil
	}
	c.value = conditionValue{readable: false}
	return nil
}

// set reports whether the block places any condition on the statement. An
// empty block sets none. A block the tool could not read does: the tool
// cannot tell what it says, so it cannot treat the statement as
// unconditional.
func (c conditionBlock) set() bool {
	return len(c.operators) > 0 || len(c.unreadable) > 0
}

// conditional reports whether the statement carries a Condition. The tool
// cannot evaluate every condition, so a conditional Deny never counts as a
// definite deny, and a conditional Allow still counts as an allow: either way
// only provable gaps are reported. An empty Condition block sets no
// condition.
func (s Statement) conditional() bool {
	return s.Condition.set()
}

// conditionOperator is one condition operator the tool models.
type conditionOperator struct {
	// arn reports whether the operator compares ARNs (ArnEquals,
	// ArnLike). Those compare the six colon-delimited components of an
	// ARN one by one, so two patterns can be shown to be disjoint.
	arn bool
	// exact reports whether the operator compares whole strings with no
	// wildcard (StringEquals). The other modelled operator, StringLike,
	// supports wildcards anywhere, and no decidable test says two
	// wildcard patterns are disjoint, so it never proves a mismatch.
	exact bool
}

// conditionOperators are the operators the tool models. Every other
// operator — Bool, NumericEquals, DateEquals, the IfExists variants, the
// ForAnyValue: and ForAllValues: prefixes — is unknown, because the tool
// cannot tell what they mean for the value the plan shows.
//
// The names are exact: AWS writes them as documented, and a policy that
// names one differently does not name the operator.
var conditionOperators = map[string]conditionOperator{
	"ArnEquals":    {arn: true},
	"ArnLike":      {arn: true},
	"StringEquals": {exact: true},
	"StringLike":   {},
}

// conditionVerdict reports what the statement's condition concludes for the
// context the plan supplies. A statement with no condition holds; one whose
// condition provably cannot match fails; one the tool cannot evaluate is
// unknown.
func (s Statement) conditionVerdict(conds Conditions) conditionResult {
	if !s.conditional() {
		return condHolds
	}
	return matchCondition(s.Condition, conds)
}

// conditionHolds reports whether the statement's condition lets it apply for
// the context the plan supplies. A condition that provably cannot match does
// not hold, so the statement grants nothing.
func (s Statement) conditionHolds(conds Conditions) bool {
	return s.conditionVerdict(conds) != condFails
}

// matchCondition reports whether a condition block holds for the context the
// plan supplies.
//
// A condition is a conjunction: it holds only when every operator and every
// key it names holds. So a key the plan does not supply, or an operator the
// tool does not model, leaves the condition unknown, and one key that
// provably cannot match makes the whole condition fail.
func matchCondition(block conditionBlock, conds Conditions) conditionResult {
	if len(block.unreadable) > 0 {
		// The tool could not read the block, so it cannot tell what it
		// says.
		return condUnknown
	}
	worst := condHolds
	for _, operator := range block.operators {
		keys, ok := block.keys[operator]
		if !ok {
			// The operator's block is unreadable, so the tool cannot
			// tell what it says.
			worst = worse(worst, condUnknown)
			continue
		}
		if len(keys) == 0 {
			// The operator names no key, so it places no condition.
			continue
		}
		op, modelled := conditionOperators[operator]
		if !modelled {
			// An operator the tool does not model, including the
			// IfExists variants and the set-operator prefixes.
			worst = worse(worst, condUnknown)
			continue
		}
		for key, policyValue := range keys {
			value, supplied := conds.lookup(key)
			if !supplied {
				// The plan does not show this key, so the tool cannot
				// compare it.
				worst = worse(worst, condUnknown)
				continue
			}
			worst = worse(worst, matchConditionKey(op, policyValue, value))
		}
	}
	return worst
}

// matchConditionKey reports what one condition key's comparison concludes.
// value is the plan's value for the key.
func matchConditionKey(op conditionOperator, policyValue conditionValue, value string) conditionResult {
	if !policyValue.readable || len(policyValue.values) == 0 {
		return condUnknown
	}
	result := condFails
	for _, v := range policyValue.values {
		r := matchValue(op, v, value)
		if r != condFails {
			// AWS matches a key against any of the values the policy
			// names, so one value that can match holds the key.
			result = r
			break
		}
	}
	return result
}

// matchValue reports what comparing the policy's value against the plan's
// value concludes. A pattern that can match the value holds; a pattern that
// provably cannot match it fails.
func matchValue(op conditionOperator, pattern, value string) conditionResult {
	switch {
	case op.arn:
		// ArnEquals and ArnLike behave identically: each of the
		// colon-delimited components of an ARN is compared on its own,
		// with * and ? wildcards inside a component.
		may, decidable := arnPatternsIntersect(pattern, value)
		if !decidable {
			return condUnknown
		}
		if may {
			return condHolds
		}
		return condFails
	case op.exact:
		// StringEquals is exact and case-sensitive.
		if pattern == value {
			return condHolds
		}
		return condFails
	default:
		// StringLike supports * and ? anywhere, and no decidable test
		// says two wildcard patterns are disjoint, so it can hold but
		// never fail.
		return condHolds
	}
}

// arnPatternsIntersect reports whether the policy's ARN pattern can match
// the plan's ARN, and whether that is decidable. A value that is not an ARN,
// or a pattern whose shape the test cannot decide on, gives an undecidable
// answer, so the tool never claims a mismatch it cannot prove.
//
// The comparison is over the six colon-delimited components of an ARN, each
// on its own, with * and ? wildcards inside a component. The components are
// compared as they are, so a pattern that spells the ARN differently from
// AWS does — "ARN:AWS:..." — simply does not match, as AWS's
// case-sensitive comparison would have it.
func arnPatternsIntersect(pattern, value string) (mayIntersect, decidable bool) {
	if pattern == "*" || value == "*" {
		// A wildcard pattern matches every ARN.
		return true, true
	}
	// The plan's value must be a real ARN: the tool cannot compare an ARN
	// pattern with a bare function name.
	if !isARN(value) {
		return true, false
	}
	as, aok := arnComponents(pattern)
	bs, bok := arnComponents(value)
	if !aok || !bok || len(as) != len(bs) {
		return true, false
	}
	// A pair of components that provably never matches settles the whole
	// comparison, whatever the other components hold.
	for i := range as {
		if may, dec := globIntersect(as[i], bs[i]); dec && !may {
			return false, true
		}
	}
	// Without such a pair, the patterns overlap unless a component's
	// overlap is undecidable.
	for i := range as {
		if _, dec := globIntersect(as[i], bs[i]); !dec {
			return true, false
		}
	}
	return true, true
}

// isARN reports whether a string is a well-formed AWS ARN.
func isARN(s string) bool {
	parts := strings.SplitN(s, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[1] != ""
}

// arnComponents splits an ARN into its six colon-delimited components. The
// last one holds the resource part, which may itself hold colons. It
// reports false when the string has no ARN shape.
func arnComponents(s string) ([]string, bool) {
	parts := strings.SplitN(s, ":", 6)
	if len(parts) != 6 {
		return nil, false
	}
	return parts, true
}

// worse returns the result that says less: a failure beats an unknown, and
// an unknown beats a hold. A condition holds only when every part of it
// holds.
func worse(a, b conditionResult) conditionResult {
	if a == condFails || b == condFails {
		return condFails
	}
	if a == condUnknown || b == condUnknown {
		return condUnknown
	}
	return condHolds
}
