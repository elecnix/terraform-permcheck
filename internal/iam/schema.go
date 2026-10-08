package iam

import "errors"

// Requirement is one path on which an operation on a resource reaches an
// action: the action, and the gate that decides whether the provider makes the
// call on that path. A requirement whose gate sets no test is always needed.
// An action the provider reaches on several paths has one requirement per
// path, and it is needed when any of their gates holds. The gate is part of
// the record, so a producer cannot list an action in one place and forget its
// gate in another.
type Requirement struct {
	// Action is the IAM action, e.g. "kms:CreateGrant".
	Action string
	// Gate is the path's gate: a presence attribute (and whether the guard
	// compares its value), a change attribute, and whether the provider
	// ignores the call's failure.
	Gate
}

// Unconditional returns one ungated requirement per action, in order.
func Unconditional(actions ...string) []Requirement {
	if actions == nil {
		return nil
	}
	reqs := make([]Requirement, len(actions))
	for i, a := range actions {
		reqs[i] = Requirement{Action: a}
	}
	return reqs
}

// Schema lists the requirements of each operation on one resource type.
// Every source emits it: the CloudFormation registry adapter in cloud, the
// provider-source parser in provideraws and the embedded table in permdata.
type Schema struct {
	// TypeName names the type in the source's own terms, such as
	// aws_kms_key or AWS::KMS::Key.
	TypeName string

	// Ops maps "create", "read", "update", "delete" and "list" to the
	// requirements of that operation, one per path that reaches an action.
	// An operation the source knows but that needs no permissions is
	// present with an empty list.
	Ops map[string][]Requirement

	// Incomplete names the operations whose permissions the source could not
	// fully determine, such as a create in which the provider-source parser
	// found no call that creates anything. A resolver chain merges in a
	// later source's requirements for these operations.
	Incomplete map[string]bool
}

// Requirements returns the requirements of op ("create", "read", "update",
// "delete" or "list"). The boolean reports whether the schema knows op at
// all: a known operation can have no requirements, and only an unknown one
// falls back to create.
func (s *Schema) Requirements(op string) ([]Requirement, bool) {
	reqs, ok := s.Ops[op]
	return reqs, ok
}

// Actions lists the distinct actions op requires, in the order each first
// appears.
func (s *Schema) Actions(op string) []string {
	var actions []string
	seen := make(map[string]bool, len(s.Ops[op]))
	for _, r := range s.Ops[op] {
		if !seen[r.Action] {
			seen[r.Action] = true
			actions = append(actions, r.Action)
		}
	}
	return actions
}

// Gates returns the gate of every path on which op reaches action, in order.
func (s *Schema) Gates(op, action string) []Gate {
	var gates []Gate
	for _, r := range s.Ops[op] {
		if r.Action == action {
			gates = append(gates, r.Gate)
		}
	}
	return gates
}

// Resolver maps a terraform resource type to its Schema. A resolver that
// fails marks its error with ErrUnknownType or ErrLookupFailed, so Validate
// can tell a type no source knows from a lookup that did not finish. An
// unmarked error counts as ErrUnknownType. The schema may be shared: callers
// must not change it.
type Resolver interface {
	Resolve(tfType string) (*Schema, error)
}

// ErrUnknownType marks a resolver error that says no source has permission
// data for the type. Validate reports the type as unresolved.
var ErrUnknownType = errors.New("resource type unknown to every schema source")

// ErrLookupFailed marks a resolver error that says a lookup did not finish,
// such as a network failure, an HTTP 5xx or a timeout. The type may exist,
// so Validate stops with the error rather than report it as unknown.
var ErrLookupFailed = errors.New("schema lookup failed")
