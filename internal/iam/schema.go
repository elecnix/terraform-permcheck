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

// Schema lists the requirements of each operation on one resource type. The
// iam package declares it because iam consumes it. The producers in cloud
// and provideraws implement it.
type Schema interface {
	// Requirements returns the requirements of op ("create", "read",
	// "update", "delete" or "list"). The boolean reports whether the schema
	// knows op at all: a known operation can have no requirements, and only
	// an unknown one falls back to create.
	Requirements(op string) ([]Requirement, bool)
}

// Resolver maps a terraform resource type to its Schema. A resolver that
// fails marks its error with ErrUnknownType or ErrLookupFailed, so Validate
// can tell a type no source knows from a lookup that did not finish. An
// unmarked error counts as ErrUnknownType.
type Resolver interface {
	Resolve(tfType string) (Schema, error)
}

// ErrUnknownType marks a resolver error that says no source has permission
// data for the type. Validate reports the type as unresolved.
var ErrUnknownType = errors.New("resource type unknown to every schema source")

// ErrLookupFailed marks a resolver error that says a lookup did not finish,
// such as a network failure, an HTTP 5xx or a timeout. The type may exist,
// so Validate stops with the error rather than report it as unknown.
var ErrLookupFailed = errors.New("schema lookup failed")
