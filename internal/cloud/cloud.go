// Package cloud defines the interface for cloud schema registries and
// provides implementations for AWS, GCP, and Azure.
package cloud

import (
	"errors"
	"fmt"
	"sort"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// Schema lists the requirements of each operation on a cloud resource type.
// Both producers emit it: the CloudFormation registry adapter here and the
// provider-source adapter in provideraws. It implements iam.Schema.
type Schema struct {
	TypeName string

	// Ops maps "create", "read", "update", "delete" and "list" to the
	// requirements of that operation, one per path that reaches an action.
	// An operation the producer knows but that needs no permissions is
	// present with an empty list.
	Ops map[string][]iam.Requirement

	// Incomplete names the operations whose permissions the provider could
	// not fully determine, such as a create in which the provider-source
	// parser found no call that creates anything. ChainProvider merges in a
	// later provider's requirements for these operations. Only the chain
	// reads it, so iam.Schema does not expose it.
	Incomplete map[string]bool
}

// Requirements returns the requirements of op, and whether the schema knows
// op at all (implements iam.Schema).
func (s *Schema) Requirements(op string) ([]iam.Requirement, bool) {
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
func (s *Schema) Gates(op, action string) []iam.Gate {
	var gates []iam.Gate
	for _, r := range s.Ops[op] {
		if r.Action == action {
			gates = append(gates, r.Gate)
		}
	}
	return gates
}

// Provider resolves cloud resource types to their required IAM permissions.
// It returns the concrete Schema, so ChainProvider can read Incomplete and
// merge operations. ChainProvider is the iam.Resolver built from providers.
type Provider interface {
	// Name returns the provider name (e.g. "aws").
	Name() string

	// Resolve maps a terraform resource type (e.g. "aws_backup_vault") to
	// the cloud-native resource type and fetches its required permissions.
	Resolve(tfType string) (*Schema, error)
}

// ChainProvider tries multiple providers in order, returning the first
// successful resolution. This allows combining a fallback provider (CFN
// schema registry) with a more precise provider (provider source parser).
type ChainProvider struct {
	providers []Provider
}

// NewChainProvider creates a ChainProvider that tries each provider in order.
func NewChainProvider(providers ...Provider) *ChainProvider {
	return &ChainProvider{providers: providers}
}

// Name returns the name of the first provider.
func (c *ChainProvider) Name() string {
	if len(c.providers) > 0 {
		return c.providers[0].Name()
	}
	return "chain"
}

// Resolve tries each provider in order and returns the first successful
// result. When that result marks operations incomplete, each later provider
// that knows the type adds its actions for those operations, so a parse that
// missed a call cannot report it as not needed. A ChainProvider is an
// iam.Resolver.
//
// When no provider resolves the type, the error is marked
// iam.ErrLookupFailed if any provider's lookup failed, since that provider
// may know the type, and iam.ErrUnknownType otherwise. A provider error that
// carries neither mark counts as not found.
func (c *ChainProvider) Resolve(tfType string) (iam.Schema, error) {
	var lastErr, failed error
	for i, p := range c.providers {
		schema, err := p.Resolve(tfType)
		if err == nil {
			complete, err := c.completeFrom(schema, tfType, c.providers[i+1:])
			if err != nil {
				return nil, err
			}
			return complete, nil
		}
		lastErr = err
		if errors.Is(err, iam.ErrLookupFailed) && failed == nil {
			failed = err
		}
	}
	if failed != nil {
		return nil, failed
	}
	if lastErr == nil {
		return nil, fmt.Errorf("%s: no schema providers: %w", tfType, iam.ErrUnknownType)
	}
	if errors.Is(lastErr, iam.ErrUnknownType) {
		return nil, lastErr
	}
	return nil, fmt.Errorf("%w: %w", iam.ErrUnknownType, lastErr)
}

// completeFrom fills the incomplete operations of schema from the first later
// provider that knows the type and has actions for them. It returns schema
// itself when nothing needs or can take filling, and a merged copy otherwise.
//
// The copy is made once, on the first operation any provider fills: the first
// provider may have cached the schema it returned, so merging has to write to
// a copy, and one copy serves every later provider.
//
// A later provider whose lookup fails (iam.ErrLookupFailed) fails the whole
// resolution, since the operation it would fill is left incomplete.
func (c *ChainProvider) completeFrom(schema *Schema, tfType string, rest []Provider) (*Schema, error) {
	merged := schema
	copied := false
	for _, p := range rest {
		ops := incompleteOps(merged)
		if len(ops) == 0 {
			break
		}
		fallback, err := p.Resolve(tfType)
		if errors.Is(err, iam.ErrLookupFailed) {
			return nil, err
		}
		if err != nil {
			continue
		}
		for _, op := range ops {
			if len(fallback.Ops[op]) == 0 {
				continue
			}
			if !copied {
				merged = schema.clone()
				copied = true
			}
			merged.mergeOperation(op, fallback)
		}
	}
	return merged, nil
}

// incompleteOps lists the operations a schema still needs filling for, as a
// sorted snapshot: mergeOperation clears entries from the schema's own map, so
// walking that map directly would be walking a map under mutation.
func incompleteOps(s *Schema) []string {
	if len(s.Incomplete) == 0 {
		return nil
	}
	ops := make([]string, 0, len(s.Incomplete))
	for op := range s.Incomplete {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	return ops
}

// clone copies a schema deeply enough that merging into the copy leaves the
// original, which a provider may cache, unchanged.
func (s *Schema) clone() *Schema {
	out := *s
	out.Ops = make(map[string][]iam.Requirement, len(s.Ops))
	for op, reqs := range s.Ops {
		out.Ops[op] = append([]iam.Requirement(nil), reqs...)
	}
	out.Incomplete = make(map[string]bool, len(s.Incomplete))
	for op, v := range s.Incomplete {
		out.Incomplete[op] = v
	}
	return &out
}

// mergeOperation adds the fallback's requirements for op on the actions s
// lacks, with every path the fallback lists for them, and marks op complete.
// Actions s already has keep their own paths.
func (s *Schema) mergeOperation(op string, fallback *Schema) {
	have := make(map[string]bool, len(s.Ops[op]))
	for _, r := range s.Ops[op] {
		have[r.Action] = true
	}
	for _, r := range fallback.Ops[op] {
		if have[r.Action] {
			continue
		}
		s.Ops[op] = append(s.Ops[op], r)
	}
	delete(s.Incomplete, op)
}
