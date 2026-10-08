// Package cloud resolves resource types through the CloudFormation schema
// registry, and chains resolvers so a precise source can fall back to a
// broader one.
package cloud

import (
	"errors"
	"fmt"
	"sort"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// ChainProvider tries multiple resolvers in order, returning the first
// successful resolution. This allows combining a fallback resolver (CFN
// schema registry) with a more precise one (provider source parser).
type ChainProvider struct {
	providers []iam.Resolver
}

// NewChainProvider creates a ChainProvider that tries each resolver in order.
func NewChainProvider(providers ...iam.Resolver) *ChainProvider {
	return &ChainProvider{providers: providers}
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
func (c *ChainProvider) Resolve(tfType string) (*iam.Schema, error) {
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
func (c *ChainProvider) completeFrom(schema *iam.Schema, tfType string, rest []iam.Resolver) (*iam.Schema, error) {
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
				merged = clone(schema)
				copied = true
			}
			mergeOperation(merged, op, fallback)
		}
	}
	return merged, nil
}

// incompleteOps lists the operations a schema still needs filling for, as a
// sorted snapshot: mergeOperation clears entries from the schema's own map, so
// walking that map directly would be walking a map under mutation.
func incompleteOps(s *iam.Schema) []string {
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
func clone(s *iam.Schema) *iam.Schema {
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
func mergeOperation(s *iam.Schema, op string, fallback *iam.Schema) {
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
