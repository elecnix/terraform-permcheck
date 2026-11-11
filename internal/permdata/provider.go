package permdata

import (
	"fmt"
	"sync"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// Provider serves the requirements of one provider version of a permissions
// table as an iam.Resolver: the newest version, unless At chose another. It
// decodes the table on first use, once, and every Provider that At derives
// from it shares the decoded table. A type the version lacks is an error, so
// a ChainProvider falls back to its next provider.
type Provider struct {
	src *tableSource
	// ref is the version Resolve serves, or "" for the newest.
	ref string
}

// tableSource decodes a table once.
type tableSource struct {
	load func() ([]byte, error)

	once  sync.Once
	table *Table
	err   error
}

// newProvider returns a Provider over an encoded table.
func newProvider(data []byte) *Provider {
	return &Provider{src: &tableSource{load: func() ([]byte, error) { return data, nil }}}
}

// At returns a Provider that serves the requirements of provider ref, which
// must be one of the table's Refs.
func (p *Provider) At(ref string) *Provider {
	return &Provider{src: p.src, ref: ref}
}

// Ref returns the provider ref Resolve serves.
func (p *Provider) Ref() (string, error) {
	tbl, err := p.decoded()
	if err != nil {
		return "", err
	}
	if p.ref == "" {
		return tbl.Newest(), nil
	}
	if _, ok := tbl.Schemas[p.ref]; !ok {
		return "", fmt.Errorf("the embedded permissions table has no provider %s (it has %v)", p.ref, tbl.Refs)
	}
	return p.ref, nil
}

// Resolve returns the schema of tfType from the table. The schema is shared:
// callers must not change it.
func (p *Provider) Resolve(tfType string) (*iam.Schema, error) {
	ref, err := p.Ref()
	if err != nil {
		return nil, err
	}
	tbl, _ := p.decoded()
	s, ok := tbl.Schemas[ref][tfType]
	if !ok {
		return nil, fmt.Errorf("%q: not in the embedded permissions table for provider %s", tfType, ref)
	}
	return s, nil
}

// Table returns the decoded table. It is shared: callers must not change it.
func (p *Provider) Table() (*Table, error) {
	return p.decoded()
}

func (p *Provider) decoded() (*Table, error) {
	s := p.src
	s.once.Do(func() {
		data, err := s.load()
		if err != nil {
			s.err = err
			return
		}
		s.table, s.err = Decode(data)
	})
	return s.table, s.err
}
