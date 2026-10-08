package permdata

import (
	"fmt"
	"sync"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
)

// Provider serves a permissions table as a cloud.Provider. It decodes the
// table on first use, once. A type the table lacks is an error, so a
// ChainProvider falls back to its next provider.
type Provider struct {
	load func() ([]byte, error)

	once  sync.Once
	table *Table
	err   error
}

// NewProvider returns a Provider over an encoded table.
func NewProvider(data []byte) *Provider {
	return &Provider{load: func() ([]byte, error) { return data, nil }}
}

// Name returns "aws".
func (p *Provider) Name() string { return "aws" }

// Resolve returns the schema of tfType from the table. The schema is shared:
// callers must not change it.
func (p *Provider) Resolve(tfType string) (*cloud.Schema, error) {
	tbl, err := p.decoded()
	if err != nil {
		return nil, err
	}
	s, ok := tbl.Schemas[tfType]
	if !ok {
		return nil, fmt.Errorf("%q: not in the embedded permissions table", tfType)
	}
	return s, nil
}

// Ref returns the provider ref the table was generated from.
func (p *Provider) Ref() (string, error) {
	tbl, err := p.decoded()
	if err != nil {
		return "", err
	}
	return tbl.Ref, nil
}

// Len returns the number of resource types in the table.
func (p *Provider) Len() (int, error) {
	tbl, err := p.decoded()
	if err != nil {
		return 0, err
	}
	return len(tbl.Schemas), nil
}

func (p *Provider) decoded() (*Table, error) {
	p.once.Do(func() {
		data, err := p.load()
		if err != nil {
			p.err = err
			return
		}
		p.table, p.err = Decode(data)
	})
	return p.table, p.err
}
