package permdata

import (
	"fmt"
	"sync"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// Provider serves a permissions table as an iam.Resolver. It decodes the
// table on first use, once. A type the table lacks is an error, so a
// ChainProvider falls back to its next provider.
type Provider struct {
	load func() ([]byte, error)

	once  sync.Once
	table *Table
	err   error
}

// newProvider returns a Provider over an encoded table.
func newProvider(data []byte) *Provider {
	return &Provider{load: func() ([]byte, error) { return data, nil }}
}

// Resolve returns the schema of tfType from the table. The schema is shared:
// callers must not change it.
func (p *Provider) Resolve(tfType string) (*iam.Schema, error) {
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
