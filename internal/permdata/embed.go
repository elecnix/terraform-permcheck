package permdata

import (
	_ "embed" // for the permissions table
	"sync"
)

// EmbeddedFile is the path of the embedded table, relative to the repository
// root. generate-permissions writes it.
const EmbeddedFile = "internal/permdata/permissions.json"

// The table is about 0.9 MB of JSON, so it is embedded uncompressed: a
// regenerated table then diffs as text in review.
//
//go:embed permissions.json
var embedded []byte

var (
	embeddedOnce     sync.Once
	embeddedProvider *Provider
)

// Embedded returns the Provider over the table built into the binary. Every
// caller shares it, so the table is decoded once per process.
func Embedded() *Provider {
	embeddedOnce.Do(func() {
		embeddedProvider = NewProvider(embedded)
	})
	return embeddedProvider
}
