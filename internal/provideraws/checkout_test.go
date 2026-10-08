package provideraws

import (
	"sync"
	"testing"
)

// checkout holds the one parse of the provider checkout that the long tests
// share. A full parse takes about a minute, and several tests read it.
var checkout struct {
	once sync.Once
	dir  string
	p    *SourceProvider
	err  error
}

// parsedCheckout returns a SourceProvider that has parsed the checkout at
// dir, parsing it on the first call only. Callers must not change it.
func parsedCheckout(t *testing.T, dir string) *SourceProvider {
	t.Helper()
	checkout.once.Do(func() {
		checkout.dir = dir
		checkout.p = NewSourceProviderWithPath(dir)
		checkout.err = checkout.p.Ensure()
	})
	if checkout.dir != dir {
		t.Fatalf("parsedCheckout(%s): already parsed %s", dir, checkout.dir)
	}
	if checkout.err != nil {
		t.Fatal(checkout.err)
	}
	return checkout.p
}
