package provideraws

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// maxIncompleteOperations bounds how many operations across the provider the
// parser may leave incomplete. At v5.90.0 three remain, all creates that only
// wait for or adopt something that already exists (aws_acm_certificate_validation,
// aws_default_vpc_dhcp_options, aws_ses_domain_identity_verification).
const maxIncompleteOperations = 5

// TestSourceProvider_FewIncompleteOperations guards against a parser pattern
// gap coming back: before closures, if-statement init calls, paginators and
// helpers in other files were followed, 177 resources had no create action at
// all, aws_s3_bucket among them. Incomplete operations fall back to the next
// provider in the chain, but each one is a parse the tool cannot trust.
func TestSourceProvider_FewIncompleteOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the provider checkout")
	}
	dir := defaultCacheDir()
	if _, err := os.Stat(filepath.Join(dir, "internal", "service")); err != nil {
		t.Skipf("provider checkout not found at %s", dir)
	}
	p := NewSourceProviderWithPath(dir)
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}

	var incomplete []string
	for tfType, s := range p.schemas {
		for op := range s.Incomplete {
			incomplete = append(incomplete, tfType+" "+op)
		}
	}
	sort.Strings(incomplete)
	t.Logf("%d resources, %d incomplete operations: %v", len(p.schemas), len(incomplete), incomplete)
	if len(incomplete) > maxIncompleteOperations {
		t.Errorf("%d incomplete operations, want at most %d: %v", len(incomplete), maxIncompleteOperations, incomplete)
	}
}
