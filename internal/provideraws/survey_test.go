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
	p := parsedCheckout(t, dir)

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

// TestSourceProvider_FrameworkResources surveys the parse of the resources
// the provider builds on the Terraform Plugin Framework. Before the parser
// read them, none of the 237 at v5.90.0 resolved from source. Now each must
// resolve, and an operation without an action of its own (transparent
// tagging aside) must be one the type does not implement in the package,
// such as a delete it gets from framework.WithNoOpDelete, or one that never
// uses a client.
func TestSourceProvider_FrameworkResources(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the provider checkout")
	}
	dir := defaultCacheDir()
	if _, err := os.Stat(filepath.Join(dir, "internal", "service")); err != nil {
		t.Skipf("provider checkout not found at %s", dir)
	}
	resources, err := parseResources(dir)
	if err != nil {
		t.Fatal(err)
	}

	var total int
	var unbound, noClient, empty []string
	for _, r := range resources {
		if !r.framework {
			continue
		}
		total++
		actions, bound := r.pkg.actionsFor(r.funcs), boundFuncs(r.funcs)
		for _, op := range []string{"create", "read", "delete"} {
			if len(actions[op]) > 0 {
				continue
			}
			name := r.tfType + " " + op
			switch fn, ok := bound[op]; {
			case !ok:
				unbound = append(unbound, name)
			case !r.pkg.idx.reachesClient(fn):
				noClient = append(noClient, name)
			default:
				empty = append(empty, name)
			}
		}
	}
	sort.Strings(unbound)
	sort.Strings(noClient)
	sort.Strings(empty)
	t.Logf("%d framework resources; operations without actions: %d not implemented in the package %v, %d that use no client %v, %d empty %v",
		total, len(unbound), unbound, len(noClient), noClient, len(empty), empty)
	if total == 0 {
		t.Fatal("no framework resources found")
	}
	if len(empty) > 0 {
		t.Errorf("%d framework operations use a client but have no action: %v", len(empty), empty)
	}
}
