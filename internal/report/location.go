package report

import (
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// Locations maps each resource block, by its type and name, to the place
// that declares it. hcl.MapResources builds it.
type Locations map[string]hcl.Location

// Of returns where m's resource is declared. A finding from a declared need
// has no resource block, so it has no location. A plan address may carry a
// count or for_each index, which a block label never does, so the index is
// dropped before the lookup.
func (l Locations) Of(m iam.MissingAction) (hcl.Location, bool) {
	if m.Need != "" {
		return hcl.Location{}, false
	}
	loc, ok := l[m.ResourceType+"."+withoutIndex(m.ResourceName)]
	return loc, ok
}

// withoutIndex removes a count or for_each index from a resource name:
// cloudtrail[0] and cloudtrail["us-east-1"] become cloudtrail. A terraform
// name cannot hold a bracket, so the first one starts the index.
func withoutIndex(name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 && strings.HasSuffix(name, "]") {
		return name[:i]
	}
	return name
}
