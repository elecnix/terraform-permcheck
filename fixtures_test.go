package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrincipalFixtures_UnknownAgreesWithKnown checks that the hand-written
// plans of testdata/principals are plans terraform could print. Terraform
// marks an attribute unknown in after_unknown only when it has no value in
// after. It also knows an attribute whose expression references a known
// attribute of another resource in the plan, such as the role of an
// aws_iam_role_policy that references the id of a role that the plan keeps.
// A fixture that breaks either rule tests a link that no plan has.
func TestPrincipalFixtures_UnknownAgreesWithKnown(t *testing.T) {
	files, err := filepath.Glob("testdata/principals/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range unknownContradictions(raw) {
			t.Errorf("%s: %s", f, c)
		}
	}
}

// unknownContradictions lists the attributes of a plan's resource changes
// that after_unknown marks unknown while terraform would know them. It
// returns nil for a file that isn't a plan.
func unknownContradictions(raw []byte) []string {
	type change struct {
		After        map[string]any `json:"after"`
		AfterUnknown map[string]any `json:"after_unknown"`
	}
	var p struct {
		ResourceChanges []struct {
			Address string `json:"address"`
			Change  change `json:"change"`
		} `json:"resource_changes"`
		Configuration struct {
			RootModule struct {
				Resources []struct {
					Address     string `json:"address"`
					Expressions map[string]struct {
						References []string `json:"references"`
					} `json:"expressions"`
				} `json:"resources"`
			} `json:"root_module"`
		} `json:"configuration"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil
	}
	changes := map[string]change{}
	for _, rc := range p.ResourceChanges {
		changes[rc.Address] = rc.Change
	}
	known := func(c change, attr string) bool {
		return c.After[attr] != nil && c.AfterUnknown[attr] != true
	}
	refs := map[string]map[string][]string{}
	for _, r := range p.Configuration.RootModule.Resources {
		refs[r.Address] = map[string][]string{}
		for attr, e := range r.Expressions {
			refs[r.Address][attr] = e.References
		}
	}
	var out []string
	for _, rc := range p.ResourceChanges {
		for attr, u := range rc.Change.AfterUnknown {
			if u != true {
				continue
			}
			if rc.Change.After[attr] != nil {
				out = append(out, rc.Address+"."+attr+" has a value and is unknown")
			}
			for _, ref := range refs[rc.Address][attr] {
				parts := strings.Split(ref, ".")
				if len(parts) < 3 {
					continue
				}
				if c, ok := changes[parts[0]+"."+parts[1]]; ok && known(c, parts[2]) {
					out = append(out, rc.Address+"."+attr+" is unknown, and it references "+ref+", which is known")
				}
			}
		}
	}
	return out
}
