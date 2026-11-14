package check

import (
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

// TestChooseProviderRef walks the order of the hints: an explicit version,
// then the lock file, then the plan's constraints, then the newest version.
func TestChooseProviderRef(t *testing.T) {
	oldest, newest := provideraws.TableProviderRefs[0], provideraws.DefaultProviderRef
	for _, tc := range []struct {
		name   string
		hints  VersionHints
		ref    string
		notice string // a substring of the notice, or "" for none
	}{
		{"explicit major", VersionHints{Explicit: "5", Locked: "6.72.0"}, oldest, ""},
		{"explicit version", VersionHints{Explicit: "v6.1.0", Constraints: []string{"~> 5.0"}}, newest, ""},
		{"lock file", VersionHints{Locked: "5.99.1", Constraints: []string{">= 6.0"}}, oldest, ""},
		{"lock file older than the table", VersionHints{Locked: "4.67.0"}, oldest, "pins AWS provider 4.67.0"},
		{"lock file newer than the table", VersionHints{Locked: "99.0.0"}, newest, "pins AWS provider 99.0.0"},
		{"constraint admits one", VersionHints{Constraints: []string{"~> 5.0"}}, oldest, ""},
		{"constraints intersect", VersionHints{Constraints: []string{">= 4.0", "< 6.0"}}, oldest, ""},
		{"constraint admits both", VersionHints{Constraints: []string{">= 5.0"}}, newest, `">= 5.0" admits provider`},
		{"constraint below the table", VersionHints{Constraints: []string{"~> 4.0"}}, oldest, "admits no version"},
		{"constraint above the table", VersionHints{Constraints: []string{">= 99.0"}}, newest, "admits no version"},
		{"nothing, no root", VersionHints{}, newest, "no --terraform-root names a directory"},
		{"nothing, plan mode with root", VersionHints{Root: "infra"}, newest, "infra has no .terraform.lock.hcl"},
		{"nothing, static mode", VersionHints{Root: "infra", Static: true}, newest, "found: infra has no .terraform.lock.hcl."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ChooseProviderRef(tc.hints)
			if err != nil {
				t.Fatal(err)
			}
			if got.Ref != tc.ref {
				t.Errorf("Ref = %s, want %s", got.Ref, tc.ref)
			}
			switch {
			case tc.notice == "" && got.Notice != "":
				t.Errorf("Notice = %q, want none", got.Notice)
			case tc.notice != "" && !strings.Contains(got.Notice, tc.notice):
				t.Errorf("Notice = %q, want it to hold %q", got.Notice, tc.notice)
			case tc.notice != "" && !strings.Contains(got.Notice, got.Ref):
				t.Errorf("Notice = %q does not name the version used, %s", got.Notice, got.Ref)
			}
		})
	}
}

func TestChooseProviderRef_ExplicitErrors(t *testing.T) {
	for _, explicit := range []string{"latest", "4", "v7.0.0"} {
		_, err := ChooseProviderRef(VersionHints{Explicit: explicit, ExplicitFrom: "--aws-provider-version"})
		if err == nil || !strings.Contains(err.Error(), "--aws-provider-version") {
			t.Errorf("Explicit %q: error = %v, want one naming the flag", explicit, err)
		}
	}
}
