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
		notice string // a substring of the notice, or "" for any named source
	}{
		{"explicit major", VersionHints{Explicit: "5", ExplicitFrom: ExplicitFromConfig, Locked: "6.72.0"}, oldest, `: aws_provider_version "5" in the config.`},
		{"explicit version", VersionHints{Explicit: "v6.1.0", ExplicitFrom: "--aws-provider-version", Constraints: []string{"~> 5.0"}}, newest, ": --aws-provider-version v6.1.0."},
		{"lock file", VersionHints{Locked: "5.99.1", LockFile: "envs/app/.terraform.lock.hcl", Constraints: []string{">= 6.0"}}, oldest, ": envs/app/.terraform.lock.hcl pins 5.99.1."},
		{"lock file older than the table", VersionHints{Locked: "4.67.0"}, oldest, "pins AWS provider 4.67.0"},
		{"lock file newer than the table", VersionHints{Locked: "99.0.0"}, newest, "pins AWS provider 99.0.0"},
		{"constraint admits one", VersionHints{Constraints: []string{"~> 5.0"}}, oldest, ""},
		// A constraint at minor or patch level picks its major's table.
		// The table's ref need not meet it: ~> 5.90 admits no 5.100.x,
		// yet the 5.x table is the one that applies.
		{"pessimistic patch constraint", VersionHints{Constraints: []string{"~> 5.100.0"}}, oldest, ""},
		{"exact constraint", VersionHints{Constraints: []string{"= 5.100.0"}}, oldest, ""},
		{"constraint the table ref does not meet", VersionHints{Constraints: []string{"~> 5.90.0"}}, oldest, ""},
		{"exact constraint on 6.x", VersionHints{Constraints: []string{"6.1.0"}}, newest, ""},
		{"constraints intersect", VersionHints{Constraints: []string{">= 4.0", "< 6.0"}}, oldest, `: the plan's constraints ">= 4.0" and "< 6.0".`},
		{"constraint admits both", VersionHints{Constraints: []string{">= 5.0"}}, newest, `">= 5.0" admits provider`},
		{"constraint below the table", VersionHints{Constraints: []string{"~> 4.0"}}, oldest, "admits no version"},
		{"constraint above the table", VersionHints{Constraints: []string{">= 99.0"}}, newest, "admits no version"},
		{"nothing, no root", VersionHints{Searched: []string{"the working directory"}}, newest, "and no .terraform.lock.hcl in the working directory."},
		{"nothing, plan mode with root", VersionHints{Searched: []string{"infra", "the working directory"}}, newest, "no .terraform.lock.hcl in infra or the working directory."},
		{"nothing, static mode", VersionHints{Searched: []string{"infra"}, Static: true}, newest, "found: no .terraform.lock.hcl in infra."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ChooseProviderRef(tc.hints)
			if err != nil {
				t.Fatal(err)
			}
			if got.Ref != tc.ref {
				t.Errorf("Ref = %s, want %s", got.Ref, tc.ref)
			}
			// Every choice says which version it reads. One the hints
			// name says what named it, and the case gives that text.
			if !strings.Contains(got.Notice, got.Ref) {
				t.Errorf("Notice = %q does not name the version used, %s", got.Notice, got.Ref)
			}
			if tc.notice != "" && !strings.Contains(got.Notice, tc.notice) {
				t.Errorf("Notice = %q, want it to hold %q", got.Notice, tc.notice)
			}
			if tc.notice == "" && !strings.HasPrefix(got.Notice, "terraform-permcheck: checking against AWS provider "+got.Ref+": ") {
				t.Errorf("Notice = %q, want the line that names its source", got.Notice)
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
