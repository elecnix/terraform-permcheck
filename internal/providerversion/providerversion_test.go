package providerversion

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMajor(t *testing.T) {
	for in, want := range map[string]int{"v5.100.0": 5, "5.100.0": 5, "6": 6, "v6": 6, " 6.0.0-beta1 ": 6} {
		if got, ok := Major(in); !ok || got != want {
			t.Errorf("Major(%q) = %d, %v, want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "latest", "v", "-1"} {
		if _, ok := Major(in); ok {
			t.Errorf("Major(%q) ok, want false", in)
		}
	}
}

func writeLock(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LockFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestFromLockFile reads the AWS block of a lock file that pins several
// providers, as terraform init writes it.
func TestFromLockFile(t *testing.T) {
	dir := writeLock(t, `# This file is maintained automatically by "terraform init".
# Manual edits may be lost in future updates.

provider "registry.terraform.io/hashicorp/archive" {
  version = "2.7.1"
  hashes = [
    "h1:AAAA=",
  ]
}

provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.100.0"
  constraints = ">= 5.0.0, < 6.0.0"
  hashes = [
    "h1:BBBB=",
  ]
}
`)
	got, ok, err := FromLockFile(dir)
	if err != nil || !ok || got != "5.100.0" {
		t.Errorf("FromLockFile = %q, %v, %v, want 5.100.0", got, ok, err)
	}
}

func TestFromLockFile_NoFileOrNoAWS(t *testing.T) {
	if got, ok, err := FromLockFile(t.TempDir()); ok || err != nil {
		t.Errorf("no lock file: got %q, %v, %v, want not found", got, ok, err)
	}
	dir := writeLock(t, "provider \"registry.terraform.io/hashicorp/random\" {\n  version = \"3.6.0\"\n}\n")
	if got, ok, err := FromLockFile(dir); ok || err != nil {
		t.Errorf("lock file without aws: got %q, %v, %v, want not found", got, ok, err)
	}
}

func TestFromLockFile_BlockWithoutVersion(t *testing.T) {
	dir := writeLock(t, "provider \"registry.terraform.io/hashicorp/aws\" {\n  hashes = []\n}\n")
	if _, _, err := FromLockFile(dir); err == nil {
		t.Error("want an error for an aws block with no version")
	}
}

// TestConstraints reads the AWS constraints of the root module and of a
// child module, and skips other providers.
func TestConstraints(t *testing.T) {
	plan := []byte(`{"configuration":{"provider_config":{
		"aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","version_constraint":"~> 5.0"},
		"module.net:aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","module_address":"module.net","version_constraint":">= 4.0"},
		"random":{"name":"random","full_name":"registry.terraform.io/hashicorp/random","version_constraint":"~> 3.0"},
		"aws.east":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws"}
	}}}`)
	got := Constraints(plan)
	if len(got) != 2 {
		t.Fatalf("Constraints = %v, want the two aws constraints", got)
	}
	if !Admits(got, 5) || Admits(got, 6) || Admits(got, 4) {
		t.Errorf("Admits(%v): want 5 only", got)
	}
	if Constraints([]byte(`{"resource_changes":[]}`)) != nil {
		t.Error("a plan with no configuration has no constraints")
	}
}

func TestAdmits(t *testing.T) {
	for _, tc := range []struct {
		constraint string
		majors     []int // the majors among 4, 5, 6 and 7 it admits
	}{
		{"~> 5.0", []int{5}},
		{"~> 5", []int{5}},
		{"~> 5.100.0", []int{5}},
		{"~> 6.72", []int{6}},
		{">= 5.0, < 6.0", []int{5}},
		{">= 5.0", []int{5, 6, 7}},
		{"> 5.0.0", []int{5, 6, 7}},
		{"<= 5.100.0", []int{4, 5}},
		{"< 6.0.0", []int{4, 5}},
		{"5.100.0", []int{5}},
		{"= 6.72.0", []int{6}},
		{"!= 6.0.0", []int{4, 5, 6, 7}},
		{">= 4.0, != 5.1.0", []int{4, 5, 6, 7}},
		{"not a constraint", []int{4, 5, 6, 7}},
		{"", []int{4, 5, 6, 7}},
		{">= 6.0.0-beta1", []int{6, 7}},
	} {
		var got []int
		for _, major := range []int{4, 5, 6, 7} {
			if Admits([]string{tc.constraint}, major) {
				got = append(got, major)
			}
		}
		if len(got) != len(tc.majors) {
			t.Errorf("%q admits %v, want %v", tc.constraint, got, tc.majors)
			continue
		}
		for i := range got {
			if got[i] != tc.majors[i] {
				t.Errorf("%q admits %v, want %v", tc.constraint, got, tc.majors)
				break
			}
		}
	}
}
