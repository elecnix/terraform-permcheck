package provideraws

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// emittedActionsFixture records every action the parser emits, across all
// resources, for the services listed in the fixture. The iam package tests
// read it to check that each of their rules names an action the parser or
// CloudFormation can produce, without needing the provider checkout.
const emittedActionsFixture = "../../testdata/provider-aws/emitted-actions.json"

// emittedActions is the shape of emittedActionsFixture.
type emittedActions struct {
	Comment     string   `json:"$comment"`
	ProviderRef string   `json:"providerRef"`
	Services    []string `json:"services"`
	Actions     []string `json:"actions"`
}

// TestEmittedActionsFixture keeps emittedActionsFixture in step with the
// parser. The fixture's own services list says which services to record. It
// needs the provider checkout, so it skips in -short mode and when the
// checkout is absent. Set UPDATE_EMITTED_FIXTURE=1 to rewrite the fixture.
func TestEmittedActionsFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the provider checkout")
	}
	dir := defaultCacheDir()
	if _, err := os.Stat(filepath.Join(dir, "internal", "service")); err != nil {
		t.Skipf("provider checkout not found at %s", dir)
	}

	have, err := os.ReadFile(emittedActionsFixture)
	if err != nil {
		t.Fatal(err)
	}
	var old emittedActions
	if err := json.Unmarshal(have, &old); err != nil {
		t.Fatal(err)
	}
	services := make(map[string]bool, len(old.Services))
	for _, s := range old.Services {
		services[s] = true
	}

	p := NewSourceProviderWithPath(dir)
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	set := make(map[string]bool)
	for _, schema := range p.schemas {
		for op := range schema.Ops {
			for _, a := range schema.Actions(op) {
				if services[strings.SplitN(a, ":", 2)[0]] {
					set[a] = true
				}
			}
		}
	}
	got := emittedActions{
		Comment:     "Actions the provider-source parser emits across all resources, for the services listed. Regenerate with UPDATE_EMITTED_FIXTURE=1 go test -run TestEmittedActionsFixture ./internal/provideraws/",
		ProviderRef: DefaultProviderRef,
		Services:    old.Services,
		Actions:     make([]string, 0, len(set)),
	}
	for a := range set {
		got.Actions = append(got.Actions, a)
	}
	sort.Strings(got.Actions)
	want, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')

	if os.Getenv("UPDATE_EMITTED_FIXTURE") != "" {
		if err := os.WriteFile(emittedActionsFixture, want, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(have, want) {
		t.Errorf("%s is stale; regenerate it with UPDATE_EMITTED_FIXTURE=1", emittedActionsFixture)
	}
}
