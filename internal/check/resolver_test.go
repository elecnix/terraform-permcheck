package check

import (
	"os"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/permdata"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

func TestParseProviderSource(t *testing.T) {
	for in, want := range map[string]ProviderSource{
		"":         SourceEmbedded,
		"embedded": SourceEmbedded,
		"live":     SourceLive,
		"LIVE":     SourceLive,
	} {
		got, err := ParseProviderSource(in)
		if err != nil || got != want {
			t.Errorf("ParseProviderSource(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseProviderSource("git"); err == nil {
		t.Error(`ParseProviderSource("git"): want an error`)
	}
}

// TestProviders_Order checks each source's chain. The embedded table comes
// first by default. The live parse replaces it rather than following it:
// both hold the same operations, so a live parse after the table would mark
// the table's incomplete operations complete and hide CloudFormation.
func TestProviders_Order(t *testing.T) {
	embedded := providers(SourceEmbedded)
	if len(embedded) != 2 {
		t.Fatalf("embedded chain has %d providers, want 2", len(embedded))
	}
	if embedded[0] != cloud.Provider(permdata.Embedded()) {
		t.Errorf("embedded chain starts with %T, want the embedded table", embedded[0])
	}
	if _, ok := embedded[1].(*cloud.AWSProvider); !ok {
		t.Errorf("embedded chain ends with %T, want *cloud.AWSProvider", embedded[1])
	}

	live := providers(SourceLive)
	if len(live) != 2 {
		t.Fatalf("live chain has %d providers, want 2", len(live))
	}
	if _, ok := live[0].(*provideraws.SourceProvider); !ok {
		t.Errorf("live chain starts with %T, want *provideraws.SourceProvider", live[0])
	}
	if _, ok := live[1].(*cloud.AWSProvider); !ok {
		t.Errorf("live chain ends with %T, want *cloud.AWSProvider", live[1])
	}
}

// TestDefaultResolver_NoClone resolves a common type through the default
// resolver and checks that nothing was cloned into the provider cache.
func TestDefaultResolver_NoClone(t *testing.T) {
	cache := t.TempDir()
	t.Setenv(provideraws.CacheDirEnv, cache)

	schema, err := DefaultResolver().Resolve("aws_s3_bucket")
	if err != nil {
		t.Fatal(err)
	}
	reqs, ok := schema.Requirements("create")
	if !ok || len(reqs) == 0 {
		t.Fatalf("aws_s3_bucket create = %v, %v", reqs, ok)
	}
	// CloudFormation lists no gates, so a gated requirement shows the table
	// answered.
	gated := false
	for _, r := range reqs {
		gated = gated || !r.Ungated()
	}
	if !gated {
		t.Errorf("aws_s3_bucket create has no gated requirement; the embedded table did not answer: %v", reqs)
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("default resolver wrote %q to the provider cache", e.Name())
	}
}

func TestResolverFor_SharedPerSource(t *testing.T) {
	if ResolverFor(SourceLive) != ResolverFor(SourceLive) {
		t.Error("ResolverFor(live) built a new resolver on the second call")
	}
	if ResolverFor(SourceLive) == ResolverFor(SourceEmbedded) {
		t.Error("live and embedded share one resolver")
	}
}
