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

// s3BucketActionsFixture records the actions the parser emits for the
// aws_s3_bucket resource family. The iam package tests read it to check their
// S3 tables against the names the parser really produces, without needing the
// provider checkout.
const s3BucketActionsFixture = "../../testdata/provider-aws/s3-bucket-actions.json"

// s3BucketActions is the shape of s3BucketActionsFixture.
type s3BucketActions struct {
	Comment     string                         `json:"$comment"`
	ProviderRef string                         `json:"providerRef"`
	Resources   map[string]map[string][]string `json:"resources"`
}

// TestS3BucketActionsFixture keeps s3BucketActionsFixture in step with the
// parser. It needs the provider checkout, so it skips in -short mode and when
// the checkout is absent. Set UPDATE_S3_FIXTURE=1 to rewrite the fixture.
func TestS3BucketActionsFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the provider checkout")
	}
	dir := defaultCacheDir()
	if _, err := os.Stat(filepath.Join(dir, "internal", "service", "s3")); err != nil {
		t.Skipf("provider checkout not found at %s", dir)
	}

	p := NewSourceProviderWithPath(dir)
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	got := s3BucketActions{
		Comment:     "S3 actions the provider-source parser emits for the aws_s3_bucket resource family. Regenerate with UPDATE_S3_FIXTURE=1 go test -run TestS3BucketActionsFixture ./internal/provideraws/",
		ProviderRef: DefaultProviderRef,
		Resources:   map[string]map[string][]string{},
	}
	for tfType, schema := range p.schemas {
		if tfType != "aws_s3_bucket" && !strings.HasPrefix(tfType, "aws_s3_bucket_") {
			continue
		}
		ops := map[string][]string{}
		for op := range schema.Ops {
			sorted := append([]string{}, schema.Actions(op)...)
			sort.Strings(sorted)
			ops[op] = sorted
		}
		got.Resources[tfType] = ops
	}
	want, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')

	if os.Getenv("UPDATE_S3_FIXTURE") != "" {
		if err := os.WriteFile(s3BucketActionsFixture, want, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(s3BucketActionsFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(have, want) {
		t.Errorf("%s is stale; regenerate it with UPDATE_S3_FIXTURE=1", s3BucketActionsFixture)
	}
}
