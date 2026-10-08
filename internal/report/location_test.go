package report

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

func TestWithoutIndex(t *testing.T) {
	for name, want := range map[string]string{
		"a":              "a",
		"a[0]":           "a",
		`b["us-east-1"]`: "b",
		`c["key[with]"]`: "c",
	} {
		if got := withoutIndex(name); got != want {
			t.Errorf("withoutIndex(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestLocations_Of(t *testing.T) {
	l := Locations{"aws_s3_bucket.a": {Path: "main.tf", Line: 3}}
	if loc, ok := l.Of(iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a[1]"}); !ok || loc.Line != 3 {
		t.Errorf("indexed address: got %+v, %v", loc, ok)
	}
	// A need finding names no resource block, even when its sid looks like one.
	if _, ok := l.Of(iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a", Need: "x"}); ok {
		t.Error("a need finding must have no location")
	}
	if _, ok := Locations(nil).Of(iam.MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a"}); ok {
		t.Error("a nil map must find nothing")
	}
}
