package iam

import "testing"

func TestKeyOf_StripsIndex(t *testing.T) {
	tests := []struct {
		name string
		want ResourceKey
	}{
		{"a", "aws_s3_bucket.a"},
		{"a[0]", "aws_s3_bucket.a"},
		{`b["us-east-1"]`, "aws_s3_bucket.b"},
	}
	for _, tt := range tests {
		if got := KeyOf("aws_s3_bucket", tt.name); got != tt.want {
			t.Errorf("KeyOf(aws_s3_bucket, %q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestLocations_Of(t *testing.T) {
	l := Locations{"aws_s3_bucket.a": {Path: "main.tf", Line: 3}}
	if loc, ok := l.Of(MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a[1]"}); !ok || loc.Line != 3 {
		t.Errorf("indexed address: got %+v, %v", loc, ok)
	}
	// A need finding names no resource block, even when its sid looks like one.
	if _, ok := l.Of(MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a", Need: "x"}); ok {
		t.Error("a need finding must have no location")
	}
	if _, ok := Locations(nil).Of(MissingAction{ResourceType: "aws_s3_bucket", ResourceName: "a"}); ok {
		t.Error("a nil map must find nothing")
	}
}
