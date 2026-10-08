package iam

import (
	"errors"
	"fmt"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// TestValidate_ReportsUnresolvedType checks that a resource change whose type
// no source knows becomes an unresolved finding, one per change, instead of
// passing unchecked. Both a typed not-found error and an untyped error count
// as unknown.
func TestValidate_ReportsUnresolvedType(t *testing.T) {
	resolver := typeKeyedResolver{"aws_s3_bucket": actionsSchema(map[string][]string{"create": {"s3:CreateBucket"}})}
	changes := []*plan.ResourceChange{
		{Type: "aws_s3_bucket", Name: "b", Change: "create"},
		{Type: "aws_new_thing", Name: "a", Change: "create"},
		{Type: "aws_new_thing", Name: "b", Change: "delete"},
	}

	missing, err := Validate(changes, grantActions("s3:*"), resolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	want := []MissingAction{
		{ResourceType: "aws_new_thing", ResourceName: "a", Change: "create", Unresolved: true},
		{ResourceType: "aws_new_thing", ResourceName: "b", Change: "delete", Unresolved: true},
	}
	if len(missing) != len(want) {
		t.Fatalf("missing = %+v, want %+v", missing, want)
	}
	for i := range want {
		if missing[i] != want[i] {
			t.Errorf("missing[%d] = %+v, want %+v", i, missing[i], want[i])
		}
	}
}

// errResolver fails every lookup with err.
type errResolver struct{ err error }

func (r errResolver) Resolve(string) (Schema, error) { return nil, r.err }

func TestValidate_TypedNotFoundIsUnresolved(t *testing.T) {
	changes := []*plan.ResourceChange{{Type: "aws_new_thing", Name: "a", Change: "create"}}
	err := fmt.Errorf("aws_new_thing: %w", ErrUnknownType)
	missing, verr := Validate(changes, grantNothing(), errResolver{err}, DefaultFilter())
	if verr != nil {
		t.Fatal(verr)
	}
	if len(missing) != 1 || !missing[0].Unresolved {
		t.Fatalf("missing = %+v, want one unresolved finding", missing)
	}
}

// TestValidate_LookupFailureFailsTheRun checks that a failed lookup, such as
// a registry outage, stops validation with an error. The tool does not know
// whether the type exists, so it can neither check it nor call it unknown.
func TestValidate_LookupFailureFailsTheRun(t *testing.T) {
	changes := []*plan.ResourceChange{{Type: "aws_s3_bucket", Name: "b", Change: "create"}}
	err := fmt.Errorf("fetch: HTTP 503: %w", ErrLookupFailed)
	missing, verr := Validate(changes, grantNothing(), errResolver{err}, DefaultFilter())
	if !errors.Is(verr, ErrLookupFailed) {
		t.Fatalf("Validate error = %v, want ErrLookupFailed", verr)
	}
	if missing != nil {
		t.Errorf("missing = %+v, want nil on error", missing)
	}
}

// TestApplyExclusions_UnresolvedType checks that an exclusion of every
// permission ("*") on a resource type covers that type's unresolved finding,
// and that a narrower permission pattern does not.
func TestApplyExclusions_UnresolvedType(t *testing.T) {
	u := MissingAction{ResourceType: "aws_new_thing", ResourceName: "a", Change: "create", Unresolved: true}
	cases := []struct {
		name string
		ex   Exclusion
		want bool
	}{
		{"all permissions on the type", Exclusion{Permission: "*", Resource: "aws_new_thing"}, true},
		{"all permissions on a type glob", Exclusion{Permission: "*", Resource: "aws_new_*"}, true},
		{"all permissions on the address", Exclusion{Permission: "*", Resource: "aws_new_thing.a"}, true},
		{"all permissions everywhere", Exclusion{Permission: "*"}, true},
		{"one service", Exclusion{Permission: "new:*", Resource: "aws_new_thing"}, false},
		{"another type", Exclusion{Permission: "*", Resource: "aws_other"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, excluded := ApplyExclusions([]MissingAction{u}, []Exclusion{tc.ex})
			if got := len(excluded) == 1; got != tc.want {
				t.Errorf("excluded = %v (kept %v), want excluded %v", excluded, kept, tc.want)
			}
		})
	}
}

func TestParseConfig_AllowUnresolvedTypes(t *testing.T) {
	cfg, err := parseConfig([]byte(`{"allow_unresolved_types": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowUnresolvedTypes {
		t.Error("allow_unresolved_types not read")
	}
}
