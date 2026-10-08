package check

import (
	"errors"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/hcl"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// fakePermResolver resolves terraform resource types from a fixed table of
// operation → ungated actions.
type fakePermResolver map[string]map[string][]string

func (r fakePermResolver) Resolve(t string) (iam.Schema, error) {
	perms, ok := r[t]
	if !ok {
		return nil, errors.New("unknown type " + t)
	}
	s := &cloud.Schema{TypeName: t, Ops: make(map[string][]iam.Requirement, len(perms))}
	for op, actions := range perms {
		s.Ops[op] = iam.Unconditional(actions...)
	}
	return s, nil
}

// staticOpChanges collapses changes to "type.change" for readable assertions.
func staticOpChanges(changes []*plan.ResourceChange) []string {
	out := make([]string, 0, len(changes))
	for _, rc := range changes {
		out = append(out, rc.Type+"."+rc.Change)
	}
	return out
}

// TestStaticChanges_OnlyEmitsOperationsWithDistinctPermissions verifies that
// static mode emits a ResourceChange only for operations whose permissions add
// something the create check does not already cover. An operation identical to
// create would produce the same result, so three entries per resource type
// would be noise.
func TestStaticChanges_OnlyEmitsOperationsWithDistinctPermissions(t *testing.T) {
	blocks := []hcl.ResourceBlock{
		{Type: "aws_kms_key", Name: "example", Attributes: []string{"description"}},
	}
	resolver := fakePermResolver{
		"aws_kms_key": {
			"create": {"kms:CreateKey", "kms:TagResource"},
			"read":   {"kms:DescribeKey"},
			"update": {"kms:CreateKey", "kms:TagResource", "kms:EnableKeyRotation"},
			"delete": {"kms:ScheduleKeyDeletion"},
		},
	}

	changes, checked := staticChanges(blocks, resolver)

	want := []string{"aws_kms_key.create", "aws_kms_key.update", "aws_kms_key.delete"}
	got := staticOpChanges(changes)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("changes = %v, want %v", got, want)
	}
	// One resource type, three operations: the count reports types, not entries.
	if checked != 1 {
		t.Errorf("checked = %d, want 1 resource type", checked)
	}
}

// TestStaticChanges_SkipsOperationsCoveredByCreate verifies that operations
// whose permissions are empty or already contained in the create set produce
// no entry, so the output stays proportional.
func TestStaticChanges_SkipsOperationsCoveredByCreate(t *testing.T) {
	blocks := []hcl.ResourceBlock{
		{Type: "aws_s3_bucket", Name: "logs"},
	}
	resolver := fakePermResolver{
		"aws_s3_bucket": {
			"create": {"s3:CreateBucket", "s3:PutBucketWebsite"},
			"update": {"s3:CreateBucket", "s3:PutBucketWebsite"},
			"delete": nil,
		},
	}

	changes, checked := staticChanges(blocks, resolver)

	if got, want := staticOpChanges(changes), "aws_s3_bucket.create"; strings.Join(got, ",") != want {
		t.Errorf("changes = %v, want [%s]", got, want)
	}
	if checked != 1 {
		t.Errorf("checked = %d, want 1", checked)
	}
}

// TestStaticChanges_SkipsUnresolvableTypes verifies that a type the resolver
// cannot map produces no entry, and that a type repeated across several blocks
// still counts once.
func TestStaticChanges_SkipsUnresolvableTypes(t *testing.T) {
	blocks := []hcl.ResourceBlock{
		{Type: "aws_s3_bucket", Name: "a"},
		{Type: "aws_s3_bucket", Name: "b"},
		{Type: "aws_unknown_service_thing", Name: "c"},
	}
	resolver := fakePermResolver{
		"aws_s3_bucket": {"create": {"s3:CreateBucket"}},
	}

	changes, checked := staticChanges(blocks, resolver)

	if got, want := staticOpChanges(changes), "aws_s3_bucket.create"; strings.Join(got, ",") != want {
		t.Errorf("changes = %v, want [%s]", got, want)
	}
	if checked != 1 {
		t.Errorf("checked = %d, want 1 (only the resolvable type was checked)", checked)
	}
}

// TestStaticChanges_CarriesParsedAttributes verifies that every emitted entry
// carries the parsed top-level attributes, so conditional permission filtering
// works for update and delete as well as create.
func TestStaticChanges_CarriesParsedAttributes(t *testing.T) {
	blocks := []hcl.ResourceBlock{
		{Type: "aws_dynamodb_table", Name: "items", Attributes: []string{"name", "tags"}},
	}
	resolver := fakePermResolver{
		"aws_dynamodb_table": {
			"create": {"dynamodb:CreateTable"},
			"delete": {"dynamodb:DeleteTable", "dynamodb:TagResource"},
		},
	}

	changes, _ := staticChanges(blocks, resolver)

	if len(changes) != 2 {
		t.Fatalf("changes = %v, want 2 entries", staticOpChanges(changes))
	}
	for _, rc := range changes {
		if !rc.Attributes["tags"] || !rc.Attributes["name"] || rc.Attributes["absent"] {
			t.Errorf("%s attributes = %v, want name and tags set", rc.Change, rc.Attributes)
		}
	}
}
