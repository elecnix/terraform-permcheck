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

	changes, checked, _ := staticChanges(blocks, resolver)

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

	changes, checked, _ := staticChanges(blocks, resolver)

	if got, want := staticOpChanges(changes), "aws_s3_bucket.create"; strings.Join(got, ",") != want {
		t.Errorf("changes = %v, want [%s]", got, want)
	}
	if checked != 1 {
		t.Errorf("checked = %d, want 1", checked)
	}
}

// TestStaticChanges_KeepsUnresolvableTypes verifies that a type the resolver
// cannot map yields one create entry per block, so validation reports each
// address as unresolved, and that it does not count as checked. A type
// repeated across several blocks still counts once.
func TestStaticChanges_KeepsUnresolvableTypes(t *testing.T) {
	blocks := []hcl.ResourceBlock{
		{Type: "aws_s3_bucket", Name: "a"},
		{Type: "aws_s3_bucket", Name: "b"},
		{Type: "aws_unknown_service_thing", Name: "c"},
		{Type: "aws_unknown_service_thing", Name: "d"},
	}
	resolver := fakePermResolver{
		"aws_s3_bucket": {"create": {"s3:CreateBucket"}},
	}

	changes, checked, err := staticChanges(blocks, resolver)
	if err != nil {
		t.Fatal(err)
	}

	want := "aws_s3_bucket.create,aws_s3_bucket.create,aws_unknown_service_thing.create,aws_unknown_service_thing.create"
	if got := staticOpChanges(changes); strings.Join(got, ",") != want {
		t.Errorf("changes = %v, want [%s]", got, want)
	}
	if changes[2].Name != "c" || changes[3].Name != "d" {
		t.Errorf("unresolved names = %s, %s; want c, d", changes[2].Name, changes[3].Name)
	}
	if checked != 1 {
		t.Errorf("checked = %d, want 1 (only the resolvable type was checked)", checked)
	}
}

// TestStaticChanges_LookupFailure verifies that a failed lookup stops static
// mode with the error instead of dropping the type.
func TestStaticChanges_LookupFailure(t *testing.T) {
	blocks := []hcl.ResourceBlock{{Type: "aws_s3_bucket", Name: "a"}}
	_, _, err := staticChanges(blocks, failingResolver{})
	if !errors.Is(err, iam.ErrLookupFailed) {
		t.Fatalf("err = %v, want ErrLookupFailed", err)
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

	changes, _, _ := staticChanges(blocks, resolver)

	if len(changes) != 2 {
		t.Fatalf("changes = %v, want 2 entries", staticOpChanges(changes))
	}
	for _, rc := range changes {
		if !rc.Attributes["tags"] || !rc.Attributes["name"] || rc.Attributes["absent"] {
			t.Errorf("%s attributes = %v, want name and tags set", rc.Change, rc.Attributes)
		}
	}
}

// TestStaticChanges_EachBlockKeepsItsAttributes verifies that every block of
// a type is checked with its own attributes. A permission gated on an
// attribute only the second block sets must still be checked, and reported
// on that block.
func TestStaticChanges_EachBlockKeepsItsAttributes(t *testing.T) {
	blocks := []hcl.ResourceBlock{
		{Mode: "resource", Type: "aws_api_gateway_rest_api", Name: "plain", Attributes: []string{"name"}},
		{Mode: "resource", Type: "aws_api_gateway_rest_api", Name: "openapi", Attributes: []string{"name", "body"}},
	}
	resolver := fakePermResolver{"aws_api_gateway_rest_api": {"create": {"apigateway:POST"}}}

	changes, checked, err := staticChanges(blocks, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0].Name != "plain" || changes[1].Name != "openapi" {
		t.Fatalf("changes = %v, want one create per block", staticOpChanges(changes))
	}
	if changes[0].Attributes["body"] || !changes[1].Attributes["body"] {
		t.Errorf("body presence = %v, %v; want false for plain, true for openapi",
			changes[0].Attributes["body"], changes[1].Attributes["body"])
	}
	if checked != 1 {
		t.Errorf("checked = %d, want 1 resource type", checked)
	}
}

// TestStaticChanges_SkipsDataBlocks verifies that a data block, which only
// reads, is not checked as a resource the configuration manages.
func TestStaticChanges_SkipsDataBlocks(t *testing.T) {
	blocks := []hcl.ResourceBlock{
		{Mode: "data", Type: "aws_iam_policy_document", Name: "p"},
		{Mode: "resource", Type: "aws_s3_bucket", Name: "b"},
	}
	resolver := fakePermResolver{"aws_s3_bucket": {"create": {"s3:CreateBucket"}}}

	changes, checked, err := staticChanges(blocks, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if got := staticOpChanges(changes); strings.Join(got, ",") != "aws_s3_bucket.create" || checked != 1 {
		t.Errorf("changes = %v, checked = %d; want only the bucket", got, checked)
	}
}
