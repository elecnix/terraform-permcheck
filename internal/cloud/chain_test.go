package cloud

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

type mockProvider struct {
	name    string
	schemas map[string]*Schema
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Resolve(tfType string) (*Schema, error) {
	s, ok := m.schemas[tfType]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return s, nil
}

func TestChainProvider_FallsBack(t *testing.T) {
	mockPrimary := &mockProvider{
		name: "primary",
		schemas: map[string]*Schema{
			"aws_backup_vault": {TypeName: "aws_backup_vault", Ops: ungated(map[string][]string{
				"create": {"backup:CreateBackupVault"},
			})},
		},
	}
	mockFallback := &mockProvider{
		name: "fallback",
		schemas: map[string]*Schema{
			"aws_dynamodb_table": {TypeName: "aws_dynamodb_table", Ops: ungated(map[string][]string{
				"create": {"dynamodb:CreateTable"},
			})},
		},
	}

	chain := NewChainProvider(mockPrimary, mockFallback)

	// Primary handles backup_vault
	schema, err := chain.Resolve("aws_backup_vault")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := schema.(*Schema).TypeName; got != "aws_backup_vault" {
		t.Errorf("got type %q, want aws_backup_vault", got)
	}

	// Fallback handles dynamodb_table (not in primary)
	schema, err = chain.Resolve("aws_dynamodb_table")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := schema.(*Schema).TypeName; got != "aws_dynamodb_table" {
		t.Errorf("got type %q, want aws_dynamodb_table", got)
	}
}

func TestChainProvider_AllFail(t *testing.T) {
	mockA := &mockProvider{name: "a", schemas: map[string]*Schema{}}
	mockB := &mockProvider{name: "b", schemas: map[string]*Schema{}}

	chain := NewChainProvider(mockA, mockB)

	_, err := chain.Resolve("nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestChainProvider_Name(t *testing.T) {
	mockA := &mockProvider{name: "aws"}
	chain := NewChainProvider(mockA)

	if chain.Name() != "aws" {
		t.Errorf("expected 'aws', got %q", chain.Name())
	}
}

// TestChainProvider_MergesIncompleteOperations checks that an operation the
// first provider marks incomplete takes the next provider's actions, while
// the operations it resolved stay its own.
func TestChainProvider_MergesIncompleteOperations(t *testing.T) {
	primarySchema := &Schema{
		TypeName: "aws_s3_bucket",
		Ops: map[string][]iam.Requirement{
			"create": {
				{Action: "s3:ListTagsForResource"},
				{Action: "s3:PutBucketTagging", Gate: iam.Gate{Attribute: "tags"}},
			},
			"read": iam.Unconditional("s3:HeadBucket"),
		},
		Incomplete: map[string]bool{"create": true, "delete": true},
	}
	primary := &mockProvider{name: "source", schemas: map[string]*Schema{"aws_s3_bucket": primarySchema}}
	fallback := &mockProvider{name: "cfn", schemas: map[string]*Schema{
		"aws_s3_bucket": {TypeName: "AWS::S3::Bucket", Ops: ungated(map[string][]string{
			"create": {"s3:CreateBucket", "s3:PutBucketTagging"},
			"read":   {"s3:GetBucketPolicy"},
			"delete": {"s3:DeleteBucket"},
		})},
	}}

	schema, err := NewChainProvider(primary, fallback).Resolve("aws_s3_bucket")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string][]string{
		"create": {"s3:ListTagsForResource", "s3:PutBucketTagging", "s3:CreateBucket"},
		"read":   {"s3:HeadBucket"},
		"delete": {"s3:DeleteBucket"},
	}
	merged := schema.(*Schema)
	if got := actionsByOp(merged); !reflect.DeepEqual(got, want) {
		t.Errorf("permissions = %v, want %v", got, want)
	}
	if got := merged.Gates("create", "s3:PutBucketTagging"); !reflect.DeepEqual(got, []iam.Gate{{Attribute: "tags"}}) {
		t.Errorf("the primary's gate on s3:PutBucketTagging was lost: %+v", got)
	}
	if len(merged.Incomplete) != 0 {
		t.Errorf("Incomplete = %v, want none left", merged.Incomplete)
	}

	// The primary's cached schema must not change.
	if len(primarySchema.Ops["create"]) != 2 || primarySchema.Ops["delete"] != nil {
		t.Errorf("the primary schema was modified: %v", primarySchema.Ops)
	}
}

// TestChainProvider_IncompleteWithoutFallback returns the first provider's
// schema unchanged when no later provider knows the type.
func TestChainProvider_IncompleteWithoutFallback(t *testing.T) {
	s := &Schema{
		TypeName:   "aws_thing",
		Ops:        ungated(map[string][]string{"read": {"thing:GetThing"}}),
		Incomplete: map[string]bool{"create": true},
	}
	primary := &mockProvider{name: "source", schemas: map[string]*Schema{"aws_thing": s}}
	fallback := &mockProvider{name: "cfn", schemas: map[string]*Schema{}}

	got, err := NewChainProvider(primary, fallback).Resolve("aws_thing")
	if err != nil {
		t.Fatal(err)
	}
	if got != s {
		t.Errorf("expected the primary schema back unchanged")
	}
}

// TestChainProvider_FirstLaterProviderFillsEachOperation pins the merge rule
// completeFrom implements: an incomplete operation takes the actions of the
// FIRST later provider that has any for it, and no further provider's actions
// are merged into it once it is complete.
func TestChainProvider_FirstLaterProviderFillsEachOperation(t *testing.T) {
	primarySchema := &Schema{
		TypeName:   "aws_widget",
		Ops:        ungated(map[string][]string{"create": {"widget:CreateWidget"}}),
		Incomplete: map[string]bool{"create": true, "delete": true},
	}
	// The second provider knows create only, so delete stays incomplete for
	// the third provider to fill.
	second := &Schema{
		TypeName: "AWS::Widget::Widget",
		Ops:      ungated(map[string][]string{"create": {"widget:CreateWidgetAlias"}}),
	}
	third := &Schema{
		TypeName: "aws_widget_alternative",
		Ops: ungated(map[string][]string{
			"create": {"widget:CreateWidgetFromTemplate"},
			"delete": {"widget:DeleteWidget"},
		}),
	}

	chain := NewChainProvider(
		&mockProvider{name: "source", schemas: map[string]*Schema{"aws_widget": primarySchema}},
		&mockProvider{name: "cfn", schemas: map[string]*Schema{"aws_widget": second}},
		&mockProvider{name: "alternative", schemas: map[string]*Schema{"aws_widget": third}},
	)

	schema, err := chain.Resolve("aws_widget")
	if err != nil {
		t.Fatal(err)
	}
	got := schema.(*Schema)

	want := map[string][]string{
		"create": {"widget:CreateWidget", "widget:CreateWidgetAlias"},
		"delete": {"widget:DeleteWidget"},
	}
	if perms := actionsByOp(got); !reflect.DeepEqual(perms, want) {
		t.Errorf("permissions = %v, want %v", perms, want)
	}
	if len(got.Incomplete) != 0 {
		t.Errorf("Incomplete = %v, want none left", got.Incomplete)
	}
	// The primary's cached schema must survive both merges.
	if !reflect.DeepEqual(actionsByOp(primarySchema), map[string][]string{"create": {"widget:CreateWidget"}}) {
		t.Errorf("the primary schema was modified: %v", primarySchema.Ops)
	}
	if len(primarySchema.Incomplete) != 2 {
		t.Errorf("the primary schema's Incomplete was modified: %v", primarySchema.Incomplete)
	}
}

// ungated builds the requirements of operation → actions, with no gates.
func ungated(perms map[string][]string) map[string][]iam.Requirement {
	ops := make(map[string][]iam.Requirement, len(perms))
	for op, actions := range perms {
		ops[op] = iam.Unconditional(actions...)
	}
	return ops
}

// actionsByOp lists the distinct actions of every operation of s.
func actionsByOp(s *Schema) map[string][]string {
	out := make(map[string][]string, len(s.Ops))
	for op := range s.Ops {
		out[op] = s.Actions(op)
	}
	return out
}
