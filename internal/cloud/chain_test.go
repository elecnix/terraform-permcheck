package cloud

import (
	"fmt"
	"reflect"
	"testing"
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
			"aws_backup_vault": {TypeName: "aws_backup_vault", Permissions: map[string][]string{
				"create": {"backup:CreateBackupVault"},
			}},
		},
	}
	mockFallback := &mockProvider{
		name: "fallback",
		schemas: map[string]*Schema{
			"aws_dynamodb_table": {TypeName: "aws_dynamodb_table", Permissions: map[string][]string{
				"create": {"dynamodb:CreateTable"},
			}},
		},
	}

	chain := NewChainProvider(mockPrimary, mockFallback)

	// Primary handles backup_vault
	schema, err := chain.Resolve("aws_backup_vault")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if schema.TypeName != "aws_backup_vault" {
		t.Errorf("got type %q, want aws_backup_vault", schema.TypeName)
	}

	// Fallback handles dynamodb_table (not in primary)
	schema, err = chain.Resolve("aws_dynamodb_table")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if schema.TypeName != "aws_dynamodb_table" {
		t.Errorf("got type %q, want aws_dynamodb_table", schema.TypeName)
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
		Permissions: map[string][]string{
			"create": {"s3:ListTagsForResource", "s3:PutBucketTagging"},
			"read":   {"s3:HeadBucket"},
		},
		Conditional: map[string]map[string]string{
			"create": {"s3:PutBucketTagging": "tags"},
		},
		Incomplete: map[string]bool{"create": true, "delete": true},
	}
	primary := &mockProvider{name: "source", schemas: map[string]*Schema{"aws_s3_bucket": primarySchema}}
	fallback := &mockProvider{name: "cfn", schemas: map[string]*Schema{
		"aws_s3_bucket": {TypeName: "AWS::S3::Bucket", Permissions: map[string][]string{
			"create": {"s3:CreateBucket", "s3:PutBucketTagging"},
			"read":   {"s3:GetBucketPolicy"},
			"delete": {"s3:DeleteBucket"},
		}},
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
	if !reflect.DeepEqual(schema.Permissions, want) {
		t.Errorf("permissions = %v, want %v", schema.Permissions, want)
	}
	if got := schema.Conditional["create"]["s3:PutBucketTagging"]; got != "tags" {
		t.Errorf("the primary's gate on s3:PutBucketTagging was lost: %q", got)
	}
	if len(schema.Incomplete) != 0 {
		t.Errorf("Incomplete = %v, want none left", schema.Incomplete)
	}

	// The primary's cached schema must not change.
	if len(primarySchema.Permissions["create"]) != 2 || primarySchema.Permissions["delete"] != nil {
		t.Errorf("the primary schema was modified: %v", primarySchema.Permissions)
	}
}

// TestChainProvider_IncompleteWithoutFallback returns the first provider's
// schema unchanged when no later provider knows the type.
func TestChainProvider_IncompleteWithoutFallback(t *testing.T) {
	s := &Schema{
		TypeName:    "aws_thing",
		Permissions: map[string][]string{"read": {"thing:GetThing"}},
		Incomplete:  map[string]bool{"create": true},
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
