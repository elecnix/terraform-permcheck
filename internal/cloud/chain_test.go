package cloud

import (
	"fmt"
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
