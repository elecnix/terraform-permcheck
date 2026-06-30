package provideraws

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSourceProvider_TagSideEffects verifies that a resource opting into
// transparent tagging (@Tags annotation) gets the service's tag SDK actions
// added as permissions gated on the `tags` attribute — the fix for issue #20.
func TestSourceProvider_TagSideEffects(t *testing.T) {
	dir := t.TempDir()
	kmsDir := filepath.Join(dir, "internal", "service", "kms")
	if err := os.MkdirAll(kmsDir, 0755); err != nil {
		t.Fatal(err)
	}

	keySrc := `
package kms

import "github.com/aws/aws-sdk-go-v2/service/kms"

// @SDKResource("aws_kms_key", name="Key")
// @Tags(identifierAttribute="id")
func resourceKeyCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KMSClient(ctx)
	_, err := conn.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil { return nil }
	return nil
}

func resourceKeyDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KMSClient(ctx)
	_, err := conn.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{})
	if err != nil { return nil }
	return nil
}
`
	if err := os.WriteFile(filepath.Join(kmsDir, "key.go"), []byte(keySrc), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(kmsDir, "tags_gen.go"), []byte(kmsTagsGenSrc), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewSourceProviderWithPath(dir)
	schema, err := p.Resolve("aws_kms_key")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	create := schema.Permissions["create"]
	if !contains(create, "kms:CreateKey") {
		t.Errorf("expected kms:CreateKey in create perms, got %v", create)
	}
	if !contains(create, "kms:TagResource") {
		t.Errorf("expected kms:TagResource added to create perms, got %v", create)
	}
	if schema.Conditional["create"]["kms:TagResource"] != "tags" {
		t.Errorf("expected kms:TagResource gated on tags, got %q", schema.Conditional["create"]["kms:TagResource"])
	}

	// UntagResource is an update-only side effect (no removals on create).
	if contains(create, "kms:UntagResource") {
		t.Errorf("did not expect kms:UntagResource in create perms, got %v", create)
	}
	update := schema.Permissions["update"]
	if !contains(update, "kms:UntagResource") {
		t.Errorf("expected kms:UntagResource in update perms, got %v", update)
	}
	if schema.Conditional["update"]["kms:UntagResource"] != "tags" {
		t.Errorf("expected kms:UntagResource gated on tags in update, got %q", schema.Conditional["update"]["kms:UntagResource"])
	}
}

// TestSourceProvider_ListTagsSideEffects verifies that a resource with the
// @Tags annotation gets the service's list-tags SDK action added unconditionally
// to read and create operations — the fix for issue #23.
func TestSourceProvider_ListTagsSideEffects(t *testing.T) {
	dir := t.TempDir()
	kmsDir := filepath.Join(dir, "internal", "service", "kms")
	if err := os.MkdirAll(kmsDir, 0755); err != nil {
		t.Fatal(err)
	}

	keySrc := `
package kms

import "github.com/aws/aws-sdk-go-v2/service/kms"

// @SDKResource("aws_kms_key", name="Key")
// @Tags(identifierAttribute="id")
func resourceKeyCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KMSClient(ctx)
	_, err := conn.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil { return nil }
	return nil
}

func resourceKeyRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KMSClient(ctx)
	_, err := conn.DescribeKey(ctx, &kms.DescribeKeyInput{})
	if err != nil { return nil }
	return nil
}

func resourceKeyDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KMSClient(ctx)
	_, err := conn.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{})
	if err != nil { return nil }
	return nil
}
`
	if err := os.WriteFile(filepath.Join(kmsDir, "key.go"), []byte(keySrc), 0644); err != nil {
		t.Fatal(err)
	}
	// kmsTagsGenSrc now includes listTags
	if err := os.WriteFile(filepath.Join(kmsDir, "tags_gen.go"), []byte(kmsTagsGenSrc), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewSourceProviderWithPath(dir)
	schema, err := p.Resolve("aws_kms_key")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Read should have ListResourceTags (unconditional — listTags is called on every Read).
	read := schema.Permissions["read"]
	if !contains(read, "kms:ListResourceTags") {
		t.Errorf("expected kms:ListResourceTags in read perms, got %v", read)
	}
	// ListResourceTags on read is unconditional — never gated on tags.
	if cond, ok := schema.Conditional["read"]; ok {
		if attr, exists := cond["kms:ListResourceTags"]; exists && attr != "" {
			t.Errorf("ListResourceTags on read must be unconditional (no gating attribute), got %q", attr)
		}
	}

	// Create should also have ListResourceTags (Create returns Read).
	create := schema.Permissions["create"]
	if !contains(create, "kms:ListResourceTags") {
		t.Errorf("expected kms:ListResourceTags in create perms (Create returns Read), got %v", create)
	}
	if cond, ok := schema.Conditional["create"]; ok {
		if attr, exists := cond["kms:ListResourceTags"]; exists && attr != "" {
			t.Errorf("ListResourceTags on create must be unconditional, got %q", attr)
		}
	}
}

// TestSourceProvider_NoListTagsWithoutAnnotation verifies that a resource
// without the @Tags annotation does not get list-tags actions added.
func TestSourceProvider_NoListTagsWithoutAnnotation(t *testing.T) {
	dir := t.TempDir()
	kmsDir := filepath.Join(dir, "internal", "service", "kms")
	if err := os.MkdirAll(kmsDir, 0755); err != nil {
		t.Fatal(err)
	}

	keySrc := `
package kms

import "github.com/aws/aws-sdk-go-v2/service/kms"

// @SDKResource("aws_kms_key_policy", name="Key Policy")
func resourceKeyPolicyCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KMSClient(ctx)
	_, err := conn.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{})
	if err != nil { return nil }
	return nil
}

func resourceKeyPolicyRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KMSClient(ctx)
	_, err := conn.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{})
	if err != nil { return nil }
	return nil
}
`
	if err := os.WriteFile(filepath.Join(kmsDir, "key_policy.go"), []byte(keySrc), 0644); err != nil {
		t.Fatal(err)
	}
	// kmsTagsGenSrc includes listTags, but resource lacks @Tags annotation
	if err := os.WriteFile(filepath.Join(kmsDir, "tags_gen.go"), []byte(kmsTagsGenSrc), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewSourceProviderWithPath(dir)
	schema, err := p.Resolve("aws_kms_key_policy")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if contains(schema.Permissions["read"], "kms:ListResourceTags") {
		t.Errorf("did not expect list-tags action on non-taggable resource read, got %v", schema.Permissions["read"])
	}
	if contains(schema.Permissions["create"], "kms:TagResource") {
		t.Errorf("did not expect tag actions on non-taggable resource, got %v", schema.Permissions["create"])
	}
}

// TestSourceProvider_NoTagSideEffectsWithoutAnnotation verifies that a resource
// without the @Tags annotation does not get tag actions added.
func TestSourceProvider_NoTagSideEffectsWithoutAnnotation(t *testing.T) {
	dir := t.TempDir()
	kmsDir := filepath.Join(dir, "internal", "service", "kms")
	if err := os.MkdirAll(kmsDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Resource without @Tags annotation.
	keySrc := `
package kms

import "github.com/aws/aws-sdk-go-v2/service/kms"

// @SDKResource("aws_kms_key_policy", name="Key Policy")
func resourceKeyPolicyCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KMSClient(ctx)
	_, err := conn.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{})
	if err != nil { return nil }
	return nil
}
`
	if err := os.WriteFile(filepath.Join(kmsDir, "key_policy.go"), []byte(keySrc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kmsDir, "tags_gen.go"), []byte(kmsTagsGenSrc), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewSourceProviderWithPath(dir)
	schema, err := p.Resolve("aws_kms_key_policy")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if contains(schema.Permissions["create"], "kms:TagResource") {
		t.Errorf("did not expect tag actions on non-taggable resource, got %v", schema.Permissions["create"])
	}
}
