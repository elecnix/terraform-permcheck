package provideraws

import "testing"

const kmsTagsGenSrc = `
package kms

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func updateTags(ctx context.Context, conn *kms.Client, identifier string, oldTagsMap, newTagsMap any) error {
	removedTags := oldTags.Removed(newTags)
	if len(removedTags) > 0 {
		input := kms.UntagResourceInput{KeyId: aws.String(identifier)}
		_, err := conn.UntagResource(ctx, &input)
		if err != nil {
			return err
		}
	}
	updatedTags := oldTags.Updated(newTags)
	if len(updatedTags) > 0 {
		input := kms.TagResourceInput{KeyId: aws.String(identifier)}
		_, err := conn.TagResource(ctx, &input)
		if err != nil {
			return err
		}
	}
	return nil
}
`

func TestExtractTagActions_KMS(t *testing.T) {
	ta, err := ExtractTagActions(kmsTagsGenSrc)
	if err != nil {
		t.Fatalf("ExtractTagActions failed: %v", err)
	}

	if !contains(ta.Apply, "kms:TagResource") {
		t.Errorf("expected kms:TagResource in Apply, got %v", ta.Apply)
	}
	if !contains(ta.Remove, "kms:UntagResource") {
		t.Errorf("expected kms:UntagResource in Remove, got %v", ta.Remove)
	}
	if contains(ta.Apply, "kms:UntagResource") {
		t.Errorf("UntagResource should not be classified as an apply action: %v", ta.Apply)
	}
}

func TestExtractTagActions_CreateDeleteTags(t *testing.T) {
	// Services like EC2 use CreateTags/DeleteTags instead of Tag/UntagResource.
	src := `
package ec2

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func updateTags(ctx context.Context, conn *ec2.Client, identifier string, oldTagsMap, newTagsMap any) error {
	if len(removed) > 0 {
		_, err := conn.DeleteTags(ctx, &ec2.DeleteTagsInput{})
		_ = err
	}
	if len(added) > 0 {
		_, err := conn.CreateTags(ctx, &ec2.CreateTagsInput{})
		_ = err
	}
	return nil
}
`
	ta, err := ExtractTagActions(src)
	if err != nil {
		t.Fatalf("ExtractTagActions failed: %v", err)
	}
	if !contains(ta.Apply, "ec2:CreateTags") {
		t.Errorf("expected ec2:CreateTags in Apply, got %v", ta.Apply)
	}
	if !contains(ta.Remove, "ec2:DeleteTags") {
		t.Errorf("expected ec2:DeleteTags in Remove, got %v", ta.Remove)
	}
}

func TestHasTagsAnnotation(t *testing.T) {
	withTags := []byte("// @SDKResource(\"aws_kms_key\", name=\"Key\")\n// @Tags(identifierAttribute=\"id\")\n")
	if !hasTagsAnnotation(withTags) {
		t.Error("expected @Tags annotation to be detected")
	}

	withoutTags := []byte("// @SDKResource(\"aws_kms_key_policy\", name=\"Key Policy\")\n")
	if hasTagsAnnotation(withoutTags) {
		t.Error("did not expect @Tags annotation to be detected")
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
