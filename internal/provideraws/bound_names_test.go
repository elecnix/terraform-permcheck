package provideraws

import (
	"os"
	"path/filepath"
	"testing"
)

// A resource whose create and update are one Put function and whose delete is
// schema.NoopContext has no function named ...Create or ...Delete. Its
// operations come from the schema.Resource bindings.
func TestSourceProvider_PutBoundResource(t *testing.T) {
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "internal", "service", "guardduty")
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatal(err)
	}
	src := `
// @SDKResource("aws_guardduty_detector_feature", name="Detector Feature")
package guardduty

import (
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

func ResourceDetectorFeature() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceDetectorFeaturePut,
		ReadWithoutTimeout:   resourceDetectorFeatureRead,
		UpdateWithoutTimeout: resourceDetectorFeaturePut,
		DeleteWithoutTimeout: schema.NoopContext,
	}
}

func resourceDetectorFeaturePut(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).GuardDutyClient(ctx)
	_, err := conn.UpdateDetector(ctx, &guardduty.UpdateDetectorInput{})
	if err != nil { return nil }
	return nil
}

func resourceDetectorFeatureRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).GuardDutyClient(ctx)
	_, err := conn.GetDetector(ctx, &guardduty.GetDetectorInput{})
	if err != nil { return nil }
	return nil
}
`
	if err := os.WriteFile(filepath.Join(svcDir, "detector_feature.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewSourceProviderWithPath(dir)
	schema, err := p.Resolve("aws_guardduty_detector_feature")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := schema.Actions("create"); !containsAction(got, "guardduty:UpdateDetector") {
		t.Errorf("create: want guardduty:UpdateDetector, got %v", got)
	}
	if got := schema.Actions("read"); !containsAction(got, "guardduty:GetDetector") {
		t.Errorf("read: want guardduty:GetDetector, got %v", got)
	}
}

// A create bound to a method of a handler struct names no function the parser
// can follow. The type stays unresolved instead of getting an entry with no
// actions, which would let a plan through unchecked.
func TestSourceProvider_MethodBoundCreateStaysUnresolved(t *testing.T) {
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "internal", "service", "sqs")
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatal(err)
	}
	src := `
// @SDKResource("aws_sqs_queue_policy", name="Queue Policy")
package sqs

func resourceQueuePolicy() *schema.Resource {
	h := &queueAttributeHandler{}
	return &schema.Resource{
		CreateWithoutTimeout: h.Upsert,
		ReadWithoutTimeout:   h.Read,
		DeleteWithoutTimeout: h.Delete,
	}
}
`
	if err := os.WriteFile(filepath.Join(svcDir, "queue_policy.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSourceProviderWithPath(dir).Resolve("aws_sqs_queue_policy"); err == nil {
		t.Error("Resolve succeeded for a create bound to a method, want not found")
	}
}
