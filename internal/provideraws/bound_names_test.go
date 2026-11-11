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

// The SQS queue policy types bind their operations to methods of a handler
// struct (h.Upsert) that another file of the package declares. The binding
// resolves to that method declaration.
func TestSourceProvider_HandlerMethodBinding(t *testing.T) {
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "internal", "service", "sqs")
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatal(err)
	}
	policy := `
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
	handler := `
package sqs

import "github.com/aws/aws-sdk-go-v2/service/sqs"

type queueAttributeHandler struct{}

func (h *queueAttributeHandler) Upsert(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).SQSClient(ctx)
	_, err := conn.SetQueueAttributes(ctx, &sqs.SetQueueAttributesInput{})
	if err != nil { return nil }
	return h.Read(ctx, d, meta)
}

func (h *queueAttributeHandler) Read(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).SQSClient(ctx)
	_, err := conn.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{})
	if err != nil { return nil }
	return nil
}

func (h *queueAttributeHandler) Delete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).SQSClient(ctx)
	_, err := conn.SetQueueAttributes(ctx, &sqs.SetQueueAttributesInput{})
	if err != nil { return nil }
	return nil
}
`
	for name, src := range map[string]string{"queue_policy.go": policy, "attribute_funcs.go": handler} {
		if err := os.WriteFile(filepath.Join(svcDir, name), []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := NewSourceProviderWithPath(dir).Resolve("aws_sqs_queue_policy")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := schema.Actions("create"); !containsAction(got, "sqs:SetQueueAttributes") {
		t.Errorf("create: want sqs:SetQueueAttributes, got %v", got)
	}
	if got := schema.Actions("read"); !containsAction(got, "sqs:GetQueueAttributes") {
		t.Errorf("read: want sqs:GetQueueAttributes, got %v", got)
	}
	if got := schema.Actions("delete"); !containsAction(got, "sqs:SetQueueAttributes") {
		t.Errorf("delete: want sqs:SetQueueAttributes, got %v", got)
	}
}

// A method binding on a receiver that is not a struct type of the package
// stays unresolved instead of getting an entry with no actions, which would
// let a plan through unchecked.
func TestSourceProvider_UnknownHandlerStaysUnresolved(t *testing.T) {
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
		t.Error("Resolve succeeded for a create bound to an undeclared type's method, want not found")
	}
}
