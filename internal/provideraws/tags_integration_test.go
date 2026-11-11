package provideraws

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
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

	create := schema.Actions("create")
	if !contains(create, "kms:CreateKey") {
		t.Errorf("expected kms:CreateKey in create perms, got %v", create)
	}
	if !contains(create, "kms:TagResource") {
		t.Errorf("expected kms:TagResource added to create perms, got %v", create)
	}
	if gates := schema.Gates("create", "kms:TagResource"); !reflect.DeepEqual(gates, []iam.Gate{{Attribute: "tags"}}) {
		t.Errorf("expected kms:TagResource gated on tags, got %+v", gates)
	}

	// UntagResource is an update-only side effect (no removals on create).
	if contains(create, "kms:UntagResource") {
		t.Errorf("did not expect kms:UntagResource in create perms, got %v", create)
	}
	update := schema.Actions("update")
	if !contains(update, "kms:UntagResource") {
		t.Errorf("expected kms:UntagResource in update perms, got %v", update)
	}
	if gates := schema.Gates("update", "kms:UntagResource"); !reflect.DeepEqual(gates, []iam.Gate{{Attribute: "tags"}}) {
		t.Errorf("expected kms:UntagResource gated on tags in update, got %+v", gates)
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
	read := schema.Actions("read")
	if !contains(read, "kms:ListResourceTags") {
		t.Errorf("expected kms:ListResourceTags in read perms, got %v", read)
	}
	// ListResourceTags on read is unconditional — never gated on tags.
	for _, g := range schema.Gates("read", "kms:ListResourceTags") {
		if g.Attribute != "" {
			t.Errorf("ListResourceTags on read must be unconditional (no gating attribute), got %q", g.Attribute)
		}
	}

	// Create should also have ListResourceTags (Create returns Read).
	create := schema.Actions("create")
	if !contains(create, "kms:ListResourceTags") {
		t.Errorf("expected kms:ListResourceTags in create perms (Create returns Read), got %v", create)
	}
	for _, g := range schema.Gates("create", "kms:ListResourceTags") {
		if g.Attribute != "" {
			t.Errorf("ListResourceTags on create must be unconditional, got %q", g.Attribute)
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
	if contains(schema.Actions("read"), "kms:ListResourceTags") {
		t.Errorf("did not expect list-tags action on non-taggable resource read, got %v", schema.Actions("read"))
	}
	if contains(schema.Actions("create"), "kms:TagResource") {
		t.Errorf("did not expect tag actions on non-taggable resource, got %v", schema.Actions("create"))
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
	if contains(schema.Actions("create"), "kms:TagResource") {
		t.Errorf("did not expect tag actions on non-taggable resource, got %v", schema.Actions("create"))
	}
}

// writeService writes the files of one service package under a fresh
// provider tree and returns a provider over it.
func writeService(t *testing.T, service string, files map[string]string) *SourceProvider {
	t.Helper()
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "internal", "service", service)
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(svcDir, name), []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return NewSourceProviderWithPath(dir)
}

// TestSourceProvider_TagsDispatchOnResourceType follows the transparent
// tagging of internal/service/kinesis (provider v6.72.0). The tagging
// functions live in a hand-written tags.go, not tags_gen.go, and the
// servicePackage methods the provider calls pick them by the resourceType of
// the @Tags annotation: a stream uses the stream tagging API, every other
// type the resource tagging API.
func TestSourceProvider_TagsDispatchOnResourceType(t *testing.T) {
	p := writeService(t, "kinesis", map[string]string{
		"stream.go": `package kinesis

// @SDKResource("aws_kinesis_stream", name="Stream")
// @Tags(identifierAttribute="name", resourceType="Stream")
func resourceStreamCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KinesisClient(ctx)
	_, err := conn.CreateStream(ctx, &input)
	return nil
}

func resourceStreamRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KinesisClient(ctx)
	_, err := conn.DescribeStreamSummary(ctx, &input)
	return nil
}

func resourceStreamDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KinesisClient(ctx)
	_, err := conn.DeleteStream(ctx, &input)
	return nil
}
`,
		"tags_gen.go": `package kinesis

func getTagsIn(ctx context.Context) []awstypes.Tag {
	return nil
}
`,
		"tags.go": `package kinesis

func listTags(ctx context.Context, conn *kinesis.Client, identifier string, optFns ...func(*kinesis.Options)) (tftags.KeyValueTags, error) {
	output, err := conn.ListTagsForResource(ctx, &input, optFns...)
	return nil, err
}

func updateTags(ctx context.Context, conn *kinesis.Client, identifier string, oldTagsMap, newTagsMap any, optFns ...func(*kinesis.Options)) error {
	_, err := conn.UntagResource(ctx, &input, optFns...)
	_, err = conn.TagResource(ctx, &input, optFns...)
	return nil
}

func listTagsForStream(ctx context.Context, conn *kinesis.Client, identifier string, optFns ...func(*kinesis.Options)) (tftags.KeyValueTags, error) {
	output, err := conn.ListTagsForStream(ctx, &input, optFns...)
	return nil, err
}

func updateTagsForStream(ctx context.Context, conn *kinesis.Client, identifier string, oldTagsMap, newTagsMap any, optFns ...func(*kinesis.Options)) error {
	_, err := conn.RemoveTagsFromStream(ctx, &input, optFns...)
	_, err = conn.AddTagsToStream(ctx, &input, optFns...)
	return nil
}

func (p *servicePackage) ListTags(ctx context.Context, meta any, identifier, resourceType string) error {
	var (
		tags tftags.KeyValueTags
		err  error
	)
	conn := meta.(*conns.AWSClient).KinesisClient(ctx)

	switch resourceType {
	case "Stream":
		tags, err = listTagsForStream(ctx, conn, identifier)

	default:
		tags, err = listTags(ctx, conn, identifier)
	}
	return err
}

func (p *servicePackage) UpdateTags(ctx context.Context, meta any, identifier, resourceType string, oldTags, newTags any) error {
	conn := meta.(*conns.AWSClient).KinesisClient(ctx)

	switch resourceType {
	case "Stream":
		return updateTagsForStream(ctx, conn, identifier, oldTags, newTags)

	default:
		return updateTags(ctx, conn, identifier, oldTags, newTags)
	}
}
`,
	})
	s, err := p.Resolve("aws_kinesis_stream")
	if err != nil {
		t.Fatal(err)
	}
	for op, want := range map[string][]string{
		"create": {"kinesis:AddTagsToStream", "kinesis:CreateStream", "kinesis:ListTagsForStream"},
		"read":   {"kinesis:DescribeStreamSummary", "kinesis:ListTagsForStream"},
		"update": {"kinesis:AddTagsToStream", "kinesis:RemoveTagsFromStream"},
		"delete": {"kinesis:DeleteStream"},
	} {
		got := append([]string(nil), s.Actions(op)...)
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", op, got, want)
		}
	}
	if gates := s.Gates("update", "kinesis:RemoveTagsFromStream"); !reflect.DeepEqual(gates, []iam.Gate{{Attribute: "tags"}}) {
		t.Errorf("update kinesis:RemoveTagsFromStream gates = %+v, want gated on tags", gates)
	}
}

// TestSourceProvider_ListTagsThroughPagingHelper follows the listTags of
// internal/service/firehose (provider v6.72.0), which pages through a helper
// in list_pages.go instead of calling the client itself.
func TestSourceProvider_ListTagsThroughPagingHelper(t *testing.T) {
	p := writeService(t, "firehose", map[string]string{
		"delivery_stream.go": `package firehose

// @SDKResource("aws_kinesis_firehose_delivery_stream", name="Delivery Stream")
// @Tags(identifierAttribute="name")
func resourceDeliveryStreamCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).FirehoseClient(ctx)
	_, err := conn.CreateDeliveryStream(ctx, &input)
	return nil
}

func resourceDeliveryStreamRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).FirehoseClient(ctx)
	_, err := conn.DescribeDeliveryStream(ctx, &input)
	return nil
}

func resourceDeliveryStreamDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).FirehoseClient(ctx)
	_, err := conn.DeleteDeliveryStream(ctx, &input)
	return nil
}
`,
		"tags_gen.go": `package firehose

func listTags(ctx context.Context, conn *firehose.Client, identifier string, optFns ...func(*firehose.Options)) (tftags.KeyValueTags, error) {
	var output []awstypes.Tag
	err := listTagsForDeliveryStreamPages(ctx, conn, &input, func(page *firehose.ListTagsForDeliveryStreamOutput, lastPage bool) bool {
		output = append(output, page.Tags...)
		return !lastPage
	}, optFns...)
	return nil, err
}

func (p *servicePackage) ListTags(ctx context.Context, meta any, identifier string) error {
	tags, err := listTags(ctx, meta.(*conns.AWSClient).FirehoseClient(ctx), identifier)
	return err
}

func updateTags(ctx context.Context, conn *firehose.Client, identifier string, oldTagsMap, newTagsMap any, optFns ...func(*firehose.Options)) error {
	_, err := conn.UntagDeliveryStream(ctx, &input, optFns...)
	_, err = conn.TagDeliveryStream(ctx, &input, optFns...)
	return nil
}

func (p *servicePackage) UpdateTags(ctx context.Context, meta any, identifier string, oldTags, newTags any) error {
	return updateTags(ctx, meta.(*conns.AWSClient).FirehoseClient(ctx), identifier, oldTags, newTags)
}
`,
		"list_pages.go": `package firehose

func listTagsForDeliveryStreamPages(ctx context.Context, conn *firehose.Client, input *firehose.ListTagsForDeliveryStreamInput, fn func(*firehose.ListTagsForDeliveryStreamOutput, bool) bool, optFns ...func(*firehose.Options)) error {
	for {
		output, err := conn.ListTagsForDeliveryStream(ctx, input, optFns...)
		if err != nil {
			return err
		}
	}
}
`,
	})
	s, err := p.Resolve("aws_kinesis_firehose_delivery_stream")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"create", "read"} {
		if got := s.Actions(op); !contains(got, "firehose:ListTagsForDeliveryStream") {
			t.Errorf("%s = %v, want firehose:ListTagsForDeliveryStream", op, got)
		}
	}
	if got := s.Actions("update"); !contains(got, "firehose:UntagDeliveryStream") || !contains(got, "firehose:TagDeliveryStream") {
		t.Errorf("update = %v, want firehose:TagDeliveryStream and firehose:UntagDeliveryStream", got)
	}
}

// TestSourceProvider_TagsCaseCallsAnotherPackage follows the bucket case of
// the s3 servicePackage.ListTags (provider v6.72.0), which lists tags through
// a function of the s3control package and falls back to a function of its own.
func TestSourceProvider_TagsCaseCallsAnotherPackage(t *testing.T) {
	dir := t.TempDir()
	for svc, files := range map[string]map[string]string{
		"s3": {
			"bucket.go": `package s3

// @SDKResource("aws_s3_bucket", name="Bucket")
// @Tags(identifierAttribute="bucket", resourceType="Bucket")
func resourceBucketCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	_, err := conn.CreateBucket(ctx, &input)
	return nil
}

func resourceBucketDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	_, err := conn.DeleteBucket(ctx, &input)
	return nil
}
`,
			"tags.go": `package s3

import tfs3control "github.com/hashicorp/terraform-provider-aws/internal/service/s3control"

func bucketListTags(ctx context.Context, conn *s3.Client, bucket string) (tftags.KeyValueTags, error) {
	output, err := conn.GetBucketTagging(ctx, &input)
	return nil, err
}

func objectListTags(ctx context.Context, conn *s3.Client, bucket, key string) (tftags.KeyValueTags, error) {
	output, err := conn.GetObjectTagging(ctx, &input)
	return nil, err
}

func (p *servicePackage) ListTags(ctx context.Context, meta any, identifier, resourceType string) error {
	c := meta.(*conns.AWSClient)
	conn := c.S3Client(ctx)

	switch resourceType {
	case "Bucket":
		tags, err = tfs3control.ListTags(ctx, c.S3ControlClient(ctx), identifier, accountID)
		if err != nil {
			tags, err = bucketListTags(ctx, conn, identifier)
		}

	case "Object", "ObjectCopy", "BucketObject":
		tags, err = objectListTags(ctx, conn, bucket, key)

	default:
		return nil
	}
	return err
}
`,
		},
		"s3control": {
			"tags.go": `package s3control

func listTags(ctx context.Context, conn *s3control.Client, identifier, accountID string) (tftags.KeyValueTags, error) {
	output, err := conn.ListTagsForResource(ctx, &input)
	return nil, err
}

var ListTags = listTags
`,
		},
	} {
		svcDir := filepath.Join(dir, "internal", "service", svc)
		if err := os.MkdirAll(svcDir, 0755); err != nil {
			t.Fatal(err)
		}
		for name, src := range files {
			if err := os.WriteFile(filepath.Join(svcDir, name), []byte(src), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	s, err := NewSourceProviderWithPath(dir).Resolve("aws_s3_bucket")
	if err != nil {
		t.Fatal(err)
	}
	got := append([]string(nil), s.Actions("read")...)
	sort.Strings(got)
	if want := []string{"s3:GetBucketTagging", "s3:ListTagsForResource"}; !reflect.DeepEqual(got, want) {
		t.Errorf("read = %v, want %v", got, want)
	}
}
