package provideraws_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

// stubProvider stands in for the CloudFormation registry.
type stubProvider map[string]*cloud.Schema

func (s stubProvider) Name() string { return "stub" }
func (s stubProvider) Resolve(tfType string) (*cloud.Schema, error) {
	if schema, ok := s[tfType]; ok {
		return schema, nil
	}
	return nil, fmt.Errorf("%q: not in stub", tfType)
}

// missingFor validates a bare create of tfType against a policy that allows
// only s3:ListBucket (what HeadBucket needs) and returns the missing actions.
func missingFor(t *testing.T, resolver iam.Resolver, tfType string) map[string]bool {
	t.Helper()
	policy, err := iam.ParsePolicy([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	changes := []*plan.ResourceChange{{
		Type:              tfType,
		Name:              "this",
		Change:            "create",
		Attributes:        map[string]bool{"bucket": true},
		ChangedAttributes: map[string]bool{"bucket": true},
	}}
	missing, err := iam.Validate(changes, policy, resolver, iam.DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool)
	for _, m := range missing {
		got[m.Action] = true
	}
	return got
}

// bucketTree writes a provider checkout holding a trimmed S3 package: the
// bucket create makes its CreateBucket call inside a retry closure, and the
// read calls a helper from another file.
func bucketTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	s3Dir := filepath.Join(dir, "internal", "service", "s3")
	if err := os.MkdirAll(s3Dir, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"bucket.go": `package s3

// @SDKResource("aws_s3_bucket", name="Bucket")
func resourceBucket() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceBucketCreate,
		ReadWithoutTimeout:   resourceBucketRead,
		DeleteWithoutTimeout: resourceBucketDelete,
	}
}

func resourceBucketCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	_, err := tfresource.RetryWhenAWSErrCodeEquals(ctx, d.Timeout(schema.TimeoutCreate), func() (interface{}, error) {
		return conn.CreateBucket(ctx, input)
	}, errCodeOperationAborted)
	return append(diags, resourceBucketRead(ctx, d, meta)...)
}

func resourceBucketRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	_, err := findBucket(ctx, conn, d.Id())
	policy, err := findBucketPolicy(ctx, conn, d.Id())
	return nil
}

func resourceBucketDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	_, err := conn.DeleteBucket(ctx, &s3.DeleteBucketInput{})
	return nil
}

func findBucket(ctx context.Context, conn *s3.Client, bucket string) (*s3.HeadBucketOutput, error) {
	return conn.HeadBucket(ctx, &s3.HeadBucketInput{})
}
`,
		"bucket_policy.go": `package s3

func findBucketPolicy(ctx context.Context, conn *s3.Client, bucket string) (string, error) {
	output, err := conn.GetBucketPolicy(ctx, nil)
	return "", err
}
`,
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(s3Dir, name), []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestBareS3BucketCreateNeedsCreateBucket_Fixture is the regression for the
// false negative where the source parser emitted no create action for
// aws_s3_bucket, so a plan creating a bare bucket reported nothing missing.
func TestBareS3BucketCreateNeedsCreateBucket_Fixture(t *testing.T) {
	source := provideraws.NewSourceProviderWithPath(bucketTree(t))
	missing := missingFor(t, cloud.NewChainProvider(source, stubProvider{}), "aws_s3_bucket")
	if !missing["s3:CreateBucket"] {
		t.Errorf("s3:CreateBucket not reported missing; got %v", missing)
	}
	if missing["s3:ListBucket"] {
		t.Errorf("s3:ListBucket is allowed but was reported missing")
	}

	// The read reaches findBucketPolicy in bucket_policy.go.
	schema, err := source.Resolve("aws_s3_bucket")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(schema.Actions("read"), "s3:GetBucketPolicy") {
		t.Errorf("read = %v, want s3:GetBucketPolicy from the other file", schema.Actions("read"))
	}
}

// TestIncompleteCreateFallsBackToNextProvider checks the chain end to end: a
// create whose function uses a client but whose parse finds no mutating call
// is incomplete, so the next provider's create actions are reported.
func TestIncompleteCreateFallsBackToNextProvider(t *testing.T) {
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "internal", "service", "thing")
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatal(err)
	}
	src := `package thing

// @SDKResource("aws_thing_widget", name="Widget")
func resourceWidget() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceWidgetCreate,
		ReadWithoutTimeout:   resourceWidgetRead,
		DeleteWithoutTimeout: resourceWidgetDelete,
	}
}

// The create hands its client to code the parser cannot follow.
func resourceWidgetCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ThingClient(ctx)
	if err := somepkg.Create(ctx, conn, d); err != nil {
		return nil
	}
	return append(diags, resourceWidgetRead(ctx, d, meta)...)
}

func resourceWidgetRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ThingClient(ctx)
	conn.GetWidget(ctx, nil)
	return nil
}

// The delete cannot remove anything and says so.
func resourceWidgetDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	log.Printf("[WARN] Cannot destroy Widget")
	return nil
}
`
	if err := os.WriteFile(filepath.Join(svcDir, "widget.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	source := provideraws.NewSourceProviderWithPath(dir)
	schema, err := source.Resolve("aws_thing_widget")
	if err != nil {
		t.Fatal(err)
	}
	if !schema.Incomplete["create"] {
		t.Errorf("create should be incomplete: %v", schema.Ops)
	}
	if schema.Incomplete["read"] || schema.Incomplete["delete"] {
		t.Errorf("read and the no-op delete should be complete, got Incomplete=%v", schema.Incomplete)
	}

	cfn := stubProvider{"aws_thing_widget": {TypeName: "AWS::Thing::Widget", Ops: map[string][]iam.Requirement{
		"create": iam.Unconditional("thing:CreateWidget"),
		"delete": iam.Unconditional("thing:DeleteWidget"),
	}}}
	resolved, err := cloud.NewChainProvider(source, cfn).Resolve("aws_thing_widget")
	if err != nil {
		t.Fatal(err)
	}
	merged := resolved.(*cloud.Schema)
	if !contains(merged.Actions("create"), "thing:CreateWidget") || !contains(merged.Actions("create"), "thing:GetWidget") {
		t.Errorf("create = %v, want the parsed read plus thing:CreateWidget", merged.Actions("create"))
	}
	if contains(merged.Actions("delete"), "thing:DeleteWidget") {
		t.Errorf("the no-op delete took the fallback's actions: %v", merged.Actions("delete"))
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// TestBareS3BucketCreateNeedsCreateBucket_Checkout runs the same check
// against the real provider source. It needs the checkout, so it skips in
// -short mode and when the checkout is absent.
func TestBareS3BucketCreateNeedsCreateBucket_Checkout(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the provider checkout")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	dir := filepath.Join(home, ".cache", "terraform-permcheck", "provider-aws")
	if _, err := os.Stat(filepath.Join(dir, "internal", "service", "s3", "bucket.go")); err != nil {
		t.Skipf("provider checkout not found at %s", dir)
	}

	source := provideraws.NewSourceProviderWithPath(dir)
	missing := missingFor(t, cloud.NewChainProvider(source, stubProvider{}), "aws_s3_bucket")
	if !missing["s3:CreateBucket"] {
		t.Errorf("s3:CreateBucket not reported missing; got %v", missing)
	}

	// The other operations of the bucket and of a log group, checked against
	// internal/service/s3/bucket.go and internal/service/logs/group.go.
	for tfType, ops := range map[string]map[string][]string{
		"aws_s3_bucket": {
			"read":   {"s3:ListBucket", "s3:GetBucketPolicy", "s3:GetBucketVersioning"},
			"update": {"s3:PutBucketPolicy", "s3:PutBucketVersioning"},
			"delete": {"s3:DeleteBucket"},
		},
		"aws_cloudwatch_log_group": {
			"create": {"logs:CreateLogGroup", "logs:PutRetentionPolicy", "logs:DescribeLogGroups"},
			"read":   {"logs:DescribeLogGroups"},
			"delete": {"logs:DeleteLogGroup"},
		},
	} {
		schema, err := source.Resolve(tfType)
		if err != nil {
			t.Fatal(err)
		}
		for op, wants := range ops {
			for _, want := range wants {
				if !contains(schema.Actions(op), want) {
					t.Errorf("%s %s is missing %s; got %v", tfType, op, want, schema.Actions(op))
				}
			}
		}
		if len(schema.Incomplete) != 0 {
			t.Errorf("%s: Incomplete = %v, want none", tfType, schema.Incomplete)
		}
	}
}
