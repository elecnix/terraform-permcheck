package provideraws

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// frameworkLifecycleSrc is trimmed from internal/service/s3/
// bucket_lifecycle_configuration.go (provider v5.90.0): a Terraform Plugin
// Framework resource whose operations are methods on the annotated type.
const frameworkLifecycleSrc = `package s3

// @FrameworkResource("aws_s3_bucket_lifecycle_configuration", name="Bucket Lifecycle Configuration")
func newResourceBucketLifecycleConfiguration(context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceBucketLifecycleConfiguration{}
	r.SetDefaultCreateTimeout(3 * time.Minute)
	return r, nil
}

type resourceBucketLifecycleConfiguration struct {
	framework.ResourceWithConfigure
	framework.WithTimeouts
}

func (r *resourceBucketLifecycleConfiguration) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var data resourceBucketLifecycleConfigurationModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &data)...)
	conn := r.Meta().S3Client(ctx)
	_, err := tfresource.RetryWhenAWSErrCodeEquals(ctx, bucketPropagationTimeout, func() (any, error) {
		return conn.PutBucketLifecycleConfiguration(ctx, &input)
	}, errCodeNoSuchBucket)
	if err != nil {
		response.Diagnostics.AddError("creating", err.Error())
		return
	}
	output, err := findBucketLifecycleConfiguration(ctx, conn, bucket, expectedBucketOwner)
	response.Diagnostics.Append(fwflex.Flatten(ctx, output, &data)...)
}

func (r *resourceBucketLifecycleConfiguration) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	conn := r.Meta().S3Client(ctx)
	output, err := findBucketLifecycleConfiguration(ctx, conn, bucket, expectedBucketOwner)
}

func (r *resourceBucketLifecycleConfiguration) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	conn := r.Meta().S3Client(ctx)
	_, err := conn.PutBucketLifecycleConfiguration(ctx, &input)
}

func (r *resourceBucketLifecycleConfiguration) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	conn := r.Meta().S3Client(ctx)
	_, err := conn.DeleteBucketLifecycle(ctx, &input)
}

func findBucketLifecycleConfiguration(ctx context.Context, conn *s3.Client, bucket, expectedBucketOwner string) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return conn.GetBucketLifecycleConfiguration(ctx, &input)
}
`

// frameworkDirectoryBucketSrc is a second framework resource of the same
// package. Its methods share their names with the lifecycle configuration's,
// so each must resolve against its own receiver type. It also uses the
// annotation spellings the provider has besides the plain one, a method
// helper on the receiver and the plan model's field guards.
const frameworkDirectoryBucketSrc = `package s3

// @FrameworkResource( aws_s3_directory_bucket, name="Directory Bucket")
// @Tags(identifierAttribute="arn")
func newDirectoryBucketResource(context.Context) (resource.ResourceWithConfigure, error) {
	return &directoryBucketResource{}, nil
}

type directoryBucketResource struct {
	framework.ResourceWithConfigure
}

type directoryBucketResourceModel struct {
	framework.WithRegionModel
	Bucket        types.String ` + "`tfsdk:\"bucket\"`" + `
	ForceDestroy  types.Bool   ` + "`tfsdk:\"force_destroy\"`" + `
	Policy        types.String ` + "`tfsdk:\"policy\"`" + `
	Configuration types.List   ` + "`tfsdk:\"configuration\"`" + `
}

func (r *directoryBucketResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var data directoryBucketResourceModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &data)...)
	conn := r.Meta().S3ExpressClient(ctx)
	_, err := conn.CreateBucket(ctx, &input)
	if !data.Policy.IsNull() {
		r.putPolicy(ctx, data)
	}
}

func (r *directoryBucketResource) putPolicy(ctx context.Context, data directoryBucketResourceModel) {
	conn := r.Meta().S3ExpressClient(ctx)
	_, err := conn.PutBucketPolicy(ctx, &input)
}

func (r *directoryBucketResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	conn := r.Meta().S3ExpressClient(ctx)
	_, err := conn.HeadBucket(ctx, &input)
}

func (r *directoryBucketResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var old, new directoryBucketResourceModel
	conn := r.Meta().S3ExpressClient(ctx)
	if !new.Configuration.Equal(old.Configuration) {
		_, err := conn.PutBucketEncryption(ctx, &input)
	}
	if !new.Policy.IsNull() && !new.Policy.IsUnknown() {
		_, err := conn.PutBucketPolicy(ctx, &input)
	}
}

func (r *directoryBucketResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var data directoryBucketResourceModel
	conn := r.Meta().S3ExpressClient(ctx)
	if data.ForceDestroy.ValueBool() {
		_, err := conn.DeleteObjects(ctx, &input)
	}
	_, err := conn.DeleteBucket(ctx, &input)
}
`

// frameworkTagsGenSrc is the service's generated tagging code.
const frameworkTagsGenSrc = `package s3

func listTags(ctx context.Context, conn *s3.Client, identifier string) (tftags.KeyValueTags, error) {
	output, err := conn.ListTagsForResource(ctx, &input)
	return nil, err
}

func updateTags(ctx context.Context, conn *s3.Client, identifier string, oldTagsMap, newTagsMap any) error {
	conn.UntagResource(ctx, &input)
	conn.TagResource(ctx, &input)
	return nil
}
`

func frameworkProvider(t *testing.T) *SourceProvider {
	t.Helper()
	dir := t.TempDir()
	s3Dir := filepath.Join(dir, "internal", "service", "s3")
	if err := os.MkdirAll(s3Dir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"bucket_lifecycle_configuration.go": frameworkLifecycleSrc,
		"directory_bucket.go":               frameworkDirectoryBucketSrc,
		"tags_gen.go":                       frameworkTagsGenSrc,
	} {
		if err := os.WriteFile(filepath.Join(s3Dir, name), []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
	}
	p := NewSourceProviderWithPath(dir)
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	return p
}

func resolveSchema(t *testing.T, p *SourceProvider, tfType string) *iam.Schema {
	t.Helper()
	s, err := p.Resolve(tfType)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSourceProvider_FrameworkResource reads the operations of a
// @FrameworkResource type from the methods of its annotated struct.
func TestSourceProvider_FrameworkResource(t *testing.T) {
	p := frameworkProvider(t)
	s := resolveSchema(t, p, "aws_s3_bucket_lifecycle_configuration")

	want := map[string][]string{
		"create": {"s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration"},
		"read":   {"s3:GetLifecycleConfiguration"},
		"update": {"s3:PutLifecycleConfiguration"},
		"delete": {"s3:PutLifecycleConfiguration"},
	}
	for op, actions := range want {
		got := s.Actions(op)
		for _, a := range actions {
			if !containsAction(got, a) {
				t.Errorf("%s: want %s, got %v", op, a, got)
			}
		}
	}
	// The directory bucket's methods share these names; none of its calls
	// may leak into the lifecycle configuration.
	for _, op := range []string{"create", "read", "update", "delete"} {
		for _, a := range []string{"s3:CreateBucket", "s3:DeleteBucket", "s3:ListBucket"} {
			if containsAction(s.Actions(op), a) {
				t.Errorf("%s: %s leaked from aws_s3_directory_bucket: %v", op, a, s.Actions(op))
			}
		}
	}
	if len(s.Incomplete) > 0 {
		t.Errorf("incomplete operations: %v", s.Incomplete)
	}
}

// TestSourceProvider_FrameworkResourceGates maps the plan model's field
// guards to the attribute the field's tfsdk tag names, and adds the
// transparent tagging actions of a @Tags resource.
func TestSourceProvider_FrameworkResourceGates(t *testing.T) {
	p := frameworkProvider(t)
	s := resolveSchema(t, p, "aws_s3_directory_bucket")

	if !containsAction(s.Actions("create"), "s3express:CreateBucket") {
		t.Fatalf("create: want s3express:CreateBucket, got %v", s.Actions("create"))
	}
	if !containsAction(s.Actions("delete"), "s3express:DeleteBucket") {
		t.Errorf("delete: want s3express:DeleteBucket, got %v", s.Actions("delete"))
	}

	gates := []struct {
		op, action string
		want       iam.Gate
	}{
		{"create", "s3express:CreateBucket", iam.Gate{}},
		// r.putPolicy is a method of the receiver, called under a presence
		// guard on the policy field.
		{"create", "s3express:PutBucketPolicy", iam.Gate{Attribute: "policy"}},
		{"update", "s3express:PutBucketEncryption", iam.Gate{Changed: "configuration"}},
		{"update", "s3express:PutBucketPolicy", iam.Gate{Attribute: "policy"}},
		// A value test is no presence guard: the call stays required.
		{"delete", "s3express:DeleteObjects", iam.Gate{}},
		{"create", "s3:TagResource", iam.Gate{Attribute: "tags"}},
		{"read", "s3:ListTagsForResource", iam.Gate{}},
	}
	for _, g := range gates {
		got := s.Gates(g.op, g.action)
		if len(got) != 1 || got[0] != g.want {
			t.Errorf("%s %s: gates %+v, want [%+v]", g.op, g.action, got, g.want)
		}
	}
}

// TestFrameworkResourceAnnotation reads the resource type from each spelling
// of the annotation the provider uses.
func TestFrameworkResourceAnnotation(t *testing.T) {
	for src, want := range map[string]string{
		`// @FrameworkResource("aws_api_gateway_account", name="Account")`:     "aws_api_gateway_account",
		`// @FrameworkResource( "aws_datazone_domain", name="Domain")`:         "aws_datazone_domain",
		`// @FrameworkResource(aws_verifiedpermissions_policy, name="Policy")`: "aws_verifiedpermissions_policy",
		`// @FrameworkResource("aws_bedrock_guardrail")`:                       "aws_bedrock_guardrail",
		`// @SDKResource("aws_instance", name="Instance")`:                     "",
	} {
		if got := frameworkResourceType(src); got != want {
			t.Errorf("frameworkResourceType(%q) = %q, want %q", src, got, want)
		}
	}
}

// TestSourceProvider_FrameworkResourceEmbeddedBase follows the security group
// rules of internal/service/ec2 (provider v5.90.0): the operations are methods
// of an embedded base type, which calls back into the embedding type through
// an interface field.
func TestSourceProvider_FrameworkResourceEmbeddedBase(t *testing.T) {
	dir := t.TempDir()
	ec2Dir := filepath.Join(dir, "internal", "service", "ec2")
	if err := os.MkdirAll(ec2Dir, 0755); err != nil {
		t.Fatal(err)
	}
	src := `package ec2

// @FrameworkResource("aws_vpc_security_group_ingress_rule", name="Security Group Ingress Rule")
func newSecurityGroupIngressRuleResource(context.Context) (resource.ResourceWithConfigure, error) {
	r := &securityGroupIngressRuleResource{}
	r.securityGroupRule = r
	return r, nil
}

type securityGroupIngressRuleResource struct {
	securityGroupRuleResource
}

func (r *securityGroupIngressRuleResource) create(ctx context.Context, data *securityGroupRuleResourceModel) (string, error) {
	conn := r.Meta().EC2Client(ctx)
	output, err := conn.AuthorizeSecurityGroupIngress(ctx, input)
	return "", err
}

func (r *securityGroupIngressRuleResource) delete(ctx context.Context, data *securityGroupRuleResourceModel) error {
	conn := r.Meta().EC2Client(ctx)
	_, err := conn.RevokeSecurityGroupIngress(ctx, &input)
	return err
}

func (r *securityGroupIngressRuleResource) findByID(ctx context.Context, id string) (*awstypes.SecurityGroupRule, error) {
	conn := r.Meta().EC2Client(ctx)
	return findSecurityGroupRuleByID(ctx, conn, id)
}

type securityGroupRule interface {
	create(context.Context, *securityGroupRuleResourceModel) (string, error)
	delete(context.Context, *securityGroupRuleResourceModel) error
	findByID(context.Context, string) (*awstypes.SecurityGroupRule, error)
}

type securityGroupRuleResource struct {
	securityGroupRule
	framework.ResourceWithConfigure
}

func (r *securityGroupRuleResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	securityGroupRuleID, err := r.securityGroupRule.create(ctx, &data)
}

func (r *securityGroupRuleResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	output, err := r.securityGroupRule.findByID(ctx, data.ID.ValueString())
}

func (r *securityGroupRuleResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	err := r.securityGroupRule.delete(ctx, &data)
}

func findSecurityGroupRuleByID(ctx context.Context, conn *ec2.Client, id string) (*awstypes.SecurityGroupRule, error) {
	output, err := conn.DescribeSecurityGroupRules(ctx, &input)
	return nil, err
}
`
	if err := os.WriteFile(filepath.Join(ec2Dir, "vpc_security_group_ingress_rule.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	p := NewSourceProviderWithPath(dir)
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	s := resolveSchema(t, p, "aws_vpc_security_group_ingress_rule")
	for op, action := range map[string]string{
		"create": "ec2:AuthorizeSecurityGroupIngress",
		"read":   "ec2:DescribeSecurityGroupRules",
		"delete": "ec2:RevokeSecurityGroupIngress",
	} {
		if !containsAction(s.Actions(op), action) {
			t.Errorf("%s: want %s, got %v", op, action, s.Actions(op))
		}
	}
}

// TestSourceProvider_FrameworkResourceWithoutCalls leaves a framework resource
// whose methods make no call the parser reads to the next provider, rather
// than resolving it to no permissions. aws_simpledb_domain uses the v1 SDK.
func TestSourceProvider_FrameworkResourceWithoutCalls(t *testing.T) {
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "internal", "service", "simpledb")
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatal(err)
	}
	src := `package simpledb

// @FrameworkResource("aws_simpledb_domain", name="Domain")
func newDomainResource(context.Context) (resource.ResourceWithConfigure, error) {
	return &domainResource{}, nil
}

type domainResource struct {
	framework.ResourceWithConfigure
}

func (r *domainResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	conn := simpleDBConn(ctx, r.Meta())
	_, err := conn.CreateDomainWithContext(ctx, input)
}
`
	if err := os.WriteFile(filepath.Join(svcDir, "domain.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	p := NewSourceProviderWithPath(dir)
	if _, err := p.Resolve("aws_simpledb_domain"); err == nil {
		t.Error("aws_simpledb_domain resolved from source with no permissions")
	}
}
