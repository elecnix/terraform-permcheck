package provideraws

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// actionNames returns the sorted action names of one operation.
func actionNames(actions map[string][]ExtractedAction, op string) []string {
	var out []string
	for _, ea := range actions[op] {
		out = append(out, ea.Action)
	}
	sort.Strings(out)
	return out
}

func hasAction(actions map[string][]ExtractedAction, op, action string) bool {
	for _, ea := range actions[op] {
		if ea.Action == action {
			return true
		}
	}
	return false
}

// bucketCreateSrc is trimmed from resourceBucketCreate in
// internal/service/s3/bucket.go (provider v5.90.0). Every SDK call it makes
// sits in a retry closure or in an if-statement's init, and the create ends
// by returning the update function.
const bucketCreateSrc = `package s3

// @SDKResource("aws_s3_bucket", name="Bucket")
func resourceBucket() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceBucketCreate,
		ReadWithoutTimeout:   resourceBucketRead,
		UpdateWithoutTimeout: resourceBucketUpdate,
		DeleteWithoutTimeout: resourceBucketDelete,
	}
}

func resourceBucketCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).S3Client(ctx)

	if region == endpoints.UsEast1RegionID {
		if _, err := findBucket(ctx, conn, bucket); err == nil {
			return sdkdiag.AppendErrorf(diags, "exists")
		}
	}

	_, err := tfresource.RetryWhenAWSErrCodeEquals(ctx, d.Timeout(schema.TimeoutCreate), func() (interface{}, error) {
		return conn.CreateBucket(ctx, input)
	}, errCodeOperationAborted)

	_, err = tfresource.RetryWhenNotFound(ctx, d.Timeout(schema.TimeoutCreate), func() (interface{}, error) {
		return findBucket(ctx, conn, d.Id())
	})

	if err := bucketCreateTags(ctx, conn, d.Id(), getTagsIn(ctx)); err != nil {
		return sdkdiag.AppendErrorf(diags, "tags")
	}

	return append(diags, resourceBucketUpdate(ctx, d, meta)...)
}

func resourceBucketRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	_, err := findBucket(ctx, conn, d.Id())
	policy, err := retryWhenNoSuchBucketError(ctx, d.Timeout(schema.TimeoutRead), func() (string, error) {
		return findBucketPolicy(ctx, conn, d.Id())
	})
	return nil
}

func resourceBucketUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	if d.HasChange("policy") {
		_, err := tfresource.RetryWhenAWSErrCodeEquals(ctx, d.Timeout(schema.TimeoutUpdate), func() (interface{}, error) {
			return conn.PutBucketPolicy(ctx, input)
		}, errCodeNoSuchBucket)
	}
	return append(diags, resourceBucketRead(ctx, d, meta)...)
}

func resourceBucketDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	_, err := conn.DeleteBucket(ctx, &s3.DeleteBucketInput{})
	if n, err := emptyBucket(ctx, conn, d.Id(), false); err != nil {
		return nil
	}
	return resourceBucketDelete(ctx, d, meta)
}

func findBucket(ctx context.Context, conn *s3.Client, bucket string, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	output, err := conn.HeadBucket(ctx, &input, optFns...)
	return output, err
}

func bucketCreateTags(ctx context.Context, conn *s3.Client, identifier string, tags []awstypes.Tag) error {
	_, err := conn.PutBucketTagging(ctx, nil)
	return err
}

func retryWhenNoSuchBucketError[T any](ctx context.Context, timeout time.Duration, f func() (T, error)) (T, error) {
	outputRaw, err := tfresource.RetryWhenAWSErrCodeEquals(ctx, timeout, func() (interface{}, error) {
		return f()
	}, errCodeNoSuchBucket)
	return outputRaw.(T), err
}
`

// bucketPolicySrc is a second file of the same package. The bucket read
// calls findBucketPolicy, which lives here and not in bucket.go.
const bucketPolicySrc = `package s3

func findBucketPolicy(ctx context.Context, conn *s3.Client, bucket string) (string, error) {
	output, err := conn.GetBucketPolicy(ctx, nil)
	return aws.ToString(output.Policy), err
}

func emptyBucket(ctx context.Context, conn *s3.Client, bucket string, force bool) (int64, error) {
	pages := s3.NewListObjectVersionsPaginator(conn, &s3.ListObjectVersionsInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		_, err = conn.DeleteObjects(ctx, nil)
	}
	return 0, nil
}
`

func TestParse_S3BucketCreateReachesClosuresAndIfInit(t *testing.T) {
	actions, err := ParseResourceFileStructured(bucketCreateSrc, "aws_s3_bucket", "Bucket")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"s3:CreateBucket", "s3:HeadBucket", "s3:PutBucketTagging", "s3:PutBucketPolicy"} {
		if !hasAction(actions, "create", want) {
			t.Errorf("create is missing %s; got %v", want, actionNames(actions, "create"))
		}
	}
	if !hasAction(actions, "delete", "s3:DeleteBucket") {
		t.Errorf("delete is missing s3:DeleteBucket; got %v", actionNames(actions, "delete"))
	}
}

func TestParsePackage_FollowsHelpersInOtherFiles(t *testing.T) {
	pkg, err := ParsePackage(map[string]string{
		"bucket.go":        bucketCreateSrc,
		"bucket_policy.go": bucketPolicySrc,
	})
	if err != nil {
		t.Fatal(err)
	}
	actions, _ := pkg.ResourceActions("bucket.go", "Bucket")

	for op, want := range map[string]string{
		"read":   "s3:GetBucketPolicy",
		"create": "s3:GetBucketPolicy", // create → update → read
		"delete": "s3:ListObjectVersions",
	} {
		if !hasAction(actions, op, want) {
			t.Errorf("%s is missing %s; got %v", op, want, actionNames(actions, op))
		}
	}
	if !hasAction(actions, "delete", "s3:DeleteObjects") {
		t.Errorf("delete is missing s3:DeleteObjects; got %v", actionNames(actions, "delete"))
	}
}

// TestParse_Paginator covers NewXxxPaginator(conn, input): the paginator calls
// the Xxx operation, so it needs service:Xxx. Trimmed from findLogGroups in
// internal/service/logs/group.go.
func TestParse_Paginator(t *testing.T) {
	src := `package logs

func resourceGroupRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).LogsClient(ctx)
	lg, err := findLogGroupByName(ctx, conn, d.Id())
	return nil
}

func resourceGroupCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).LogsClient(ctx)
	_, err := conn.CreateLogGroup(ctx, input)
	if v, ok := d.GetOk("retention_in_days"); ok {
		_, err := tfresource.RetryWhenIsAErrorMessageContains[*awstypes.InvalidParameterException](ctx, propagationTimeout, func() (interface{}, error) {
			return conn.PutRetentionPolicy(ctx, input)
		}, "AWS Logs Delivery")
	}
	return append(diags, resourceGroupRead(ctx, d, meta)...)
}

func resourceGroupDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).LogsClient(ctx)
	_, err := tfresource.RetryWhenIsAErrorMessageContains[*awstypes.OperationAbortedException](ctx, 1*time.Minute, func() (interface{}, error) {
		return conn.DeleteLogGroup(ctx, &cloudwatchlogs.DeleteLogGroupInput{})
	}, "try again")
	return nil
}

func findLogGroupByName(ctx context.Context, conn *cloudwatchlogs.Client, name string) (*awstypes.LogGroup, error) {
	return findLogGroup(ctx, conn, &cloudwatchlogs.DescribeLogGroupsInput{}, nil)
}

func findLogGroup(ctx context.Context, conn *cloudwatchlogs.Client, input *cloudwatchlogs.DescribeLogGroupsInput, filter tfslices.Predicate[*awstypes.LogGroup]) (*awstypes.LogGroup, error) {
	output, err := findLogGroups(ctx, conn, input, filter)
	return tfresource.AssertSingleValueResult(output)
}

func findLogGroups(ctx context.Context, conn *cloudwatchlogs.Client, input *cloudwatchlogs.DescribeLogGroupsInput, filter tfslices.Predicate[*awstypes.LogGroup]) ([]awstypes.LogGroup, error) {
	var output []awstypes.LogGroup
	pages := cloudwatchlogs.NewDescribeLogGroupsPaginator(conn, input)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
	}
	return output, nil
}
`
	actions, err := ParseResourceFileStructured(src, "aws_cloudwatch_log_group", "Group")
	if err != nil {
		t.Fatal(err)
	}
	for op, wants := range map[string][]string{
		"read":   {"logs:DescribeLogGroups"},
		"create": {"logs:CreateLogGroup", "logs:PutRetentionPolicy", "logs:DescribeLogGroups"},
		"delete": {"logs:DeleteLogGroup"},
	} {
		for _, want := range wants {
			if !hasAction(actions, op, want) {
				t.Errorf("%s is missing %s; got %v", op, want, actionNames(actions, op))
			}
		}
	}
	for _, ea := range actions["create"] {
		if ea.Action == "logs:PutRetentionPolicy" && ea.Condition != "retention_in_days" {
			t.Errorf("PutRetentionPolicy should stay gated on retention_in_days, got %+v", ea)
		}
	}
}

// TestParse_ClientShapes covers clients that are not a single conn variable:
// a second client in the same function, a client accessor called inline, and
// a typed client parameter with an unusual name.
func TestParse_ClientShapes(t *testing.T) {
	src := `package ec2

func resourceThingCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).EC2Client(ctx)
	kmsConn := meta.(*conns.AWSClient).KMSClient(ctx)
	conn.CreateThing(ctx, nil)
	kmsConn.CreateGrant(ctx, nil)
	conn.ModifyThing(ctx, nil)
	meta.(*conns.AWSClient).IAMClient(ctx).PassRole(ctx, nil)
	describeThing(ctx, conn)
	return nil
}

func resourceThingDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return deleteThing(ctx, meta.(*conns.AWSClient))
}

func describeThing(ctx context.Context, ec2conn *ec2.Client) {
	ec2conn.DescribeThings(ctx, nil)
}

func deleteThing(ctx context.Context, awsClient *conns.AWSClient) diag.Diagnostics {
	awsClient.EC2Client(ctx).DeleteThing(ctx, nil)
	return nil
}
`
	actions, err := ParseResourceFileStructured(src, "aws_thing", "Thing")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ec2:CreateThing", "ec2:DescribeThings", "ec2:ModifyThing", "iam:PassRole", "kms:CreateGrant"}
	if got := actionNames(actions, "create"); !equalStrings(got, want) {
		t.Errorf("create = %v, want %v", got, want)
	}
	if got := actionNames(actions, "delete"); !equalStrings(got, []string{"ec2:DeleteThing"}) {
		t.Errorf("delete = %v, want [ec2:DeleteThing]", got)
	}
}

// TestParsePackage_SchemaBindsOperations reads the operations from the
// schema.Resource literal, so a CRUD function whose name does not follow the
// resource<Name><Op> pattern still maps to its operation, and a delete bound
// to a no-op is declared without a function.
func TestParsePackage_SchemaBindsOperations(t *testing.T) {
	src := `package thing

// @SDKResource("aws_thing", name="Thing")
func resourceThing() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceThingCreate,
		ReadWithoutTimeout:   readThing,
		DeleteWithoutTimeout: schema.NoopContext,
		Schema: map[string]*schema.Schema{
			"nested": {Elem: &schema.Resource{Schema: map[string]*schema.Schema{}}},
		},
	}
}

func resourceThingCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ThingClient(ctx)
	conn.CreateThing(ctx, nil)
	return nil
}

func readThing(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).ThingClient(ctx)
	conn.GetThing(ctx, nil)
	return nil
}
`
	pkg, err := ParsePackage(map[string]string{"thing.go": src})
	if err != nil {
		t.Fatal(err)
	}
	actions, bound := pkg.ResourceActions("thing.go", "Thing")
	if got := actionNames(actions, "read"); !equalStrings(got, []string{"thing:GetThing"}) {
		t.Errorf("read = %v, want [thing:GetThing]", got)
	}
	if fn, ok := bound["delete"]; !ok || fn != "" {
		t.Errorf("delete binding = %q, %v; want a declared no-op", fn, ok)
	}
	if fn := bound["create"]; fn != "resourceThingCreate" {
		t.Errorf("create binding = %q, want resourceThingCreate", fn)
	}
	if _, ok := bound["update"]; ok {
		t.Errorf("update should not be bound")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestParse_FunctionValues covers a package function used as a value and
// called later, trimmed from resourceRouteRead in internal/service/ec2/vpc_route.go.
// A method or an imported package that shares a name with a plain function
// must not count as a reference to it.
func TestParse_FunctionValues(t *testing.T) {
	src := `package ec2

func resourceRouteRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).EC2Client(ctx)
	var routeFinder routeFinder
	switch destinationAttributeKey {
	case routeDestinationCIDRBlock:
		routeFinder = findRouteByIPv4Destination
	}
	outputRaw, err := tfresource.RetryWhenNewResourceNotFound(ctx, ec2PropagationTimeout, func() (interface{}, error) {
		return routeFinder(ctx, conn, routeTableID, destination)
	}, d.IsNewResource())
	d.SetId(create.ID(routeTableID))
	return nil
}

func findRouteByIPv4Destination(ctx context.Context, conn *ec2.Client, routeTableID, destination string) (*awstypes.Route, error) {
	conn.DescribeRouteTables(ctx, nil)
	return nil, nil
}

func (r *securityGroupEgressRuleResource) create(ctx context.Context, conn *ec2.Client) {
	conn.AuthorizeSecurityGroupEgress(ctx, nil)
}
`
	actions, err := ParseResourceFileStructured(src, "aws_route", "Route")
	if err != nil {
		t.Fatal(err)
	}
	if got := actionNames(actions, "read"); !equalStrings(got, []string{"ec2:DescribeRouteTables"}) {
		t.Errorf("read = %v, want [ec2:DescribeRouteTables]", got)
	}
}

// TestParsePackage_FactoryAndImporterBindings covers an operation bound to the
// result of a factory call, trimmed from internal/service/glue/resource_policy.go,
// and an importer bound in a schema.ResourceImporter literal.
func TestParsePackage_FactoryAndImporterBindings(t *testing.T) {
	src := `package glue

// @SDKResource("aws_glue_resource_policy", name="Resource Policy")
func ResourceResourcePolicy() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceResourcePolicyPut(awstypes.ExistConditionNotExist),
		ReadWithoutTimeout:   resourceResourcePolicyRead,
		Importer: &schema.ResourceImporter{
			StateContext: importPolicy,
		},
	}
}

func resourceResourcePolicyPut(condition awstypes.ExistCondition) func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		conn := meta.(*conns.AWSClient).GlueClient(ctx)
		_, err := conn.PutResourcePolicy(ctx, input)
		return nil
	}
}

func resourceResourcePolicyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).GlueClient(ctx)
	conn.GetResourcePolicy(ctx, nil)
	return nil
}

func importPolicy(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	meta.(*conns.AWSClient).GlueClient(ctx).GetResourcePolicy(ctx, nil)
	return nil, nil
}
`
	pkg, err := ParsePackage(map[string]string{"resource_policy.go": src})
	if err != nil {
		t.Fatal(err)
	}
	actions, _ := pkg.ResourceActions("resource_policy.go", "ResourcePolicy")
	if got := actionNames(actions, "create"); !equalStrings(got, []string{"glue:PutResourcePolicy"}) {
		t.Errorf("create = %v, want [glue:PutResourcePolicy]", got)
	}
	if got := actionNames(actions, "import"); !equalStrings(got, []string{"glue:GetResourcePolicy"}) {
		t.Errorf("import = %v, want [glue:GetResourcePolicy]", got)
	}
}

// TestParse_ClientsThatAreNotAPICalls covers the client methods and
// constructors that make no API call of their own, and the S3 uploader that
// makes PutObject calls with the client it is handed.
func TestParse_ClientsThatAreNotAPICalls(t *testing.T) {
	src := `package s3

func resourceObjectCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)
	presign := s3.NewPresignClient(conn)
	_ = conn.Options().Region
	uploader := manager.NewUploader(conn)
	_, err := uploader.Upload(ctx, input)
	return nil
}
`
	actions, err := ParseResourceFileStructured(src, "aws_s3_object", "Object")
	if err != nil {
		t.Fatal(err)
	}
	if got := actionNames(actions, "create"); !equalStrings(got, []string{"s3:PutObject"}) {
		t.Errorf("create = %v, want [s3:PutObject]", got)
	}
}

// TestSourceProvider_FollowsOtherServicePackages covers a call into another
// service package through its exports.go alias, trimmed from
// internal/service/ram/sharing_with_organization.go and internal/service/iam.
func TestSourceProvider_FollowsOtherServicePackages(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(dir, "internal", "service", rel)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("ram/sharing_with_organization.go", `package ram

import (
	tfiam "github.com/hashicorp/terraform-provider-aws/internal/service/iam"
)

// @SDKResource("aws_ram_sharing_with_organization", name="Sharing With Organization")
func resourceSharingWithOrganization() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceSharingWithOrganizationCreate,
		ReadWithoutTimeout:   resourceSharingWithOrganizationRead,
	}
}

func resourceSharingWithOrganizationCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).RAMClient(ctx)
	conn.EnableSharingWithAwsOrganization(ctx, nil)
	return append(diags, resourceSharingWithOrganizationRead(ctx, d, meta)...)
}

func resourceSharingWithOrganizationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	err := findSharingWithOrganization(ctx, meta.(*conns.AWSClient))
	return nil
}

func findSharingWithOrganization(ctx context.Context, awsClient *conns.AWSClient) error {
	_, err := tfiam.FindRoleByName(ctx, awsClient.IAMClient(ctx), sharingWithOrganizationRoleName)
	return err
}
`)
	write("iam/exports.go", `package iam

var (
	FindRoleByName = findRoleByName
)
`)
	write("iam/role.go", `package iam

func findRoleByName(ctx context.Context, conn *iam.Client, name string) (*awstypes.Role, error) {
	output, err := conn.GetRole(ctx, nil)
	return output.Role, err
}
`)

	schema, err := NewSourceProviderWithPath(dir).Resolve("aws_ram_sharing_with_organization")
	if err != nil {
		t.Fatal(err)
	}
	if got := schema.Permissions["read"]; !equalStrings(got, []string{"iam:GetRole"}) {
		t.Errorf("read = %v, want [iam:GetRole]", got)
	}
	if len(schema.Incomplete) != 0 {
		t.Errorf("Incomplete = %v, want none", schema.Incomplete)
	}
}
