package provideraws

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// bestEffortOf returns whether the parse found action in op and, if so,
// whether it marked the action best-effort.
func bestEffortOf(actions map[string][]ExtractedAction, op, action string) (found, bestEffort bool) {
	for _, ea := range actions[op] {
		if ea.Action == action {
			return true, ea.BestEffort
		}
	}
	return false, false
}

// discardedErrorsSrc holds one function per way the provider drops the error
// of a call. Each is bound to its own operation through the naming convention.
const discardedErrorsSrc = `package widget

// Blank error result: the call's failure is ignored.
func resourceWidgetCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).WidgetClient(ctx)

	output, err := conn.CreateWidget(ctx, input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Widget: %s", err)
	}

	_, _ = conn.PutWidgetNote(ctx, nil)
	out, _ := conn.GetWidgetHint(ctx, nil)
	conn.TagWidget(ctx, nil)
	_ = putWidgetBadge(ctx, conn)
	putWidgetLabel(ctx, conn)
	logWidget(ctx, conn)

	if v, err := findWidgetQuota(ctx, conn); err == nil {
		d.Set("quota", v)
	}

	return diags
}

// The error is checked, then swallowed: the function returns no error.
func resourceWidgetRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).WidgetClient(ctx)

	widget, err := conn.DescribeWidget(ctx, nil)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Widget (%s): %s", d.Id(), err)
	}

	policy, err := conn.GetWidgetPolicy(ctx, nil)
	if err != nil {
		return diags
	}

	d.Set("color", widgetColor(ctx, conn))
	return diags
}

func widgetColor(ctx context.Context, conn *widget.Client) string {
	out, err := conn.GetWidgetColor(ctx, nil)
	if err != nil {
		return ""
	}
	return out.Color
}

func putWidgetBadge(ctx context.Context, conn *widget.Client) error {
	_, err := conn.PutWidgetBadge(ctx, nil)
	return err
}

func putWidgetLabel(ctx context.Context, conn *widget.Client) error {
	_, err := conn.PutWidgetLabel(ctx, nil)
	return err
}

// logWidget returns nothing, so the parse cannot tell whether a failure
// reaches the apply. Its call stays required.
func logWidget(ctx context.Context, conn *widget.Client) {
	out, err := conn.ListWidgetLogs(ctx, nil)
	record(out, err)
}

func findWidgetQuota(ctx context.Context, conn *widget.Client) (int, error) {
	out, err := conn.GetWidgetQuota(ctx, nil)
	if err != nil {
		return 0, err
	}
	return out.Quota, nil
}
`

// TestParse_DiscardedErrorIsBestEffort covers the call sites whose error the
// provider discards. Such a call cannot fail the apply, so a policy that
// denies it still lets the apply succeed.
func TestParse_DiscardedErrorIsBestEffort(t *testing.T) {
	actions, err := ParseResourceFileStructured(discardedErrorsSrc, "aws_widget", "Widget")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		op, action string
		bestEffort bool
	}{
		{"create", "widget:CreateWidget", false},
		{"create", "widget:PutWidgetNote", true},   // _, _ = conn.X()
		{"create", "widget:GetWidgetHint", true},   // out, _ := conn.X()
		{"create", "widget:TagWidget", true},       // conn.X() as a statement
		{"create", "widget:PutWidgetBadge", true},  // _ = helper()
		{"create", "widget:PutWidgetLabel", true},  // helper() returning error, as a statement
		{"create", "widget:ListWidgetLogs", false}, // helper() returning nothing
		{"create", "widget:GetWidgetQuota", true},  // if v, err := helper(); err == nil
		{"read", "widget:DescribeWidget", false},   // error returned
		{"read", "widget:GetWidgetPolicy", true},   // if err != nil { return diags }
		{"read", "widget:GetWidgetColor", true},    // if err != nil { return "" }
	}
	for _, c := range cases {
		found, be := bestEffortOf(actions, c.op, c.action)
		if !found {
			t.Errorf("%s: %s not found in %v", c.op, c.action, actionNames(actions, c.op))
			continue
		}
		if be != c.bestEffort {
			t.Errorf("%s: %s BestEffort = %v, want %v", c.op, c.action, be, c.bestEffort)
		}
	}
}

// roleCreateSrc is trimmed from resourceRoleCreate in
// internal/service/iam/role.go (provider v5.90.0). When adding the inline
// policies fails, the create deletes the role it made and returns the error.
const roleCreateSrc = `package iam

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IAMClient(ctx)

	output, err := retryCreateRole(ctx, conn, input)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating IAM Role (%s): %s", name, err)
	}

	roleName := aws.ToString(output.Role.RoleName)

	if v, ok := d.GetOk("inline_policy"); ok && v.(*schema.Set).Len() > 0 {
		policies := expandRoleInlinePolicies(roleName, v.(*schema.Set).List())
		if err := addRoleInlinePolicies(ctx, conn, policies); err != nil {
			derr := deleteRole(ctx, conn, roleName, true, true, false)
			if derr != nil {
				return sdkdiag.AppendErrorf(diags, "creating IAM role (%s), inline policy failed (%s), deleting role: %s", d.Id(), err, derr)
			}

			return sdkdiag.AppendErrorf(diags, "creating IAM Role (%s): %s", name, err)
		}
	}

	return diags
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IAMClient(ctx)

	if err := deleteRole(ctx, conn, d.Id(), true, true, true); err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting IAM Role (%s): %s", d.Id(), err)
	}

	return diags
}

func retryCreateRole(ctx context.Context, conn *iam.Client, input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	return conn.CreateRole(ctx, input)
}

func addRoleInlinePolicies(ctx context.Context, conn *iam.Client, policies []*iam.PutRolePolicyInput) error {
	for _, policy := range policies {
		if _, err := conn.PutRolePolicy(ctx, policy); err != nil {
			return err
		}
	}
	return nil
}

func deleteRole(ctx context.Context, conn *iam.Client, roleName string, forceDetach, hasInline, hasManaged bool) error {
	_, err := conn.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(roleName)})
	return err
}
`

// TestParse_ErrorPathCleanupIsBestEffort covers a cleanup made inside the
// branch that handles a failed call. It runs only when the apply is already
// failing, so a successful apply does not need it.
func TestParse_ErrorPathCleanupIsBestEffort(t *testing.T) {
	actions, err := ParseResourceFileStructured(roleCreateSrc, "aws_iam_role", "Role")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		op, action string
		bestEffort bool
	}{
		{"create", "iam:CreateRole", false},
		{"create", "iam:PutRolePolicy", false},
		{"create", "iam:DeleteRole", true},
		{"delete", "iam:DeleteRole", false},
	}
	for _, c := range cases {
		found, be := bestEffortOf(actions, c.op, c.action)
		if !found {
			t.Errorf("%s: %s not found in %v", c.op, c.action, actionNames(actions, c.op))
			continue
		}
		if be != c.bestEffort {
			t.Errorf("%s: %s BestEffort = %v, want %v", c.op, c.action, be, c.bestEffort)
		}
	}
}

// TestParse_ErrorBranchThatRecoversIsRequired covers branches on err != nil
// that the cleanup rule must leave alone: one that tells errors apart and
// creates what was not found, and a plain return after the real call.
func TestParse_ErrorBranchThatRecoversIsRequired(t *testing.T) {
	src := `package widget

func resourceWidgetCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).WidgetClient(ctx)

	_, err := conn.GetWidgetRegistry(ctx, nil)
	if err != nil {
		if !tfresource.NotFound(err) {
			return sdkdiag.AppendErrorf(diags, "reading registry: %s", err)
		}
		if _, err := conn.CreateWidgetRegistry(ctx, nil); err != nil {
			return sdkdiag.AppendErrorf(diags, "creating registry: %s", err)
		}
		return diags
	}

	return diags
}
`
	actions, err := ParseResourceFileStructured(src, "aws_widget", "Widget")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"widget:GetWidgetRegistry", "widget:CreateWidgetRegistry"} {
		found, be := bestEffortOf(actions, "create", action)
		if !found || be {
			t.Errorf("%s: found=%v BestEffort=%v, want found and required", action, found, be)
		}
	}
}

// TestParse_RequiredPathWinsOverBestEffort checks that an action reached both
// through a discarded call and through a checked one keeps both paths: the
// best-effort one with no gate, and the required one gated on note.
func TestParse_RequiredPathWinsOverBestEffort(t *testing.T) {
	src := `package widget

func resourceWidgetCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).WidgetClient(ctx)

	conn.PutWidgetNote(ctx, nil)

	if v, ok := d.GetOk("note"); ok {
		if _, err := conn.PutWidgetNote(ctx, nil); err != nil {
			return sdkdiag.AppendErrorf(diags, "note: %s", err)
		}
	}
	return diags
}
`
	actions, err := ParseResourceFileStructured(src, "aws_widget", "Widget")
	if err != nil {
		t.Fatal(err)
	}
	for _, ea := range actions["create"] {
		if ea.Action != "widget:PutWidgetNote" {
			continue
		}
		want := []iam.Gate{{BestEffort: true}, {Attribute: "note"}}
		if !reflect.DeepEqual(ea.Gates, want) {
			t.Errorf("PutWidgetNote = %+v, want gates %+v", ea, want)
		}
		return
	}
	t.Fatalf("PutWidgetNote not found in %v", actionNames(actions, "create"))
}

// TestSourceProvider_DynamoDBDefaultKeyLookupIsBestEffort is trimmed from
// clearSSEDefaultKey in internal/service/dynamodb/table.go and
// findDefaultKeyARNForService in internal/service/kms (provider v5.90.0). The
// table read looks up the account's default DynamoDB KMS key and keeps the
// state as it is when the lookup fails, so kms:DescribeKey must not be
// required.
func TestSourceProvider_DynamoDBDefaultKeyLookupIsBestEffort(t *testing.T) {
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
	write("dynamodb/table.go", `package dynamodb

import (
	"github.com/hashicorp/terraform-provider-aws/internal/service/kms"
)

// @SDKResource("aws_dynamodb_table", name="Table")
func resourceTable() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceTableCreate,
		ReadWithoutTimeout:   resourceTableRead,
	}
}

func resourceTableCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).DynamoDBClient(ctx)
	if _, err := conn.CreateTable(ctx, input); err != nil {
		return sdkdiag.AppendErrorf(diags, "creating DynamoDB Table: %s", err)
	}
	return append(diags, resourceTableRead(ctx, d, meta)...)
}

func resourceTableRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).DynamoDBClient(ctx)
	table, err := conn.DescribeTable(ctx, nil)
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading DynamoDB Table (%s): %s", d.Id(), err)
	}
	sse := flattenTableServerSideEncryption(table.SSEDescription)
	sse = clearSSEDefaultKey(ctx, meta.(*conns.AWSClient), sse)
	replicas = clearReplicaDefaultKeys(ctx, meta.(*conns.AWSClient), replicas)
	return diags
}

func clearSSEDefaultKey(ctx context.Context, client *conns.AWSClient, sseList []interface{}) []interface{} {
	if len(sseList) == 0 {
		return sseList
	}
	sse := sseList[0].(map[string]interface{})
	dk, err := kms.FindDefaultKeyARNForService(ctx, client.KMSClient(ctx), "dynamodb", client.Region(ctx))
	if err != nil {
		return sseList
	}
	if v, ok := sse[names.AttrKMSKeyARN].(string); ok && v == dk {
		sse[names.AttrKMSKeyARN] = ""
		return []interface{}{sse}
	}
	return sseList
}

func clearReplicaDefaultKeys(ctx context.Context, client *conns.AWSClient, replicas []interface{}) []interface{} {
	for i, replicaRaw := range replicas {
		dk, err := kms.FindDefaultKeyARNForService(ctx, client.KMSClient(ctx), "dynamodb", replica["region_name"].(string))
		if err != nil {
			continue
		}
		replicas[i] = replica
	}
	return replicas
}
`)
	write("kms/exports.go", `package kms

var (
	FindDefaultKeyARNForService = findDefaultKeyARNForService
)
`)
	write("kms/key.go", `package kms

func findDefaultKeyARNForService(ctx context.Context, conn *kms.Client, service, region string) (string, error) {
	keyID := fmt.Sprintf("alias/aws/%s", service)
	key, err := findKeyByID(ctx, conn, keyID)
	if err != nil {
		return "", fmt.Errorf("reading KMS Key (%s): %s", keyID, err)
	}
	return aws.ToString(key.Arn), nil
}

func findKeyByID(ctx context.Context, conn *kms.Client, keyID string) (*awstypes.KeyMetadata, error) {
	output, err := conn.DescribeKey(ctx, nil)
	if err != nil {
		return nil, err
	}
	return output.KeyMetadata, nil
}
`)

	schema, err := NewSourceProviderWithPath(dir).Resolve("aws_dynamodb_table")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"create", "read"} {
		if !containsString(schema.Actions(op), "kms:DescribeKey") {
			t.Errorf("%s = %v, want kms:DescribeKey listed", op, schema.Actions(op))
		}
		if gates := schema.Gates(op, "kms:DescribeKey"); len(gates) != 1 || !gates[0].BestEffort {
			t.Errorf("%s: kms:DescribeKey not best-effort: %+v", op, gates)
		}
		if gates := schema.Gates(op, "dynamodb:DescribeTable"); len(gates) != 1 || gates[0].BestEffort {
			t.Errorf("%s: dynamodb:DescribeTable marked best-effort", op)
		}
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
