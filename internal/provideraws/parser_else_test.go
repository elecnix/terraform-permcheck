package provideraws

import (
	"reflect"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// gateCase is one action and the gates it must carry.
type gateCase struct {
	action string
	want   []iam.Gate
}

// presence, valued and changed build the gate of one path.
func presence(attr string) iam.Gate { return iam.Gate{Attribute: attr} }
func valued(attr string) iam.Gate   { return iam.Gate{Attribute: attr, ValueGuarded: true} }
func changed(attr string) iam.Gate  { return iam.Gate{Changed: attr} }

// always is the gate of a path that tests no attribute.
var always = []iam.Gate{{}}

// checkGates compares the gates of each action of op with the cases.
func checkGates(t *testing.T, actions map[string][]ExtractedAction, op string, cases []gateCase) {
	t.Helper()
	got := map[string][]iam.Gate{}
	for _, ea := range actions[op] {
		got[ea.Action] = ea.paths()
	}
	for _, c := range cases {
		gates, ok := got[c.action]
		if !ok {
			t.Errorf("%s: %s not extracted, got %v", op, c.action, actions[op])
			continue
		}
		if !reflect.DeepEqual(gates, c.want) {
			t.Errorf("%s: %s gates = %+v, want %+v", op, c.action, gates, c.want)
		}
	}
}

// parseCreate parses a create function body of an SDK resource.
func parseCreate(t *testing.T, body string) map[string][]ExtractedAction {
	t.Helper()
	src := "package x\n\nfunc resourceThingCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {\n" +
		"\tconn := meta.(*conns.AWSClient).DynamoDBClient(ctx)\n" + body + "\n\treturn nil\n}\n"
	actions, err := ParseResourceFileStructured(src, "aws_thing", "Thing")
	if err != nil {
		t.Fatal(err)
	}
	return actions
}

// TestElseBranch_OrganizationsAccount is trimmed from
// internal/service/organizations/account.go (provider v5.90.0). The else
// branch runs when create_govcloud is false, so CreateAccount must not
// inherit the create_govcloud gate.
func TestElseBranch_OrganizationsAccount(t *testing.T) {
	actions := parseCreate(t, `
	if d.Get("create_govcloud").(bool) {
		outputRaw, err := tfresource.RetryWhenIsA[*awstypes.FinalizingOrganizationException](ctx, organizationFinalizationTimeout,
			func() (interface{}, error) {
				return conn.CreateGovCloudAccount(ctx, input)
			})
		if err != nil {
			return sdkdiag.AppendErrorf(diags, "creating: %s", err)
		}
	} else {
		outputRaw, err := tfresource.RetryWhenIsA[*awstypes.FinalizingOrganizationException](ctx, organizationFinalizationTimeout,
			func() (interface{}, error) {
				return conn.CreateAccount(ctx, input)
			})
		if err != nil {
			return sdkdiag.AppendErrorf(diags, "creating: %s", err)
		}
	}`)
	checkGates(t, actions, "create", []gateCase{
		{"dynamodb:CreateGovCloudAccount", []iam.Gate{presence("create_govcloud")}},
		{"dynamodb:CreateAccount", always},
	})
}

// TestElseBranch_DynamoDBTable is trimmed from
// internal/service/dynamodb/table.go (provider v5.90.0). The final else
// creates a plain table, which needs neither import_table nor a restore
// source. The restore branch runs when either restore source is set.
func TestElseBranch_DynamoDBTable(t *testing.T) {
	actions := parseCreate(t, `
	sourceName, nameOk := d.GetOk("restore_source_name")
	sourceArn, arnOk := d.GetOk("restore_source_table_arn")

	if nameOk || arnOk {
		_, err := tfresource.RetryWhen(ctx, createTableTimeout, func() (interface{}, error) {
			return conn.RestoreTableToPointInTime(ctx, input)
		}, retryable)
		if err != nil {
			return create.AppendDiagError(diags, names.DynamoDB, create.ErrActionCreating, resNameTable, tableName, err)
		}
	} else if vit, ok := d.GetOk("import_table"); ok && len(vit.([]interface{})) > 0 && vit.([]interface{})[0] != nil {
		importTableOutput, err := tfresource.RetryWhen(ctx, createTableTimeout, func() (interface{}, error) {
			return conn.ImportTable(ctx, input)
		}, retryable)
		if err != nil {
			return create.AppendDiagError(diags, names.DynamoDB, create.ErrActionCreating, resNameTable, tableName, err)
		}
	} else {
		_, err := tfresource.RetryWhen(ctx, createTableTimeout, func() (interface{}, error) {
			return conn.CreateTable(ctx, input)
		}, retryable)
		if err != nil {
			return create.AppendDiagError(diags, names.DynamoDB, create.ErrActionCreating, resNameTable, tableName, err)
		}
	}`)
	checkGates(t, actions, "create", []gateCase{
		{"dynamodb:RestoreTableToPointInTime", []iam.Gate{presence("restore_source_name"), presence("restore_source_table_arn")}},
		{"dynamodb:ImportTable", []iam.Gate{valued("import_table")}},
		{"dynamodb:CreateTable", always},
	})
}

// TestElseBranch_RDSCluster is trimmed from internal/service/rds/cluster.go
// (provider v5.90.0): an else-if chain of presence guards that ends in the
// plain create.
func TestElseBranch_RDSCluster(t *testing.T) {
	actions := parseCreate(t, `
	if v, ok := d.GetOk("snapshot_identifier"); ok {
		_, err = conn.RestoreDBClusterFromSnapshot(ctx, input)
	} else if v, ok := d.GetOk("s3_import"); ok {
		_, err = conn.RestoreDBClusterFromS3(ctx, input)
	} else if v, ok := d.GetOk("restore_to_point_in_time"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		_, err = conn.RestoreDBClusterToPointInTime(ctx, input)
	} else {
		_, err = conn.CreateDBCluster(ctx, input)
	}`)
	checkGates(t, actions, "create", []gateCase{
		{"dynamodb:RestoreDBClusterFromSnapshot", []iam.Gate{presence("snapshot_identifier")}},
		{"dynamodb:RestoreDBClusterFromS3", []iam.Gate{presence("s3_import")}},
		{"dynamodb:RestoreDBClusterToPointInTime", []iam.Gate{valued("restore_to_point_in_time")}},
		{"dynamodb:CreateDBCluster", always},
	})
}

// TestElseBranch_GuardKinds covers the else branch of each guard kind, the
// negated forms, whose else branch carries the gate, an outer guard, which
// the else branch keeps, and guard locals bound before the if-statement.
func TestElseBranch_GuardKinds(t *testing.T) {
	actions := parseCreate(t, `
	if v, ok := d.GetOk("a"); ok && v.(*schema.Set).Len() > 0 {
		_, err = conn.ValueThen(ctx, input)
	} else {
		_, err = conn.ValueElse(ctx, input)
	}
	if d.HasChange("b") {
		_, err = conn.ChangeThen(ctx, input)
	} else {
		_, err = conn.ChangeElse(ctx, input)
	}
	if _, ok := d.GetOk("c"); !ok {
		_, err = conn.NegPresenceThen(ctx, input)
	} else {
		_, err = conn.NegPresenceElse(ctx, input)
	}
	if !d.Get("e").(bool) {
		_, err = conn.NegGetThen(ctx, input)
	} else {
		_, err = conn.NegGetElse(ctx, input)
	}
	if !d.HasChange("f") {
		_, err = conn.NegChangeThen(ctx, input)
	} else {
		_, err = conn.NegChangeElse(ctx, input)
	}
	if changed := d.HasChange("g"); !changed {
		_, err = conn.NegBoundThen(ctx, input)
	} else {
		_, err = conn.NegBoundElse(ctx, input)
	}
	if v, ok := d.GetOk("h"); !ok || v.(string) == "" {
		_, err = conn.NegOrThen(ctx, input)
	} else {
		_, err = conn.NegOrElse(ctx, input)
	}
	if _, ok := d.GetOk("i"); ok || other {
		_, err = conn.OrThen(ctx, input)
	} else {
		_, err = conn.OrElse(ctx, input)
	}
	if changed := d.HasChange("j"); changed && other {
		_, err = conn.AndThen(ctx, input)
	}
	if d.HasChange("outer") {
		if _, ok := d.GetOk("inner"); ok {
			_, err = conn.NestedThen(ctx, input)
		} else {
			_, err = conn.NestedElse(ctx, input)
		}
	}
	_, mOk := d.GetOk("m")
	_, nOk := d.GetOk("n")
	_, pOk := d.GetOk("p")
	nOk = other
	setFlag(&pOk)
	if mOk {
		_, err = conn.BoundBefore(ctx, input)
	}
	if nOk {
		_, err = conn.ReassignedBefore(ctx, input)
	}
	if pOk {
		_, err = conn.PointerBefore(ctx, input)
	}
	if _, ok := d.GetOk("k"); ok {
		_, err = conn.ChainA(ctx, input)
	} else if _, ok := d.GetOk("l"); ok {
		_, err = conn.ChainB(ctx, input)
	} else {
		_, err = conn.ChainC(ctx, input)
	}`)
	checkGates(t, actions, "create", []gateCase{
		{"dynamodb:ValueThen", []iam.Gate{valued("a")}},
		{"dynamodb:ValueElse", always},
		{"dynamodb:ChangeThen", []iam.Gate{changed("b")}},
		{"dynamodb:ChangeElse", always},
		{"dynamodb:NegPresenceThen", always},
		{"dynamodb:NegPresenceElse", []iam.Gate{presence("c")}},
		{"dynamodb:NegGetThen", always},
		{"dynamodb:NegGetElse", []iam.Gate{presence("e")}},
		{"dynamodb:NegChangeThen", always},
		{"dynamodb:NegChangeElse", []iam.Gate{changed("f")}},
		{"dynamodb:NegBoundThen", always},
		{"dynamodb:NegBoundElse", []iam.Gate{changed("g")}},
		{"dynamodb:NegOrThen", always},
		{"dynamodb:NegOrElse", []iam.Gate{presence("h")}},
		{"dynamodb:OrThen", always},
		{"dynamodb:OrElse", always},
		{"dynamodb:AndThen", []iam.Gate{changed("j")}},
		{"dynamodb:NestedThen", []iam.Gate{changed("outer")}},
		{"dynamodb:NestedElse", []iam.Gate{changed("outer")}},
		{"dynamodb:BoundBefore", []iam.Gate{presence("m")}},
		{"dynamodb:ReassignedBefore", always},
		{"dynamodb:PointerBefore", always},
		{"dynamodb:ChainA", []iam.Gate{presence("k")}},
		{"dynamodb:ChainB", []iam.Gate{presence("l")}},
		{"dynamodb:ChainC", always},
	})
}

// TestElseBranch_EarlyReturn covers a guarded block that returns: the code
// after it runs only when the guard does not hold, so it carries no gate.
func TestElseBranch_EarlyReturn(t *testing.T) {
	actions := parseCreate(t, `
	if v, ok := d.GetOk("snapshot_identifier"); ok {
		_, err = conn.RestoreFromSnapshot(ctx, input)
		return nil
	}
	_, err = conn.CreatePlain(ctx, input)`)
	checkGates(t, actions, "create", []gateCase{
		{"dynamodb:RestoreFromSnapshot", []iam.Gate{presence("snapshot_identifier")}},
		{"dynamodb:CreatePlain", always},
	})
}

// TestKinesisStreamUpdateGates is trimmed from
// internal/service/kinesis/stream.go (provider v5.90.0). A change guard
// inside a conjunction gates its body, and d.HasChanges gates its body on
// a change to any of its attributes.
func TestKinesisStreamUpdateGates(t *testing.T) {
	src := `package kinesis

func resourceStreamUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).KinesisClient(ctx)

	if streamMode := getStreamMode(d); streamMode == types.StreamModeProvisioned && d.HasChange("shard_count") {
		_, err := conn.UpdateShardCount(ctx, input)
		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating: %s", err)
		}
	}

	if d.HasChanges("encryption_type", "kms_key_id") {
		switch newEncryptionType {
		case types.EncryptionTypeKms:
			_, err := conn.StartStreamEncryption(ctx, input)
			if err != nil {
				return sdkdiag.AppendErrorf(diags, "starting: %s", err)
			}
		}
	}
	return nil
}
`
	actions, err := ParseResourceFileStructured(src, "aws_kinesis_stream", "Stream")
	if err != nil {
		t.Fatal(err)
	}
	checkGates(t, actions, "update", []gateCase{
		{"kinesis:UpdateShardCount", []iam.Gate{changed("shard_count")}},
		{"kinesis:StartStreamEncryption", []iam.Gate{changed("encryption_type"), changed("kms_key_id")}},
	})
}

// TestElseBranch_Framework covers the else branch of a framework guard:
// `data.X.IsNull()` runs its else branch only when X is set.
func TestElseBranch_Framework(t *testing.T) {
	src := `package x

// @FrameworkResource("aws_thing", name="Thing")
func newResourceThing(context.Context) (resource.ResourceWithConfigure, error) {
	return &resourceThing{}, nil
}

type resourceThing struct {
	framework.ResourceWithConfigure
}

type resourceThingModel struct {
	Policy types.String ` + "`tfsdk:\"policy\"`" + `
}

func (r *resourceThing) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var data resourceThingModel
	conn := r.Meta().S3Client(ctx)
	if data.Policy.IsNull() {
		_, err = conn.DeleteBucketPolicy(ctx, &input)
	} else {
		_, err = conn.PutBucketPolicy(ctx, &input)
	}
	if !data.Policy.IsNull() {
		_, err = conn.GetBucketPolicy(ctx, &input)
	} else {
		_, err = conn.GetBucketAcl(ctx, &input)
	}
}
`
	pkg, err := ParsePackage(map[string]string{"thing.go": src})
	if err != nil {
		t.Fatal(err)
	}
	actions := pkg.actionsFor(pkg.frameworkFuncs("resourceThing"))
	checkGates(t, actions, "create", []gateCase{
		{"s3:DeleteBucketPolicy", always},
		{"s3:PutBucketPolicy", []iam.Gate{presence("policy")}},
		{"s3:GetBucketPolicy", []iam.Gate{presence("policy")}},
		{"s3:GetBucketAcl", always},
	})
}
