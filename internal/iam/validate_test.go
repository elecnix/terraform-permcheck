package iam

import (
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// bucketMissing validates an aws_s3_bucket that needs actions, in a plan that
// also changes the types in others, against an empty policy with no filter.
// It returns the actions reported on the bucket and on other resources. The
// resolver knows only the bucket and the vault, so the sub-resources come back
// unresolved; the helper leaves those findings out.
func bucketMissing(t *testing.T, actions []string, others ...string) (bucket, rest []string) {
	t.Helper()
	resolver := typeKeyedResolver{
		"aws_s3_bucket":    actionsSchema(map[string][]string{"create": actions}),
		"aws_backup_vault": actionsSchema(map[string][]string{"create": {"backup:CreateBackupVault"}}),
	}
	changes := []*plan.ResourceChange{{Type: "aws_s3_bucket", Name: "logs", Change: "create"}}
	for _, typ := range others {
		changes = append(changes, &plan.ResourceChange{Type: typ, Name: "other", Change: "create"})
	}
	missing, err := Validate(changes, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range missing {
		if m.Unresolved {
			continue
		}
		if m.ResourceType == "aws_s3_bucket" {
			bucket = append(bucket, m.Action)
		} else {
			rest = append(rest, m.Action)
		}
	}
	return bucket, rest
}

func TestValidate_S3SubresourceAbsorbsItsActions(t *testing.T) {
	bucket, _ := bucketMissing(t,
		[]string{"s3:CreateBucket", "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning", "s3:DeleteBucket"},
		"aws_s3_bucket_server_side_encryption_configuration")
	// The encryption sub-resource takes over its action; versioning has no
	// sub-resource in the plan, and the bucket's own actions stay.
	want := []string{"s3:CreateBucket", "s3:PutBucketVersioning", "s3:DeleteBucket"}
	if strings.Join(bucket, ",") != strings.Join(want, ",") {
		t.Errorf("bucket actions = %v, want %v", bucket, want)
	}
}

func TestValidate_S3AbsorptionNeedsTheSubresource(t *testing.T) {
	bucket, _ := bucketMissing(t, []string{"s3:PutEncryptionConfiguration", "s3:CreateBucket"}, "aws_dynamodb_table")
	if len(bucket) != 2 {
		t.Errorf("bucket actions = %v, want both kept with no sub-resource in the plan", bucket)
	}
}

func TestValidate_S3SubresourcesEachAbsorbTheirOwn(t *testing.T) {
	bucket, _ := bucketMissing(t,
		[]string{"s3:CreateBucket", "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning", "s3:PutBucketLogging"},
		"aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_versioning", "aws_s3_bucket_logging")
	if strings.Join(bucket, ",") != "s3:CreateBucket" {
		t.Errorf("bucket actions = %v, want only s3:CreateBucket", bucket)
	}
}

func TestValidate_S3AbsorptionLeavesOtherResources(t *testing.T) {
	bucket, rest := bucketMissing(t, []string{"s3:PutEncryptionConfiguration"},
		"aws_s3_bucket_server_side_encryption_configuration", "aws_backup_vault")
	if len(bucket) != 0 {
		t.Errorf("bucket actions = %v, want the encryption call absorbed", bucket)
	}
	if strings.Join(rest, ",") != "backup:CreateBackupVault" {
		t.Errorf("other actions = %v, want backup:CreateBackupVault", rest)
	}
}

// The parser emits PutBucketPolicy and the request payment calls for
// aws_s3_bucket too. The sub-resource that makes the same call owns it.
func TestValidate_S3PolicyAndRequestPaymentAbsorbed(t *testing.T) {
	bucket, _ := bucketMissing(t,
		[]string{"s3:CreateBucket", "s3:PutBucketPolicy", "s3:PutBucketRequestPayment", "s3:GetBucketRequestPayment"},
		"aws_s3_bucket_policy", "aws_s3_bucket_request_payment_configuration")
	if strings.Join(bucket, ",") != "s3:CreateBucket" {
		t.Errorf("bucket actions = %v, want only s3:CreateBucket", bucket)
	}
}

// The encryption sub-resource absorbs the encryption calls in both spellings:
// the schema's DeleteBucketEncryption and the IAM action it needs.
func TestDecide_EncryptionSpellingsAbsorbed(t *testing.T) {
	inPlan := map[string]bool{"aws_s3_bucket_server_side_encryption_configuration": true}
	for _, a := range []string{"s3:PutEncryptionConfiguration", "s3:GetEncryptionConfiguration", "s3:DeleteBucketEncryption"} {
		if got := decide("aws_s3_bucket", a, false, false, inPlan).absorbedBy; got == "" {
			t.Errorf("decide(aws_s3_bucket, %s) not absorbed", a)
		}
	}
	// Only aws_s3_bucket hands actions over.
	if got := decide("aws_s3_bucket_versioning", "s3:PutEncryptionConfiguration", false, false, inPlan).absorbedBy; got != "" {
		t.Errorf("decide on a sub-resource absorbed by %s", got)
	}
}

// fakeSchema lists a test schema's operations: operation → requirements,
// one per path that reaches an action, each carrying its own gate.
type fakeSchema map[string][]Requirement

// schema returns the Schema of these operations.
func (f fakeSchema) schema() *Schema {
	return &Schema{Ops: f}
}

// actionsSchema builds a fakeSchema of ungated requirements from
// operation → actions.
func actionsSchema(perms map[string][]string) fakeSchema {
	s := make(fakeSchema, len(perms))
	for op, actions := range perms {
		s[op] = Unconditional(actions...)
	}
	return s
}

// fakeResolver serves one schema for every terraform resource type.
type fakeResolver struct{ s fakeSchema }

func (r fakeResolver) Resolve(string) (*Schema, error) { return r.s.schema(), nil }

// grantNothing returns a policy with no statements, which grants no action.
func grantNothing() *policy.Document { return &policy.Document{} }

// grantActions returns a policy that allows the action patterns on every
// resource.
func grantActions(actions ...string) *policy.Document {
	return &policy.Document{Statements: []policy.Statement{{Effect: "Allow", Action: actions, Resource: []string{"*"}}}}
}

// TestValidate_BestEffortIsOptional checks that an action whose failure the
// provider ignores is never reported as required. The default filter drops
// it, and with no filter it is tagged [optional].
func TestValidate_BestEffortIsOptional(t *testing.T) {
	schema := fakeSchema{"read": {
		{Action: "dynamodb:DescribeTable"},
		{Action: "kms:DescribeKey", Gate: Gate{BestEffort: true}},
	}}
	changes := []*plan.ResourceChange{{Type: "aws_dynamodb_table", Name: "t", Change: "read"}}

	missing, err := Validate(changes, grantNothing(), fakeResolver{schema}, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "kms:DescribeKey") {
		t.Error("best-effort kms:DescribeKey reported under the default filter")
	}
	if !hasAction(missing, "dynamodb:DescribeTable") {
		t.Error("dynamodb:DescribeTable missing from the report")
	}

	missing, err = Validate(changes, grantNothing(), fakeResolver{schema}, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	class, found := classOf(missing, "kms:DescribeKey")
	if !found {
		t.Fatal("kms:DescribeKey dropped with no filter")
	}
	if class != "[optional]" {
		t.Errorf("kms:DescribeKey class = %q, want [optional]", class)
	}
}

func TestValidate_ConditionalGatedOnAttribute(t *testing.T) {
	schema := fakeSchema{"create": {
		{Action: "kms:CreateKey"},
		{Action: "kms:TagResource", Gate: Gate{Attribute: "tags"}},
	}}
	resolver := fakeResolver{schema}

	// Case 1: tags present → kms:TagResource is required (reported missing).
	withTags := []*plan.ResourceChange{
		{Type: "aws_kms_key", Name: "k", Change: "create", Attributes: map[string]bool{"tags": true}},
	}
	missing, err := Validate(withTags, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "kms:TagResource") {
		t.Error("expected kms:TagResource to be required when tags are present")
	}
	if !hasAction(missing, "kms:CreateKey") {
		t.Error("expected kms:CreateKey to always be required")
	}

	// Case 2: attributes parsed but tags absent → kms:TagResource gated out.
	noTags := []*plan.ResourceChange{
		{Type: "aws_kms_key", Name: "k", Change: "create", Attributes: map[string]bool{"description": true}},
	}
	missing, err = Validate(noTags, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "kms:TagResource") {
		t.Error("expected kms:TagResource to be gated out when tags absent")
	}
	if !hasAction(missing, "kms:CreateKey") {
		t.Error("expected kms:CreateKey to remain required")
	}

	// Case 3: no attribute info (nil) → conditional kept (cannot prove absence).
	unknown := []*plan.ResourceChange{
		{Type: "aws_kms_key", Name: "k", Change: "create"},
	}
	missing, err = Validate(unknown, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "kms:TagResource") {
		t.Error("expected kms:TagResource to be kept when attribute info is unknown")
	}
}

func TestValidate_ConditionalGatedOnAttribute_Delete(t *testing.T) {
	// A conditional permission on a delete change must be evaluated against
	// prior state (change.before), not treated as unknown.
	schema := fakeSchema{"delete": {
		{Action: "secretsmanager:DeleteSecret"},
		{Action: "secretsmanager:UpdateSecretVersionStage", Gate: Gate{Attribute: "version_stages"}},
	}}
	resolver := fakeResolver{schema}

	// Case 1: before-state has version_stages set → permission still required.
	withStages := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret_version", Name: "v", Change: "delete", Attributes: map[string]bool{"version_stages": true}},
	}
	missing, err := Validate(withStages, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "secretsmanager:UpdateSecretVersionStage") {
		t.Error("expected UpdateSecretVersionStage to be required when before-state has version_stages set")
	}

	// Case 2: before-state has version_stages unset → permission suppressed.
	withoutStages := []*plan.ResourceChange{
		{Type: "aws_secretsmanager_secret_version", Name: "v", Change: "delete", Attributes: map[string]bool{"secret_id": true}},
	}
	missing, err = Validate(withoutStages, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "secretsmanager:UpdateSecretVersionStage") {
		t.Error("expected UpdateSecretVersionStage to be suppressed when before-state has version_stages unset")
	}
	if !hasAction(missing, "secretsmanager:DeleteSecret") {
		t.Error("expected unconditional DeleteSecret to remain required")
	}
}

func hasAction(missing []MissingAction, action string) bool {
	for _, m := range missing {
		if m.Action == action {
			return true
		}
	}
	return false
}

// classOf returns the class tag the report gives an action, and whether the
// action is in the report at all.
func classOf(missing []MissingAction, action string) (string, bool) {
	for _, m := range missing {
		if m.Action == action {
			return m.Class, true
		}
	}
	return "", false
}

func TestValidate_ExcludeConditional(t *testing.T) {
	schema := fakeSchema{"create": {
		{Action: "kms:CreateKey"},
		{Action: "kms:CreateGrant", Gate: Gate{Attribute: "kms_key_arn"}},
	}}
	resolver := fakeResolver{schema}

	changes := []*plan.ResourceChange{
		{Type: "aws_backup_vault", Name: "v", Change: "create"},
	}

	// With ExcludeConditional: kms:CreateGrant should be filtered out
	filter := FilterConfig{ExcludeConditional: true}
	missing, err := Validate(changes, grantNothing(), resolver, filter)
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "kms:CreateGrant") {
		t.Error("kms:CreateGrant should be excluded when ExcludeConditional is true")
	}
	if !hasAction(missing, "kms:CreateKey") {
		t.Error("kms:CreateKey should remain (unconditional)")
	}
}

func TestStripResourceIndex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no index", "cloudtrail", "cloudtrail"},
		{"count index", "cloudtrail[0]", "cloudtrail"},
		{"large count", "cloudtrail[123]", "cloudtrail"},
		{"for_each string key", `config["us-east-1"]`, "config"},
		{"for_each with dots", `foo["bar.baz"]`, "foo"},
		{"already clean", "my_bucket", "my_bucket"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripResourceIndex(tt.input)
			if got != tt.expected {
				t.Errorf("stripResourceIndex(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestValidate_ChangeGatedOnAttribute covers update-path permissions gated on
// d.HasChange: the plan shows whether the attribute changed, so the permission
// is reported only when it did.
func TestValidate_ChangeGatedOnAttribute(t *testing.T) {
	schema := fakeSchema{"update": {
		{Action: "iam:UpdateRole"},
		{Action: "iam:PutRolePermissionsBoundary", Gate: Gate{Changed: "permissions_boundary"}},
		{Action: "iam:DeleteRolePermissionsBoundary", Gate: Gate{Changed: "permissions_boundary"}},
	}}
	resolver := fakeResolver{schema}

	// Case 1: the attribute changed → both gated actions are required.
	changed := []*plan.ResourceChange{
		{
			Type:              "aws_iam_role",
			Name:              "example",
			Change:            "update",
			Attributes:        map[string]bool{"permissions_boundary": true, "assume_role_policy": true},
			ChangedAttributes: map[string]bool{"permissions_boundary": true, "assume_role_policy": true},
		},
	}
	missing, err := Validate(changed, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary"} {
		if !hasAction(missing, action) {
			t.Errorf("expected %s to be required when the attribute changed", action)
		}
	}

	// Case 2: only another attribute changed → both gated actions are dropped.
	unchanged := []*plan.ResourceChange{
		{
			Type:              "aws_iam_role",
			Name:              "example",
			Change:            "update",
			Attributes:        map[string]bool{"permissions_boundary": true},
			ChangedAttributes: map[string]bool{"permissions_boundary": false, "assume_role_policy": true},
		},
	}
	missing, err = Validate(unchanged, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary"} {
		if hasAction(missing, action) {
			t.Errorf("expected %s to be gated out when the attribute did not change", action)
		}
	}
	if !hasAction(missing, "iam:UpdateRole") {
		t.Error("expected the unconditional iam:UpdateRole to remain required")
	}

	// Case 3: no change data (static HCL mode) → kept, presence unknown.
	unknown := []*plan.ResourceChange{
		{Type: "aws_iam_role", Name: "example", Change: "update"},
	}
	missing, err = Validate(unknown, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "iam:PutRolePermissionsBoundary") {
		t.Error("expected change-gated permission to be kept when change data is unknown")
	}

	// Case 4: --only-required drops change-gated permissions too.
	missing, err = Validate(changed, grantNothing(), resolver, FilterConfig{ExcludeConditional: true})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "iam:PutRolePermissionsBoundary") {
		t.Error("expected change-gated permission to be excluded by ExcludeConditional")
	}
	if !hasAction(missing, "iam:UpdateRole") {
		t.Error("expected the unconditional iam:UpdateRole to survive ExcludeConditional")
	}
}

// TestValidate_ChangeGatedKeepsPresenceGates checks the two gate kinds do not
// interfere: a change-gated action is not dropped by attribute presence.
func TestValidate_ChangeGatedKeepsPresenceGates(t *testing.T) {
	schema := fakeSchema{"create": {
		{Action: "kms:TagResource", Gate: Gate{Changed: "permissions_boundary"}},
	}}
	resolver := fakeResolver{schema}

	// The attribute is unset and unchanged, but this action is gated on the
	// change, not on presence — presence must not suppress it.
	changes := []*plan.ResourceChange{
		{
			Type:              "aws_kms_key",
			Name:              "k",
			Change:            "create",
			Attributes:        map[string]bool{"description": true},
			ChangedAttributes: map[string]bool{"permissions_boundary": true},
		},
	}
	missing, err := Validate(changes, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "kms:TagResource") {
		t.Error("expected kms:TagResource to remain: its gate is a change, not presence")
	}
}

// TestValidate_BothGatesOnOneAction covers an action that carries both a
// presence gate and a change gate. Both must hold, and the report must name
// both attributes, since either one can suppress the action.
func TestValidate_BothGatesOnOneAction(t *testing.T) {
	schema := fakeSchema{"update": {
		{Action: "iam:UpdateRolePolicy", Gate: Gate{Attribute: "tags", Changed: "policy"}},
	}}
	resolver := fakeResolver{schema}

	// Both gates hold → reported, naming both attributes.
	bothHold := []*plan.ResourceChange{
		{
			Type:              "aws_iam_role",
			Name:              "example",
			Change:            "update",
			Attributes:        map[string]bool{"tags": true, "policy": true},
			ChangedAttributes: map[string]bool{"policy": true},
		},
	}
	missing, err := Validate(bothHold, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].Action != "iam:UpdateRolePolicy" {
		t.Fatalf("expected exactly iam:UpdateRolePolicy when both gates hold, got %v", missing)
	}
	if got := missing[0].ConditionAttribute; got != "tags+policy" {
		t.Errorf("ConditionAttribute = %q, want %q naming both gating attributes", got, "tags+policy")
	}

	// The presence gate fails → dropped, even though the change gate holds.
	presenceFails := []*plan.ResourceChange{
		{
			Type:              "aws_iam_role",
			Name:              "example",
			Change:            "update",
			Attributes:        map[string]bool{"tags": false, "policy": true},
			ChangedAttributes: map[string]bool{"policy": true},
		},
	}
	missing, err = Validate(presenceFails, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "iam:UpdateRolePolicy") {
		t.Error("expected the action to be dropped when the presence gate fails")
	}

	// The change gate fails → dropped, even though the presence gate holds.
	changeFails := []*plan.ResourceChange{
		{
			Type:              "aws_iam_role",
			Name:              "example",
			Change:            "update",
			Attributes:        map[string]bool{"tags": true, "policy": true},
			ChangedAttributes: map[string]bool{"policy": false},
		},
	}
	missing, err = Validate(changeFails, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "iam:UpdateRolePolicy") {
		t.Error("expected the action to be dropped when the change gate fails")
	}
}

func TestValidate_ValueGuardNeedsConfiguredAttribute(t *testing.T) {
	// A call guarded by a comparison on the attribute's value (a set that must
	// be non-empty) fires only when the author configured it. The attribute's
	// default keeps the value non-zero, so presence in state proves nothing.
	schema := fakeSchema{"delete": {
		{Action: "secretsmanager:DeleteSecret"},
		{Action: "secretsmanager:UpdateSecretVersionStage", Gate: Gate{Attribute: "version_stages", ValueGuarded: true}},
	}}
	resolver := fakeResolver{schema}

	// Case 1: before-state holds the default label, but the author wrote no
	// version_stages → the provider makes no call → the action is not reported.
	defaulted := []*plan.ResourceChange{{
		Type:            "aws_secretsmanager_secret_version",
		Name:            "v",
		Change:          "delete",
		Attributes:      map[string]bool{"version_stages": true},
		AttributeValues: map[string]string{"id": "sv-1"},
		Configured:      map[string]bool{"secret_string": true},
	}}
	missing, err := Validate(defaulted, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if hasAction(missing, "secretsmanager:UpdateSecretVersionStage") {
		t.Error("expected UpdateSecretVersionStage suppressed when version_stages is only a default")
	}
	if !hasAction(missing, "secretsmanager:DeleteSecret") {
		t.Error("expected unconditional DeleteSecret to remain required")
	}

	// Case 2: the author wrote version_stages → the call is real.
	configured := []*plan.ResourceChange{{
		Type:            "aws_secretsmanager_secret_version",
		Name:            "v",
		Change:          "delete",
		Attributes:      map[string]bool{"version_stages": true},
		AttributeValues: map[string]string{"id": "sv-1"},
		Configured:      map[string]bool{"secret_string": true, "version_stages": true},
	}}
	missing, err = Validate(configured, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "secretsmanager:UpdateSecretVersionStage") {
		t.Error("expected UpdateSecretVersionStage required when version_stages is configured")
	}

	// Case 3: no configuration section (static HCL mode) → fall back to
	// presence, which reports the action.
	noConfig := []*plan.ResourceChange{{
		Type:       "aws_secretsmanager_secret_version",
		Name:       "v",
		Change:     "delete",
		Attributes: map[string]bool{"version_stages": true},
	}}
	missing, err = Validate(noConfig, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "secretsmanager:UpdateSecretVersionStage") {
		t.Error("expected UpdateSecretVersionStage kept when the configuration is unknown")
	}
}

// An operation the schema knows, even with no requirements, is answered on
// its own. Only an operation the schema does not know falls back to create.
func TestValidate_KnownEmptyOperationDoesNotFallBack(t *testing.T) {
	schema := fakeSchema{
		"create": Unconditional("kms:CreateKey"),
		"update": nil,
	}
	resolver := fakeResolver{schema}

	update := []*plan.ResourceChange{{Type: "aws_kms_key", Name: "k", Change: "update"}}
	missing, err := Validate(update, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("known empty update reported %+v, want nothing", missing)
	}

	del := []*plan.ResourceChange{{Type: "aws_kms_key", Name: "k", Change: "delete"}}
	missing, err = Validate(del, grantNothing(), resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "kms:CreateKey") {
		t.Errorf("unknown delete reported %+v, want the create fallback", missing)
	}
}
