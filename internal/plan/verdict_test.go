package plan

import (
	"reflect"
	"testing"
)

// summary collapses changes to "address change" for assertions.
func summary(changes []*ResourceChange) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.Address+" "+c.Change)
	}
	return out
}

// TestParse_ReplaceSplitsIntoDeleteAndCreate verifies that a replace yields
// a delete of the prior object and a create of the planned one, in the order
// terraform runs them, each reading its own state.
func TestParse_ReplaceSplitsIntoDeleteAndCreate(t *testing.T) {
	for _, tc := range []struct {
		actions string
		want    []string
	}{
		{`["delete","create"]`, []string{"aws_sqs_queue.q delete", "aws_sqs_queue.q create"}},
		{`["create","delete"]`, []string{"aws_sqs_queue.q create", "aws_sqs_queue.q delete"}},
	} {
		raw := []byte(`{"resource_changes":[{"address":"aws_sqs_queue.q","mode":"managed","type":"aws_sqs_queue","name":"q",
			"change":{"actions":` + tc.actions + `,
			"before":{"name":"old-q","kms_master_key_id":"k"},
			"after":{"name":"new-q","kms_master_key_id":null},"after_unknown":{"arn":true}}}]}`)
		changes, err := Parse(raw, "aws_")
		if err != nil {
			t.Fatal(err)
		}
		if got := summary(changes); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: changes = %v, want %v", tc.actions, got, tc.want)
		}
		for _, c := range changes {
			switch c.Change {
			case "delete":
				if c.AttributeValues["name"] != "old-q" || !c.Attributes["kms_master_key_id"] || c.ChangedAttributes != nil {
					t.Errorf("%s: delete reads %v / %v / changed %v, want the prior state and unknown change",
						tc.actions, c.AttributeValues, c.Attributes, c.ChangedAttributes)
				}
			case "create":
				if c.AttributeValues["name"] != "new-q" || c.Attributes["kms_master_key_id"] || !c.ChangedAttributes["name"] {
					t.Errorf("%s: create reads %v / %v / changed %v, want the planned state",
						tc.actions, c.AttributeValues, c.Attributes, c.ChangedAttributes)
				}
			}
		}
	}
}

// TestParse_UnknownAttributeIsPresent verifies that an attribute the plan
// marks as computed at apply time counts as set when the author configured
// it, at the top level or inside a nested block. An unconfigured attribute
// the provider computes stays unset, and tags_all never counts.
func TestParse_UnknownAttributeIsPresent(t *testing.T) {
	raw := []byte(`{"resource_changes":[{"address":"aws_x.a","mode":"managed","type":"aws_x","name":"a",
		"change":{"actions":["create"],"before":null,
		"after":{"parent_id":null,"ttl":null,"computed_only":null,"tags_all":null},
		"after_unknown":{"parent_id":true,"ttl":[{"enabled":true}],"computed_only":true,"tags_all":true}}}],
		"configuration":{"root_module":{"resources":[{"address":"aws_x.a","mode":"managed","type":"aws_x","name":"a",
		"expressions":{"parent_id":{"references":["aws_y.b.id","aws_y.b"]},"ttl":[{"enabled":{"references":["var.on"]}}]}}]}}}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	attrs := changes[0].Attributes
	if !attrs["parent_id"] || !attrs["ttl"] {
		t.Errorf("attributes = %v, want parent_id and ttl present", attrs)
	}
	if attrs["computed_only"] || attrs["tags"] || attrs["tags_all"] {
		t.Errorf("attributes = %v, want computed_only, tags and tags_all unset", attrs)
	}
}

// TestParse_UnknownAttributeWithoutConfiguration verifies that a plan with
// no configuration section counts every unknown attribute but tags_all as
// set, since it cannot tell a configured attribute from a computed one.
func TestParse_UnknownAttributeWithoutConfiguration(t *testing.T) {
	raw := []byte(`{"resource_changes":[{"address":"aws_x.a","mode":"managed","type":"aws_x","name":"a",
		"change":{"actions":["create"],"before":null,"after":{"parent_id":null,"tags_all":null},
		"after_unknown":{"parent_id":true,"tags_all":true}}}]}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	attrs := changes[0].Attributes
	if !attrs["parent_id"] || attrs["tags"] || attrs["tags_all"] {
		t.Errorf("attributes = %v, want only parent_id present", attrs)
	}
}

// TestParse_SkipsDataSourcesAndForget verifies that a data source read and a
// forget, which call no mutating API, are not resource changes to check.
func TestParse_SkipsDataSourcesAndForget(t *testing.T) {
	raw := []byte(`{"resource_changes":[
		{"address":"data.aws_iam_policy_document.p","mode":"data","type":"aws_iam_policy_document","name":"p","change":{"actions":["read"],"before":null,"after":{}}},
		{"address":"aws_sqs_queue.f","mode":"managed","type":"aws_sqs_queue","name":"f","change":{"actions":["forget"],"before":{"name":"q1"},"after":null}},
		{"address":"aws_sqs_queue.k","mode":"managed","type":"aws_sqs_queue","name":"k","change":{"actions":["create"],"before":null,"after":{"name":"q2"}}}]}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := summary(changes), []string{"aws_sqs_queue.k create"}; !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %v, want %v", got, want)
	}
}

// TestParse_KeepsNoOpForReferences verifies that an unchanged resource stays
// in the parse as a no-op, so another change that references it can read its
// name, while Checked reports it needs no check.
func TestParse_KeepsNoOpForReferences(t *testing.T) {
	raw := []byte(`{"resource_changes":[
		{"address":"aws_secretsmanager_secret.s","mode":"managed","type":"aws_secretsmanager_secret","name":"s","change":{"actions":["no-op"],"before":{"name":"app"},"after":{"name":"app"}}},
		{"address":"aws_sqs_queue.k","mode":"managed","type":"aws_sqs_queue","name":"k","change":{"actions":["create"],"before":null,"after":{"name":"q2"}}}]}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := summary(changes), []string{"aws_secretsmanager_secret.s no-op", "aws_sqs_queue.k create"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %v, want %v", got, want)
	}
	if changes[0].Checked() || !changes[1].Checked() {
		t.Errorf("Checked() = %v, %v; want false for the no-op and true for the create", changes[0].Checked(), changes[1].Checked())
	}
	if changes[0].AttributeValues["name"] != "app" {
		t.Errorf("no-op values = %v, want name app", changes[0].AttributeValues)
	}
}

// TestParse_CarriesModuleAndIndex verifies that a change keeps the module it
// lives in and its count or for_each index, so two resources with the same
// type and name in different modules or instances stay apart.
func TestParse_CarriesModuleAndIndex(t *testing.T) {
	raw := []byte(`{"resource_changes":[
		{"address":"aws_sqs_queue.q","mode":"managed","type":"aws_sqs_queue","name":"q","change":{"actions":["create"],"after":{}}},
		{"address":"module.prod.aws_sqs_queue.q[0]","module_address":"module.prod","mode":"managed","type":"aws_sqs_queue","name":"q","index":0,"change":{"actions":["create"],"after":{}}},
		{"address":"module.a[\"x.y\"].aws_sqs_queue.q[\"k\"]","module_address":"module.a[\"x.y\"]","mode":"managed","type":"aws_sqs_queue","name":"q","index":"k","change":{"actions":["create"],"after":{}}}]}`)
	changes, err := Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"aws_sqs_queue.q create", "module.prod.aws_sqs_queue.q[0] create", `module.a["x.y"].aws_sqs_queue.q["k"] create`}
	if got := summary(changes); !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %v, want %v", got, want)
	}
	for i, c := range changes {
		if got, want := c.ModuleAddress+"|"+c.InstanceName(), []string{"|q", "module.prod|q[0]", `module.a["x.y"]|q["k"]`}[i]; got != want {
			t.Errorf("module|instance = %q, want %q", got, want)
		}
	}
}

// TestParse_ReferencesFollowModuleAddress verifies that two modules declaring
// the same resource type and name each read their own references, on every
// run. Module calls decode into a Go map, so a lookup that walks them would
// resolve in random order.
func TestParse_ReferencesFollowModuleAddress(t *testing.T) {
	raw := []byte(`{"resource_changes":[
		{"address":"module.a.aws_secretsmanager_secret_version.v","module_address":"module.a","mode":"managed","type":"aws_secretsmanager_secret_version","name":"v","change":{"actions":["create"],"after":{}}},
		{"address":"module.b.aws_secretsmanager_secret_version.v","module_address":"module.b","mode":"managed","type":"aws_secretsmanager_secret_version","name":"v","change":{"actions":["create"],"after":{}}}],
		"configuration":{"root_module":{"module_calls":{
			"a":{"module":{"resources":[{"mode":"managed","type":"aws_secretsmanager_secret_version","name":"v","expressions":{"secret_id":{"references":["aws_secretsmanager_secret.sa"]}}}]}},
			"b":{"module":{"resources":[{"mode":"managed","type":"aws_secretsmanager_secret_version","name":"v","expressions":{"secret_id":{"references":["aws_secretsmanager_secret.sb"]}}}]}}}}}}`)
	for i := 0; i < 50; i++ {
		changes, err := Parse(raw, "aws_")
		if err != nil {
			t.Fatal(err)
		}
		a, b := changes[0].References["secret_id"], changes[1].References["secret_id"]
		if len(a) != 1 || a[0] != "aws_secretsmanager_secret.sa" || len(b) != 1 || b[0] != "aws_secretsmanager_secret.sb" {
			t.Fatalf("run %d: module.a refs %v, module.b refs %v; want each module's own", i, a, b)
		}
	}
}
