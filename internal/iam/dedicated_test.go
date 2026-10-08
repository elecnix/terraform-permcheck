package iam

import (
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// embeddedSchemas reads the embedded permissions table as fake schemas. The
// iam package cannot import permdata, which depends on it, so the test reads
// the JSON itself.
func embeddedSchemas(t *testing.T) map[string]fakeSchema {
	t.Helper()
	raw, err := os.ReadFile("../permdata/permissions.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Resources map[string]struct {
			Ops map[string][]struct {
				Action       string `json:"action"`
				Attribute    string `json:"attribute"`
				ValueGuarded bool   `json:"value_guarded"`
				Changed      string `json:"changed"`
				BestEffort   bool   `json:"best_effort"`
			} `json:"ops"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]fakeSchema, len(doc.Resources))
	for typ, res := range doc.Resources {
		s := fakeSchema{}
		for op, reqs := range res.Ops {
			for _, r := range reqs {
				s[op] = append(s[op], Requirement{Action: r.Action, Gate: Gate{
					Attribute: r.Attribute, ValueGuarded: r.ValueGuarded,
					Changed: r.Changed, BestEffort: r.BestEffort,
				}})
			}
		}
		out[typ] = s
	}
	return out
}

// hiddenOps returns the types whose op reaches actions that the default
// filter drops, every one of them. Such a type can be created or deleted
// with a policy that grants it nothing.
func hiddenOps(schemas map[string]fakeSchema, op string) []string {
	var hidden []string
	for typ, s := range schemas {
		reqs := s[op]
		if len(reqs) == 0 {
			continue
		}
		dedicated := isDedicated(s.schema())
		all := true
		for _, r := range reqs {
			if decide(typ, r.Action, r.BestEffort, dedicated, nil).class == classManagement {
				all = false
				break
			}
		}
		if all {
			hidden = append(hidden, typ)
		}
	}
	sort.Strings(hidden)
	return hidden
}

// TestEmbedded_NoTypeHidesItsOwnWork checks every type in the embedded table.
// A resource that exists to make one call, such as aws_s3_object for
// s3:PutObject, must not have that call classed as data-plane or optional,
// or the default filter passes a policy that cannot create it.
func TestEmbedded_NoTypeHidesItsOwnWork(t *testing.T) {
	schemas := embeddedSchemas(t)
	for _, op := range []string{"create", "delete"} {
		if hidden := hiddenOps(schemas, op); len(hidden) > 0 {
			t.Errorf("%d types have every %s action hidden by default: %v", len(hidden), op, hidden)
		}
	}
}

// TestEmbedded_ParentsKeepTheirClasses checks that the dedicated rule leaves
// the parents alone: aws_s3_bucket makes its own management call, so its
// bucket-feature calls stay optional and its force_destroy calls data-plane.
func TestEmbedded_ParentsKeepTheirClasses(t *testing.T) {
	schemas := embeddedSchemas(t)
	for _, typ := range []string{"aws_s3_bucket", "aws_dynamodb_table", "aws_backup_vault", "aws_iam_user", "aws_kms_key", "aws_s3_directory_bucket"} {
		if isDedicated(schemas[typ].schema()) {
			t.Errorf("%s counts as dedicated, want a parent", typ)
		}
	}
	for _, typ := range []string{
		"aws_s3_object", "aws_s3_object_copy", "aws_iam_user_policy", "aws_dynamodb_table_item",
		"aws_kms_ciphertext", "aws_s3tables_table_bucket", "aws_backup_vault_lock_configuration",
		"aws_dynamodb_kinesis_streaming_destination",
	} {
		if !isDedicated(schemas[typ].schema()) {
			t.Errorf("%s does not count as dedicated", typ)
		}
	}
}

// TestValidate_DedicatedResourceCoreActionRequired checks the reproducer: an
// aws_s3_object create against a policy without s3:PutObject is reported as
// required under the default filter, while aws_s3_bucket keeps its feature
// calls optional.
func TestValidate_DedicatedResourceCoreActionRequired(t *testing.T) {
	resolver := typeKeyedResolver{
		"aws_s3_object": actionsSchema(map[string][]string{"create": {"s3:PutObject", "s3:GetObject"}}),
		"aws_s3_bucket": actionsSchema(map[string][]string{"create": {"s3:CreateBucket", "s3:GetBucketWebsite"}}),
	}
	changes := []*plan.ResourceChange{
		{Type: "aws_s3_object", Name: "o", Change: "create"},
		{Type: "aws_s3_bucket", Name: "b", Change: "create"},
	}
	missing, err := Validate(changes, grantActions("s3:CreateBucket"), resolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range missing {
		got = append(got, m.ResourceType+" "+m.Action+" "+m.Class)
	}
	want := []string{"aws_s3_object s3:PutObject [required]", "aws_s3_object s3:GetObject [required]"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("missing = %v, want %v", got, want)
	}
}
