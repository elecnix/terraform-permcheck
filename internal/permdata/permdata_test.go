package permdata

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

// sample is a table that uses every field the format stores: each gate
// field, a known operation with no requirements, an action reached on two
// paths, and an incomplete operation.
func sample() map[string]*cloud.Schema {
	return map[string]*cloud.Schema{
		"aws_widget": {
			TypeName: "aws_widget",
			Ops: map[string][]iam.Requirement{
				"create": {
					{Action: "demo:CreateWidget"},
					{Action: "kms:CreateGrant", Gate: iam.Gate{Attribute: "kms_key_arn", ValueGuarded: true}},
					{Action: "demo:TagResource", Gate: iam.Gate{Attribute: "tags"}},
					{Action: "demo:TagResource", Gate: iam.Gate{Changed: "tags_all"}},
				},
				"read":   {{Action: "kms:DescribeKey", Gate: iam.Gate{BestEffort: true}}},
				"update": {},
			},
			Incomplete: map[string]bool{"delete": true},
		},
		"aws_gadget": {
			TypeName: "aws_gadget",
			Ops:      map[string][]iam.Requirement{"delete": {{Action: "demo:DeleteGadget"}}},
		},
	}
}

// TestEncodeDecode_RoundTrip checks that decoding an encoded table gives back
// the same schemas.
func TestEncodeDecode_RoundTrip(t *testing.T) {
	want := sample()
	data, err := Encode("v1.2.3", want)
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v\n%s", err, data)
	}
	if tbl.Ref != "v1.2.3" {
		t.Errorf("Ref = %q, want v1.2.3", tbl.Ref)
	}
	assertSameSchemas(t, tbl.Schemas, want)
}

// TestEncode_Deterministic checks that the same table always encodes to the
// same bytes, whatever order the maps were built in.
func TestEncode_Deterministic(t *testing.T) {
	first, err := Encode("v1", sample())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := Encode("v1", sample())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("encoding %d differs:\n%s\nvs\n%s", i, first, again)
		}
	}
	// Types come out sorted, and each requirement sits on its own line, so
	// a regenerated table diffs line by line.
	s := string(first)
	if strings.Index(s, `"aws_gadget"`) > strings.Index(s, `"aws_widget"`) {
		t.Errorf("resource types not sorted:\n%s", s)
	}
	if !strings.Contains(s, "\n          {\"action\":\"demo:CreateWidget\"},\n") {
		t.Errorf("requirement not on its own line:\n%s", s)
	}
}

// TestDecode_RejectsOtherFormat checks that a table written in another
// format version is refused rather than misread.
func TestDecode_RejectsOtherFormat(t *testing.T) {
	_, err := Decode([]byte(`{"format": 99, "ref": "v1", "resources": {}}`))
	if err == nil || !strings.Contains(err.Error(), "format") {
		t.Errorf("Decode(format 99) error = %v, want a format error", err)
	}
}

// TestGateFields fails when iam.Gate gains a field, because the format must
// then store it too. Add the field to requirement, bump FormatVersion, and
// regenerate permissions.json.
func TestGateFields(t *testing.T) {
	if n := reflect.TypeOf(iam.Gate{}).NumField(); n != 4 {
		t.Errorf("iam.Gate has %d fields, the permdata format stores 4", n)
	}
}

// TestGenerate_MatchesSourceProvider generates a table from a small provider
// tree and checks that the decoded table serves the same requirements as the
// parser itself.
func TestGenerate_MatchesSourceProvider(t *testing.T) {
	src := provideraws.NewSourceProviderWithPath("../check/testdata/provider")
	data, err := Generate(src)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Generate(provideraws.NewSourceProviderWithPath("../check/testdata/provider"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, again) {
		t.Error("two generations from the same tree differ")
	}

	tbl, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Ref != provideraws.DefaultProviderRef {
		t.Errorf("Ref = %q, want %q", tbl.Ref, provideraws.DefaultProviderRef)
	}
	want, err := src.Schemas()
	if err != nil {
		t.Fatal(err)
	}
	assertSameSchemas(t, tbl.Schemas, want)

	p := NewProvider(data)
	for tfType, w := range want {
		got, err := p.Resolve(tfType)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", tfType, err)
		}
		assertSameSchemas(t, map[string]*cloud.Schema{tfType: got}, map[string]*cloud.Schema{tfType: w})
	}
}

// TestProvider_UnknownType checks that a type the table lacks is an error, so
// the chain falls back to the next provider.
func TestProvider_UnknownType(t *testing.T) {
	data, err := Encode("v1", sample())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProvider(data).Resolve("aws_nothing"); err == nil {
		t.Error("Resolve(aws_nothing): want an error")
	}
	if _, err := NewProvider([]byte("not json")).Resolve("aws_widget"); err == nil {
		t.Error("Resolve on a broken table: want an error")
	}
}

// TestEmbedded_KeyTypes checks that the embedded table loads, matches the
// pinned provider ref, and holds the requirements of common resource types.
func TestEmbedded_KeyTypes(t *testing.T) {
	p := Embedded()
	ref, err := p.Ref()
	if err != nil {
		t.Fatal(err)
	}
	if ref != provideraws.DefaultProviderRef {
		t.Errorf("embedded table is for %s, DefaultProviderRef is %s; regenerate it with generate-permissions", ref, provideraws.DefaultProviderRef)
	}
	if n, _ := p.Len(); n < 1000 {
		t.Errorf("embedded table has %d resource types, want over 1000", n)
	}
	for tfType, ops := range map[string]map[string]string{
		"aws_s3_bucket":            {"create": "s3:CreateBucket", "delete": "s3:DeleteBucket"},
		"aws_dynamodb_table":       {"create": "dynamodb:CreateTable", "read": "dynamodb:DescribeTable", "delete": "dynamodb:DeleteTable"},
		"aws_cloudwatch_log_group": {"create": "logs:CreateLogGroup"},
	} {
		schema, err := p.Resolve(tfType)
		if err != nil {
			t.Errorf("Resolve(%s): %v", tfType, err)
			continue
		}
		for op, action := range ops {
			if !contains(schema.Actions(op), action) {
				t.Errorf("%s %s = %v, want %s", tfType, op, schema.Actions(op), action)
			}
		}
	}
}

func assertSameSchemas(t *testing.T, got, want map[string]*cloud.Schema) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d types, want %d", len(got), len(want))
	}
	for tfType, w := range want {
		g, ok := got[tfType]
		if !ok {
			t.Errorf("%s missing", tfType)
			continue
		}
		if g.TypeName != tfType {
			t.Errorf("%s: TypeName = %q", tfType, g.TypeName)
		}
		if !reflect.DeepEqual(g.Ops, w.Ops) {
			t.Errorf("%s: Ops = %+v, want %+v", tfType, g.Ops, w.Ops)
		}
		if len(g.Incomplete) != len(w.Incomplete) || (len(w.Incomplete) > 0 && !reflect.DeepEqual(g.Incomplete, w.Incomplete)) {
			t.Errorf("%s: Incomplete = %v, want %v", tfType, g.Incomplete, w.Incomplete)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
