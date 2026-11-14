package permdata

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/provideraws"
)

// sample is a table that uses every field the format stores: each gate
// field, a known operation with no requirements, an action reached on two
// paths, and an incomplete operation.
func sample() map[string]*iam.Schema {
	return map[string]*iam.Schema{
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
	data, err := Generate([]Version{{Ref: "v1.2.3", Schemas: want}})
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v\n%s", err, data)
	}
	if !reflect.DeepEqual(tbl.Refs, []string{"v1.2.3"}) {
		t.Errorf("Refs = %q, want [v1.2.3]", tbl.Refs)
	}
	assertSameSchemas(t, tbl.Schemas["v1.2.3"], want)
	if strings.Contains(string(data), `"providers"`) {
		t.Errorf("a one-version table marks providers:\n%s", data)
	}
}

// TestEncode_Deterministic checks that the same table always encodes to the
// same bytes, whatever order the maps were built in.
func TestEncode_Deterministic(t *testing.T) {
	first, err := Generate(twoVersions())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := Generate(twoVersions())
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
	last, prev := -1, ""
	for _, tfType := range []string{"aws_new_gizmo", "aws_old_gadget", "aws_widget"} {
		i := strings.Index(s, `"`+tfType+`": {`)
		if i < 0 {
			t.Fatalf("table lacks %s:\n%s", tfType, s)
		}
		if i < last {
			t.Errorf("resource types not sorted: %s comes before %s:\n%s", tfType, prev, s)
		}
		last, prev = i, tfType
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
	// Format 1 named one ref and had no providers marks.
	_, err = Decode([]byte(`{"format": 1, "ref": "v6.72.0", "resources": {}}`))
	if err == nil || !strings.Contains(err.Error(), "format") {
		t.Errorf("Decode(format 1) error = %v, want a format error", err)
	}
}

// TestGateFields fails when iam.Gate gains a field, because the format must
// then store it too. Add the field to requirement, bump formatVersion, and
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
	generate := func(src *provideraws.SourceProvider) []byte {
		t.Helper()
		schemas, err := src.Schemas()
		if err != nil {
			t.Fatal(err)
		}
		data, err := Generate([]Version{{Ref: provideraws.DefaultProviderRef, Schemas: schemas}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	src := provideraws.NewSourceProviderWithPath("../check/testdata/provider")
	data := generate(src)
	again := generate(provideraws.NewSourceProviderWithPath("../check/testdata/provider"))
	if !bytes.Equal(data, again) {
		t.Error("two generations from the same tree differ")
	}

	tbl, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Newest() != provideraws.DefaultProviderRef {
		t.Errorf("Newest = %q, want %q", tbl.Newest(), provideraws.DefaultProviderRef)
	}
	want, err := src.Schemas()
	if err != nil {
		t.Fatal(err)
	}
	assertSameSchemas(t, tbl.Schemas[provideraws.DefaultProviderRef], want)

	p := newProvider(data)
	for tfType, w := range want {
		got, err := p.Resolve(tfType)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", tfType, err)
		}
		assertSameSchemas(t, map[string]*iam.Schema{tfType: got}, map[string]*iam.Schema{tfType: w})
	}
}

// TestProvider_UnknownType checks that a type the table lacks is an error, so
// the chain falls back to the next provider.
func TestProvider_UnknownType(t *testing.T) {
	data, err := Generate([]Version{{Ref: "v1", Schemas: sample()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newProvider(data).Resolve("aws_nothing"); err == nil {
		t.Error("Resolve(aws_nothing): want an error")
	}
	if _, err := newProvider(data).At("v9.0.0").Resolve("aws_widget"); err == nil {
		t.Error("Resolve on a ref the table lacks: want an error")
	}
	if _, err := newProvider([]byte("not json")).Resolve("aws_widget"); err == nil {
		t.Error("Resolve on a broken table: want an error")
	}
}

// TestEmbedded_KeyTypes checks that the embedded table loads, matches the
// pinned provider ref, and holds the requirements of common resource types.
func TestEmbedded_KeyTypes(t *testing.T) {
	p := Embedded()
	tbl, err := p.decoded()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tbl.Refs, provideraws.TableProviderRefs) {
		t.Errorf("embedded table is for %v, TableProviderRefs is %v; regenerate it with generate-permissions", tbl.Refs, provideraws.TableProviderRefs)
	}
	for _, ref := range tbl.Refs {
		if n := len(tbl.Schemas[ref]); n < 1000 {
			t.Errorf("embedded table has %d resource types for %s, want over 1000", n, ref)
		}
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

func assertSameSchemas(t *testing.T, got, want map[string]*iam.Schema) {
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
