package permdata

import (
	"reflect"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// twoVersions is a table in two provider versions that differ in every way
// the format records: a type only one version has, an operation only one
// version has, a requirement only one version has, the same action on a
// different gate, a different order, and an operation incomplete in one
// version only. The newer version comes first, so Generate must sort them.
func twoVersions() []Version {
	v5 := map[string]*iam.Schema{
		"aws_widget": {
			TypeName: "aws_widget",
			Ops: map[string][]iam.Requirement{
				"create": {
					{Action: "demo:CreateWidget"},
					{Action: "demo:PutWidgetPolicy", Gate: iam.Gate{Attribute: "policy"}},
					{Action: "demo:DescribeWidget"},
				},
				"read":   {{Action: "demo:DescribeWidget"}},
				"update": {},
				"delete": {{Action: "demo:DeleteWidget"}},
			},
			Incomplete: map[string]bool{"delete": true},
		},
		"aws_old_gadget": {
			TypeName: "aws_old_gadget",
			Ops:      map[string][]iam.Requirement{"delete": {{Action: "demo:DeleteGadget"}}},
		},
	}
	v6 := map[string]*iam.Schema{
		"aws_widget": {
			TypeName: "aws_widget",
			Ops: map[string][]iam.Requirement{
				"create": {
					{Action: "demo:CreateWidget"},
					{Action: "demo:DescribeWidget"},
					{Action: "demo:PutWidgetPolicy", Gate: iam.Gate{Attribute: "policy", BestEffort: true}},
					{Action: "demo:GetWidgetConcurrency"},
				},
				"read":   {{Action: "demo:DescribeWidget"}},
				"update": {{Action: "demo:TagResource", Gate: iam.Gate{Attribute: "tags"}}},
				"delete": {{Action: "demo:DeleteWidget"}},
				"list":   {{Action: "demo:ListWidgets"}},
			},
		},
		"aws_new_gizmo": {
			TypeName: "aws_new_gizmo",
			Ops:      map[string][]iam.Requirement{"create": {{Action: "demo:CreateGizmo"}}},
		},
	}
	return []Version{{Ref: "v6.1.0", Schemas: v6}, {Ref: "v5.9.0", Schemas: v5}}
}

// TestGenerate_MergesVersions checks that each version decodes back to the
// schemas it was generated from, so a run on either version reads exactly
// what its parse found.
func TestGenerate_MergesVersions(t *testing.T) {
	versions := twoVersions()
	data, err := Generate(versions)
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v\n%s", err, data)
	}
	if want := []string{"v5.9.0", "v6.1.0"}; !reflect.DeepEqual(tbl.Refs, want) {
		t.Errorf("Refs = %v, want %v", tbl.Refs, want)
	}
	if tbl.Newest() != "v6.1.0" {
		t.Errorf("Newest = %s, want v6.1.0", tbl.Newest())
	}
	for _, v := range versions {
		t.Run(v.Ref, func(t *testing.T) {
			assertSameSchemas(t, tbl.Schemas[v.Ref], v.Schemas)
		})
	}
	if ref, ok := tbl.RefFor(5); !ok || ref != "v5.9.0" {
		t.Errorf("RefFor(5) = %q, %v", ref, ok)
	}
	if _, ok := tbl.RefFor(4); ok {
		t.Error("RefFor(4): want false")
	}
}

// TestGenerate_MarksOnlyWhatDiffers checks the lines of a merged table: what
// both versions share is written as a one-version table writes it, and each
// difference carries the versions it applies to.
func TestGenerate_MarksOnlyWhatDiffers(t *testing.T) {
	data, err := Generate(twoVersions())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		"\n  \"refs\": {\n    \"5\": \"v5.9.0\",\n    \"6\": \"v6.1.0\"\n  },\n",
		// Shared requirements carry no mark.
		"\n          {\"action\":\"demo:CreateWidget\"},\n",
		"\n          {\"action\":\"demo:DeleteWidget\"}\n",
		// A type only one version has is marked once, on the type.
		"\"aws_old_gadget\": {\n      \"providers\": [\"5\"],\n      \"ops\": {\n        \"delete\": [\n          {\"action\":\"demo:DeleteGadget\"}\n",
		"\"aws_new_gizmo\": {\n      \"providers\": [\"6\"],\n",
		// An operation only one version has.
		"\"op_providers\": {\"list\":[\"6\"]},",
		// Its requirements are relative to the operation, so they carry
		// no mark of their own.
		"\n          {\"action\":\"demo:ListWidgets\"}\n",
		// A requirement only one version has, and the same action on
		// another gate.
		"{\"action\":\"demo:GetWidgetConcurrency\",\"providers\":[\"6\"]}",
		"{\"action\":\"demo:PutWidgetPolicy\",\"attribute\":\"policy\",\"providers\":[\"5\"]}",
		"{\"action\":\"demo:PutWidgetPolicy\",\"attribute\":\"policy\",\"best_effort\":true,\"providers\":[\"6\"]}",
		"{\"action\":\"demo:TagResource\",\"attribute\":\"tags\",\"providers\":[\"6\"]}",
		// An operation incomplete in one version.
		"\"incomplete\": [{\"op\":\"delete\",\"providers\":[\"5\"]}],",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("table lacks %q:\n%s", want, s)
		}
	}
	// DescribeWidget is shared, but the versions order it differently
	// around PutWidgetPolicy: it is written once, and the order of each
	// version survives.
	if n := strings.Count(s, "{\"action\":\"demo:DescribeWidget\"}"); n != 2 {
		t.Errorf("DescribeWidget is written %d times, want once in create and once in read:\n%s", n, s)
	}
}

// TestGenerate_RejectsSameMajor checks that two refs of one major version
// are refused: the table holds one version per major.
func TestGenerate_RejectsSameMajor(t *testing.T) {
	_, err := Generate([]Version{{Ref: "v6.1.0", Schemas: sample()}, {Ref: "v6.2.0", Schemas: sample()}})
	if err == nil || !strings.Contains(err.Error(), "same major") {
		t.Errorf("Generate(two 6.x) error = %v, want a same-major error", err)
	}
	if _, err := Generate([]Version{{Ref: "main", Schemas: sample()}}); err == nil {
		t.Error("Generate(ref main): want an error")
	}
	if _, err := Generate(nil); err == nil {
		t.Error("Generate(nil): want an error")
	}
}

// TestDecode_RejectsUnknownProvider checks that a providers mark naming a
// major version the refs lack is an error rather than a silent drop.
func TestDecode_RejectsUnknownProvider(t *testing.T) {
	_, err := Decode([]byte(`{"format": 2, "refs": {"6": "v6.1.0"}, "resources": {
		"aws_widget": {"ops": {"create": [{"action":"demo:CreateWidget","providers":["7"]}]}}}}`))
	if err == nil || !strings.Contains(err.Error(), `"7"`) {
		t.Errorf("Decode error = %v, want one naming provider 7", err)
	}
	_, err = Decode([]byte(`{"format": 2, "refs": {"6": "v5.1.0"}, "resources": {}}`))
	if err == nil {
		t.Error("Decode(refs 6 = v5.1.0): want an error")
	}
}

// TestProvider_At checks that a Provider serves the version At names, and
// the newest by default.
func TestProvider_At(t *testing.T) {
	data, err := Generate(twoVersions())
	if err != nil {
		t.Fatal(err)
	}
	p := newProvider(data)
	if _, err := p.Resolve("aws_new_gizmo"); err != nil {
		t.Errorf("newest: Resolve(aws_new_gizmo): %v", err)
	}
	if _, err := p.Resolve("aws_old_gadget"); err == nil {
		t.Error("newest: Resolve(aws_old_gadget): want an error")
	}
	old := p.At("v5.9.0")
	if _, err := old.Resolve("aws_old_gadget"); err != nil {
		t.Errorf("v5.9.0: Resolve(aws_old_gadget): %v", err)
	}
	s, err := old.Resolve("aws_widget")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Actions("create"); !reflect.DeepEqual(got, []string{"demo:CreateWidget", "demo:PutWidgetPolicy", "demo:DescribeWidget"}) {
		t.Errorf("v5.9.0 create = %v", got)
	}
	if _, ok := s.Requirements("list"); ok {
		t.Error("v5.9.0 knows list, which only v6.1.0 has")
	}
	if ref, err := old.Ref(); err != nil || ref != "v5.9.0" {
		t.Errorf("Ref = %q, %v", ref, err)
	}
}
