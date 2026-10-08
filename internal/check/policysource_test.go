package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicySource_Validate(t *testing.T) {
	cases := []struct {
		name   string
		src    PolicySource
		static bool
		err    string
	}{
		{"file", PolicySource{File: "p.json"}, false, ""},
		{"plan output", PolicySource{PlanOutput: "out"}, false, ""},
		{"state output", PolicySource{StateOutput: "out"}, false, ""},
		{"none", PolicySource{}, false, "one of --policy-file, --policy-from-plan-output, or --policy-from-state-output is required"},
		{"two", PolicySource{File: "p.json", PlanOutput: "out"}, false, "only one of"},
		{"static file", PolicySource{File: "p.json"}, true, ""},
		{"static none", PolicySource{}, true, ""},
		{"static plan output", PolicySource{PlanOutput: "out"}, true, "not applicable in static HCL mode"},
		{"static state output", PolicySource{StateOutput: "out"}, true, "not applicable in static HCL mode"},
	}
	for _, c := range cases {
		err := c.src.Validate(c.static)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want one containing %q", c.name, err, c.err)
		}
	}
}

func TestPolicySource_Load(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(file, []byte(`{"Statement":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state.json")
	if err := os.WriteFile(state, []byte(`{"outputs":{"p":{"value":"{\"Statement\":[]}"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := []byte(`{"planned_values":{"outputs":{"p":{"value":{"Statement":[]}}}}}`)
	noStdin := func() ([]byte, error) { t.Fatal("stdin read"); return nil, nil }

	for name, src := range map[string]PolicySource{
		"file":         {File: file},
		"plan output":  {PlanOutput: "p"},
		"state output": {StateOutput: "p", StateFile: state},
	} {
		got, err := src.Load(plan, noStdin)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.ReplaceAll(string(got), " ", "") != `{"Statement":[]}` {
			t.Errorf("%s: got %s", name, got)
		}
	}

	if _, err := (PolicySource{File: filepath.Join(dir, "absent.json")}).Load(nil, noStdin); err == nil || !strings.HasPrefix(err.Error(), "read policy: ") {
		t.Errorf("absent file: error %v, want a read policy error", err)
	}
}

func TestCloudPrefix(t *testing.T) {
	if p, err := CloudPrefix("aws"); err != nil || p != "aws_" {
		t.Errorf("CloudPrefix(aws) = %q, %v", p, err)
	}
	if _, err := CloudPrefix(""); err == nil || err.Error() != "--cloud is required (supported: aws)" {
		t.Errorf("CloudPrefix(\"\") error = %v", err)
	}
	if _, err := CloudPrefix("gcp"); err == nil || err.Error() != `unsupported cloud "gcp" (supported: aws)` {
		t.Errorf("CloudPrefix(gcp) error = %v", err)
	}
}
