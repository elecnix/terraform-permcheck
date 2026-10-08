package check

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pipe is a stdin that is a pipe holding content.
func pipe(content string) Stdin {
	return Stdin{MayHoldPlan: true, Read: func() ([]byte, error) { return []byte(content), nil }}
}

// terminal is a stdin that is a terminal. Reading it fails the test, since
// the read would wait for the user to type.
func terminal(t *testing.T) Stdin {
	return Stdin{Terminal: true, Read: func() ([]byte, error) { t.Fatal("read a terminal"); return nil, nil }}
}

func TestSources_Static(t *testing.T) {
	cases := []struct {
		in   Sources
		want bool
	}{
		{Sources{TerraformRoot: "."}, true},
		{Sources{TerraformRoot: ".", PlanFile: "-"}, false},
		{Sources{TerraformRoot: ".", PlanFile: "plan.json"}, false},
		{Sources{}, false},
		{Sources{PlanFile: "plan.json"}, false},
	}
	for _, c := range cases {
		if got := c.in.Static(); got != c.want {
			t.Errorf("%+v.Static() = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestSources_StdinIgnored checks that static HCL mode reports a stdin that
// may hold a plan, so the caller can warn that it is ignored.
func TestSources_StdinIgnored(t *testing.T) {
	static := Sources{TerraformRoot: "."}
	if !static.StdinIgnored(pipe("")) {
		t.Error("static mode with a pipe: want ignored")
	}
	if static.StdinIgnored(Stdin{}) {
		t.Error("static mode with /dev/null or an empty file: want not ignored")
	}
	if (Sources{PlanFile: "-", TerraformRoot: "."}).StdinIgnored(pipe("")) {
		t.Error("--plan-file -: want not ignored")
	}
}

func TestSources_Validate(t *testing.T) {
	file := PolicySource{File: "p.json"}
	cases := []struct {
		name  string
		in    Sources
		stdin Stdin
		err   string
	}{
		{"plan from pipe", Sources{Policy: file}, pipe("{}"), ""},
		{"plan from terminal", Sources{Policy: file}, terminal(t), "no plan input"},
		{"plan file", Sources{PlanFile: "plan.json", Policy: file}, terminal(t), ""},
		{"dash from terminal", Sources{PlanFile: "-", Policy: file}, terminal(t), ""},
		{"static ignores stdin", Sources{TerraformRoot: ".", Policy: file}, terminal(t), ""},
		{"static plan output", Sources{TerraformRoot: ".", Policy: PolicySource{PlanOutput: "p"}}, Stdin{}, "not applicable in static HCL mode"},
		{"no policy", Sources{PlanFile: "plan.json"}, Stdin{}, "is required"},
		{"plan and state from stdin", Sources{PlanFile: "-", Policy: PolicySource{StateOutput: "p"}}, pipe("{}"), "cannot both come from stdin"},
		{"plan and state dash", Sources{Policy: PolicySource{StateOutput: "p", StateFile: "-"}}, pipe("{}"), "cannot both come from stdin"},
		{"state from stdin", Sources{PlanFile: "plan.json", Policy: PolicySource{StateOutput: "p"}}, pipe("{}"), ""},
		{"state from terminal", Sources{PlanFile: "plan.json", Policy: PolicySource{StateOutput: "p"}}, terminal(t), "no state input"},
		{"state dash from terminal", Sources{PlanFile: "plan.json", Policy: PolicySource{StateOutput: "p", StateFile: "-"}}, terminal(t), ""},
	}
	for _, c := range cases {
		err := c.in.Validate(c.stdin)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want one containing %q", c.name, err, c.err)
		}
	}
}

func TestSources_ReadPlan(t *testing.T) {
	file := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(file, []byte(`{"from":"file"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		in    Sources
		stdin Stdin
		want  string
		err   error
	}{
		{"file", Sources{PlanFile: file}, terminal(t), `{"from":"file"}`, nil},
		{"dash", Sources{PlanFile: "-"}, pipe(`{"from":"stdin"}`), `{"from":"stdin"}`, nil},
		{"default stdin", Sources{}, pipe(`{"from":"stdin"}`), `{"from":"stdin"}`, nil},
		{"empty stdin", Sources{}, pipe(" \n"), "", ErrNoPlanInput},
		{"empty dash", Sources{PlanFile: "-"}, pipe(""), "", ErrNoPlanInput},
	}
	for _, c := range cases {
		got, err := c.in.ReadPlan(c.stdin)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%s: error %v, want %v", c.name, err, c.err)
			}
			continue
		}
		if err != nil || string(got) != c.want {
			t.Errorf("%s: ReadPlan = %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

// TestPolicySource_LoadStateDash checks that --state-file - reads the state
// from stdin.
func TestPolicySource_LoadStateDash(t *testing.T) {
	read := func() ([]byte, error) { return []byte(`{"outputs":{"p":{"value":{"Statement":[]}}}}`), nil }
	got, err := (PolicySource{StateOutput: "p", StateFile: "-"}).Load(nil, read)
	if err != nil || strings.ReplaceAll(string(got), " ", "") != `{"Statement":[]}` {
		t.Errorf("Load = %s, %v", got, err)
	}
}
