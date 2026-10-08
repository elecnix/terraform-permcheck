package check

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// PolicySource says where the validate command reads the policy: a file, an
// output of the plan, or an output of a state. Exactly one of File,
// PlanOutput and StateOutput is set.
type PolicySource struct {
	File        string // --policy-file
	PlanOutput  string // --policy-from-plan-output
	StateOutput string // --policy-from-state-output
	// StateFile is the state JSON StateOutput reads (--state-file). Empty
	// or "-" means stdin.
	StateFile string
}

// stateFromStdin reports whether the policy comes from a state read from
// stdin.
func (s PolicySource) stateFromStdin() bool {
	return s.StateOutput != "" && (s.StateFile == "" || s.StateFile == "-")
}

// Validate checks the selection rules. Plan mode needs exactly one source.
// Static HCL mode has no plan or state, so only File applies there. Static
// mode reads File only when there is something to check, so it may be
// empty.
func (s PolicySource) Validate(static bool) error {
	if static {
		if s.PlanOutput != "" || s.StateOutput != "" {
			return fmt.Errorf("--policy-from-plan/output not applicable in static HCL mode (no plan available)")
		}
		return nil
	}
	n := 0
	for _, v := range []string{s.File, s.PlanOutput, s.StateOutput} {
		if v != "" {
			n++
		}
	}
	switch {
	case n == 0:
		return fmt.Errorf("one of --policy-file, --policy-from-plan-output, or --policy-from-state-output is required")
	case n > 1:
		return fmt.Errorf("only one of --policy-file, --policy-from-plan-output, or --policy-from-state-output may be specified")
	}
	return nil
}

// Load reads the policy JSON. planRaw is the plan the PlanOutput is read
// from. readStdin reads the state when StateFile is empty or "-". An output
// may hold the policy as a JSON string or as an object.
func (s PolicySource) Load(planRaw []byte, readStdin func() ([]byte, error)) ([]byte, error) {
	switch {
	case s.PlanOutput != "":
		v, err := plan.ParseOutput(planRaw, s.PlanOutput)
		if err != nil {
			return nil, fmt.Errorf("read policy from plan output: %w", err)
		}
		return unwrapJSONString(v), nil
	case s.StateOutput != "":
		var stateRaw []byte
		var err error
		if s.stateFromStdin() {
			stateRaw, err = readStdin()
		} else {
			stateRaw, err = os.ReadFile(s.StateFile)
		}
		if err != nil {
			return nil, fmt.Errorf("read state: %w", err)
		}
		v, err := plan.ParseStateOutput(stateRaw, s.StateOutput)
		if err != nil {
			return nil, fmt.Errorf("read policy from state output: %w", err)
		}
		return unwrapJSONString(v), nil
	default:
		raw, err := os.ReadFile(s.File)
		if err != nil {
			return nil, fmt.Errorf("read policy: %w", err)
		}
		return raw, nil
	}
}

// unwrapJSONString returns the string a JSON string value holds, such as
// the output of jsonencode, or any other value as it is.
func unwrapJSONString(raw json.RawMessage) []byte {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []byte(s)
	}
	return raw
}

// CloudPrefix checks the --cloud name and returns the resource type prefix
// of that cloud. Only aws is supported.
func CloudPrefix(name string) (string, error) {
	switch name {
	case "":
		return "", fmt.Errorf("--cloud is required (supported: aws)")
	case "aws":
		return "aws_", nil
	}
	return "", fmt.Errorf("unsupported cloud %q (supported: aws)", name)
}
