package check

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

// ErrNoPlanInput marks a validate run with no plan to read: no --plan-file
// and no --terraform-root, and stdin is a terminal or empty.
var ErrNoPlanInput = errors.New("no plan input: provide --plan-file, pipe plan JSON to stdin, or use --terraform-root for static HCL mode")

// Stdin describes the process's stdin to the input rules, so they can be
// tested without one.
type Stdin struct {
	// Terminal is set when stdin is a character device: a terminal, where a
	// read waits for the user to type, or /dev/null, which holds nothing.
	Terminal bool
	// MayHoldPlan is set when stdin is a pipe or a non-empty file. It is
	// unset for a terminal, /dev/null and an empty file. Telling them apart
	// does not read stdin, so an open pipe cannot hang the run.
	MayHoldPlan bool
	// Read reads all of stdin.
	Read func() ([]byte, error)
}

// Sources says where the validate command reads the plan and the policy.
//
// --terraform-root without --plan-file is static HCL mode, whatever stdin
// is: CI runners and parent processes often hand the tool a pipe that
// nobody writes to. --plan-file - reads the plan from stdin. With neither
// flag, the plan comes from stdin.
type Sources struct {
	PlanFile      string // --plan-file; empty or "-" means stdin
	TerraformRoot string // --terraform-root
	Policy        PolicySource
}

// Static reports whether the run is static HCL mode.
func (in Sources) Static() bool {
	return in.PlanFile == "" && in.TerraformRoot != ""
}

// StdinIgnored reports whether static HCL mode ignores a stdin that may
// hold a plan, so the caller can warn that it is not checked.
func (in Sources) StdinIgnored(stdin Stdin) bool {
	return in.Static() && stdin.MayHoldPlan
}

// planFromStdin reports whether the plan comes from stdin.
func (in Sources) planFromStdin() bool {
	return !in.Static() && (in.PlanFile == "" || in.PlanFile == "-")
}

// Validate checks the input rules before anything is read. Without
// --plan-file a terminal stdin is no plan input, and a state read from a
// terminal is no state input. The plan and the state cannot both come from
// stdin, since the second read would find nothing.
func (in Sources) Validate(stdin Stdin) error {
	if err := in.Policy.Validate(in.Static()); err != nil {
		return err
	}
	if in.Static() {
		return nil
	}
	if in.PlanFile == "" && stdin.Terminal {
		return ErrNoPlanInput
	}
	if in.Policy.stateFromStdin() {
		if in.planFromStdin() {
			return fmt.Errorf("the plan and the state cannot both come from stdin; pass --plan-file or --state-file")
		}
		if in.Policy.StateFile == "" && stdin.Terminal {
			return fmt.Errorf("no state input: pass --state-file, or pipe the output of `terraform show -json` for the state to stdin")
		}
	}
	return nil
}

// ReadPlan reads the plan JSON from --plan-file or stdin. An empty stdin is
// ErrNoPlanInput.
func (in Sources) ReadPlan(stdin Stdin) ([]byte, error) {
	if !in.planFromStdin() {
		raw, err := os.ReadFile(in.PlanFile)
		if err != nil {
			return nil, fmt.Errorf("read plan: %w", err)
		}
		return raw, nil
	}
	raw, err := stdin.Read()
	if err != nil {
		return nil, fmt.Errorf("read plan: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, ErrNoPlanInput
	}
	return raw, nil
}
