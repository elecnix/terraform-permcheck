package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

func scanningConfigChange(change string, values map[string]string) *plan.ResourceChange {
	return &plan.ResourceChange{
		Type: "aws_ecr_registry_scanning_configuration", Name: "this", Change: change,
		AttributeValues: values,
	}
}

func TestValueRequirement_EnhancedScanningNeedsListAccountPermissions(t *testing.T) {
	for _, change := range []string{"create", "update"} {
		rc := scanningConfigChange(change, map[string]string{"scan_type": "ENHANCED"})
		m := impliedMissing(rc, grantActions("ecr:*"), nil, false)
		if !hasActionOn(m, "inspector2:ListAccountPermissions", "aws_ecr_registry_scanning_configuration", "this") {
			t.Errorf("%s: expected inspector2:ListAccountPermissions missing, got %+v", change, m)
		}
	}
}

func TestValueRequirement_BasicScanningNeedsNothing(t *testing.T) {
	for _, change := range []string{"create", "update", "delete"} {
		rc := scanningConfigChange(change, map[string]string{"scan_type": "BASIC"})
		if m := impliedMissing(rc, grantNothing(), nil, false); len(m) != 0 {
			t.Errorf("%s: BASIC must not need an Inspector action, got %+v", change, m)
		}
	}
}

func TestValueRequirement_DeleteNeedsNothing(t *testing.T) {
	// A delete reverts the registry to BASIC, whatever the prior scan_type.
	rc := scanningConfigChange("delete", map[string]string{"scan_type": "ENHANCED"})
	if m := impliedMissing(rc, grantNothing(), nil, false); len(m) != 0 {
		t.Errorf("delete must not need an Inspector action, got %+v", m)
	}
}

func TestValueRequirement_UnknownScanTypeStaysReported(t *testing.T) {
	rc := scanningConfigChange("create", map[string]string{})
	m := impliedMissing(rc, grantNothing(), nil, false)
	if !hasActionOn(m, "inspector2:ListAccountPermissions", "aws_ecr_registry_scanning_configuration", "this") {
		t.Errorf("an unknown scan_type may be ENHANCED, so the action stays required, got %+v", m)
	}
}

func TestValueRequirement_Covered(t *testing.T) {
	doc := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"inspector2:ListAccountPermissions","Resource":"*"}]}`)
	rc := scanningConfigChange("create", map[string]string{"scan_type": "ENHANCED"})
	if m := impliedMissing(rc, doc, nil, false); len(m) != 0 {
		t.Errorf("expected covered, got %+v", m)
	}
}
