package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

const (
	listByResource = "backup:ListRecoveryPointsByResource"
	listByVault    = "backup:ListRecoveryPointsByBackupVault"
)

func dependentChange() *plan.ResourceChange {
	return &plan.ResourceChange{Type: "aws_example", Name: "e", Change: "create"}
}

// TestDependentActions_NeedFindsMissingDependency is the regression of the
// Backup pair: AWS refuses ListRecoveryPointsByResource unless the caller
// also holds ListRecoveryPointsByBackupVault.
func TestDependentActions_NeedFindsMissingDependency(t *testing.T) {
	need := []Need{{Sid: "ListBackups", Actions: []string{listByResource}, Resources: []string{"*"}}}

	got := CheckNeeds(need, grantActions(listByResource), false)
	if len(got) != 1 || got[0].Action != listByVault || got[0].DependsOn != listByResource || got[0].Need != "ListBackups" {
		t.Fatalf("want %s missing, depending on %s, got %+v", listByVault, listByResource, got)
	}

	if got := CheckNeeds(need, grantActions(listByResource, listByVault), false); len(got) != 0 {
		t.Errorf("both actions granted, want no finding, got %+v", got)
	}
}

func TestDependentActions_NeedWithoutResources(t *testing.T) {
	need := []Need{{Sid: "ListBackups", Actions: []string{listByResource}}}
	got := CheckNeeds(need, grantActions(listByResource), false)
	if len(got) != 1 || got[0].Action != listByVault {
		t.Fatalf("want %s missing, got %+v", listByVault, got)
	}
}

// A dependency the need lists itself is reported once, on its own.
func TestDependentActions_NeedListingBothReportsOnce(t *testing.T) {
	need := []Need{{Sid: "ListBackups", Actions: []string{listByResource, listByVault}}}
	got := CheckNeeds(need, grantNothing(), false)
	if len(got) != 2 {
		t.Fatalf("want one finding per action, got %+v", got)
	}
	for _, m := range got {
		if m.DependsOn != "" {
			t.Errorf("%s is required on its own, got DependsOn %q", m.Action, m.DependsOn)
		}
	}
}

// A grant of the dependency limited to some resources might cover the call,
// so it is unverified under strict resources and covered otherwise.
func TestDependentActions_ScopedDependencyFollowsCoverageRules(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"`+listByResource+`","Resource":"*"},
		{"Effect":"Allow","Action":"`+listByVault+`","Resource":"arn:aws:backup:us-east-1:111122223333:backup-vault:one"}]}`)
	need := []Need{{Sid: "ListBackups", Actions: []string{listByResource}}}
	if got := CheckNeeds(need, doc, false); len(got) != 0 {
		t.Errorf("a scoped grant of the dependency is not provably missing, got %+v", got)
	}
	got := CheckNeeds(need, doc, true)
	if len(got) != 1 || got[0].Action != listByVault || !got[0].ResourceScopeUnverified {
		t.Errorf("strict: want an unverified %s, got %+v", listByVault, got)
	}
}

func TestDependentActions_ResourceTypeFindsMissingDependency(t *testing.T) {
	reqs := []targeted{{Requirement: Requirement{Action: listByResource}}}
	rc := dependentChange()

	got := checkChange(rc, reqs, grantActions(listByResource), false, nil, FilterConfig{})
	if len(got) != 1 || got[0].Action != listByVault || got[0].DependsOn != listByResource || got[0].ResourceType != "aws_example" {
		t.Fatalf("want %s missing, depending on %s, got %+v", listByVault, listByResource, got)
	}
	if got := checkChange(rc, reqs, grantActions(listByResource, listByVault), false, nil, FilterConfig{}); len(got) != 0 {
		t.Errorf("both actions granted, want no finding, got %+v", got)
	}
}

// A requirement whose gate does not hold does not pull in its dependency.
func TestDependentActions_GatedRequirementNeedsGateForDependency(t *testing.T) {
	reqs := []targeted{{Requirement: Requirement{Action: listByResource, Gate: Gate{Attribute: "used"}}}}
	rc := dependentChange()
	rc.Attributes = map[string]bool{}
	if got := checkChange(rc, reqs, grantNothing(), false, nil, FilterConfig{}); len(got) != 0 {
		t.Errorf("gate does not hold, want no finding, got %+v", got)
	}
	rc.Attributes["used"] = true
	got := checkChange(rc, reqs, grantActions(listByResource), false, nil, FilterConfig{})
	if len(got) != 1 || got[0].Action != listByVault || got[0].ConditionAttribute != "used" {
		t.Errorf("gate holds, want %s carrying the gate, got %+v", listByVault, got)
	}
}

// The dependency follows the class of the action that needs it, so the
// default filter does not hide it while it shows the action.
func TestDependentActions_DependencyFollowsParentFilter(t *testing.T) {
	reqs := []targeted{{Requirement: Requirement{Action: listByResource}}}
	got := checkChange(dependentChange(), reqs, grantActions(listByResource), true, nil, DefaultFilter())
	if len(got) != 1 || got[0].Class != ClassManagement {
		t.Errorf("want the dependency kept with its parent's class, got %+v", got)
	}
}

func TestDependentActions_TableIsWellFormed(t *testing.T) {
	for action, deps := range dependentActions {
		if len(deps) == 0 {
			t.Errorf("%s: empty row", action)
		}
		for _, d := range deps {
			if d.action == "" || d.evidence == "" {
				t.Errorf("%s: dependency %+v needs an action and an evidence note", action, d)
			}
			if d.action == action {
				t.Errorf("%s depends on itself", action)
			}
		}
	}
}

// A dependent action the type lists only behind a gate that does not hold is
// not required on its own, so the parent still pulls it in.
func TestDependentActions_UnrequiredListingDoesNotSuppressDependency(t *testing.T) {
	reqs := []targeted{
		{Requirement: Requirement{Action: listByResource}},
		{Requirement: Requirement{Action: listByVault, Gate: Gate{Attribute: "unset"}}},
	}
	rc := dependentChange()
	rc.Attributes = map[string]bool{}
	got := checkChange(rc, reqs, grantActions(listByResource), false, nil, FilterConfig{})
	if len(got) != 1 || got[0].Action != listByVault || got[0].DependsOn != listByResource {
		t.Errorf("want %s reported as a dependency, got %+v", listByVault, got)
	}
}

// A dependent action the type lists, but the conditional filter drops, is not
// reported on its own, so the parent reports it.
func TestDependentActions_ConditionalFilterDoesNotHideDependency(t *testing.T) {
	reqs := []targeted{
		{Requirement: Requirement{Action: listByResource}},
		{Requirement: Requirement{Action: listByVault, Gate: Gate{Attribute: "used"}}},
	}
	rc := dependentChange()
	rc.Attributes = map[string]bool{"used": true}
	got := checkChange(rc, reqs, grantActions(listByResource), false, nil, FilterConfig{ExcludeConditional: true})
	if len(got) != 1 || got[0].Action != listByVault || got[0].DependsOn != listByResource {
		t.Errorf("want %s reported as a dependency, got %+v", listByVault, got)
	}
}

// The same holds when the class filter drops the directly listed action,
// whose class the filter excludes.
func TestDependentActions_ClassFilterDoesNotHideDependency(t *testing.T) {
	for _, c := range []struct {
		name   string
		filter FilterConfig
		class  Class
	}{
		{"data-plane", FilterConfig{ExcludeDataPlane: true}, ClassDataPlane},
		{"optional", FilterConfig{ExcludeOptional: true}, ClassOptional},
	} {
		parent, dep := "x:Parent", "x:Dependent"
		saved := dependentActions
		dependentActions = map[string][]dependentAction{parent: {{action: dep, evidence: "test"}}}
		ruleIndex[dep] = rule{class: c.class}
		reqs := []targeted{{Requirement: Requirement{Action: parent}}, {Requirement: Requirement{Action: dep}}}
		got := checkChange(dependentChange(), reqs, grantActions(parent), false, nil, c.filter)
		delete(ruleIndex, dep)
		dependentActions = saved
		if len(got) != 1 || got[0].Action != dep || got[0].DependsOn != parent {
			t.Errorf("%s: want %s reported as a dependency, got %+v", c.name, dep, got)
		}
	}
}
