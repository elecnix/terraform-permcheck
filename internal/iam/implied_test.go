package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// impliedMissing checks only the requirements AWS implies for rc, with no
// filter, the way Validate checks them.
func impliedMissing(rc *plan.ResourceChange, policy *policy.Document, set *changeSet, strict bool) []MissingAction {
	return checkChange(rc, impliedRequirements(rc, set), policy, false, nil, FilterConfig{StrictResources: strict})
}

// TestCheckChange_VerdictReadsRunningPaths checks that only the paths whose
// gate holds decide coverage. A path the change does not take cannot make
// its targets missing.
func TestCheckChange_VerdictReadsRunningPaths(t *testing.T) {
	rc := &plan.ResourceChange{
		Type: "aws_example", Name: "e", Change: "create",
		Attributes: map[string]bool{"used": true},
	}
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/used"}]}`)
	reqs := []targeted{
		{Requirement: Requirement{Action: "iam:PassRole", Gate: Gate{Attribute: "used"}}, targets: [][]string{{"arn:*:iam::*:role/used"}}},
		{Requirement: Requirement{Action: "iam:PassRole", Gate: Gate{Attribute: "unset"}}, targets: [][]string{{"arn:*:iam::*:role/other"}}},
	}
	if m := checkChange(rc, reqs, policy, false, nil, FilterConfig{}); len(m) != 0 {
		t.Errorf("a path the change does not take must not decide coverage, got %+v", m)
	}
	rc.Attributes["unset"] = true
	if m := checkChange(rc, reqs, policy, false, nil, FilterConfig{}); len(m) != 1 {
		t.Errorf("each path the change takes must be covered, got %+v", m)
	}
}
