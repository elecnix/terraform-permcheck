package check

import (
	"reflect"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

var testNeeds = []iam.Need{
	{Sid: "Auth", Actions: []string{"ecr:GetAuthorizationToken"}, Resources: []string{"*"}},
	{Sid: "Verify", Principal: "deploy", Actions: []string{"ecr:DescribeImages"}},
	{Sid: "Secrets", Principal: "task", Actions: []string{"secretsmanager:GetSecretValue"}},
}

// needActions collapses need findings to "sid:action".
func needActions(missing []iam.MissingAction) []string {
	var out []string
	for _, m := range missing {
		out = append(out, m.Need+":"+m.Action)
	}
	return out
}

// TestRun_NeedsAddFindings verifies the needs the principal selects join the
// resource findings, and the result counts them.
func TestRun_NeedsAddFindings(t *testing.T) {
	in := FromPlan([]*plan.ResourceChange{{Type: "aws_kms_key", Name: "a", Change: "delete"}})

	res, err := Run(in, policy("ecr:DescribeImages"), Options{
		Resolver:  fakeResolver{"aws_kms_key": kmsKey},
		Needs:     testNeeds,
		Principal: "deploy",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{":kms:ScheduleKeyDeletion", "Auth:ecr:GetAuthorizationToken"}
	if got := needActions(res.Missing); !reflect.DeepEqual(got, want) {
		t.Errorf("missing = %v, want %v", got, want)
	}
	if res.Needs != 2 {
		t.Errorf("Needs = %d, want 2", res.Needs)
	}
}

// TestRun_NeedsWithEmptyInput verifies needs are checked even when the plan
// has no resource changes, so the policy is loaded.
func TestRun_NeedsWithEmptyInput(t *testing.T) {
	res, err := Run(FromPlan(nil), policy(), Options{Resolver: fakeResolver{}, Needs: testNeeds})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := needActions(res.Missing); !reflect.DeepEqual(got, []string{"Auth:ecr:GetAuthorizationToken"}) {
		t.Errorf("missing = %v", got)
	}
}

// TestRun_NeedsExcluded verifies config exclusions apply to need findings.
func TestRun_NeedsExcluded(t *testing.T) {
	res, err := Run(FromPlan(nil), policy(), Options{
		Resolver:   fakeResolver{},
		Needs:      testNeeds,
		Principal:  "task",
		Exclusions: []iam.Exclusion{{Permission: "secretsmanager:*", Resource: "needs.Secrets"}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := needActions(res.Missing); !reflect.DeepEqual(got, []string{"Auth:ecr:GetAuthorizationToken"}) {
		t.Errorf("missing = %v", got)
	}
	if len(res.Excluded) != 1 || res.Excluded[0].Need != "Secrets" {
		t.Errorf("excluded = %+v", res.Excluded)
	}
}

// TestRun_UnknownPrincipal verifies a principal no need names is an error,
// reported before the policy loads.
func TestRun_UnknownPrincipal(t *testing.T) {
	_, err := Run(FromPlan(nil), noPolicy(t), Options{Resolver: fakeResolver{}, Needs: testNeeds, Principal: "deploi"})
	if err == nil || !strings.Contains(err.Error(), `"deploi"`) {
		t.Errorf("want an unknown principal error, got %v", err)
	}
}
