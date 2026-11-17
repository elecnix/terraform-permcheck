package check

import (
	"reflect"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/principal"
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

	res, err := Run(in, allowing("ecr:DescribeImages"), Options{
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
	res, err := Run(FromPlan(nil), allowing(), Options{Resolver: fakeResolver{}, Needs: testNeeds})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := needActions(res.Missing); !reflect.DeepEqual(got, []string{"Auth:ecr:GetAuthorizationToken"}) {
		t.Errorf("missing = %v", got)
	}
}

// TestRun_NeedsExcluded verifies config exclusions apply to need findings.
func TestRun_NeedsExcluded(t *testing.T) {
	res, err := Run(FromPlan(nil), allowing(), Options{
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

// mappedPlan has the task role and an inline policy that allows it
// secretsmanager:GetSecretValue.
func mappedPlan(t *testing.T) []*plan.ResourceChange {
	t.Helper()
	changes, err := plan.Parse([]byte(`{"resource_changes": [
		{"address": "aws_iam_role.task", "type": "aws_iam_role", "name": "task",
		 "change": {"actions": ["create"], "after": {"name": "app-task"}, "after_unknown": {"arn": true}}},
		{"address": "aws_iam_role_policy.p", "type": "aws_iam_role_policy", "name": "p",
		 "change": {"actions": ["create"], "after": {"role": "app-task",
			"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"secretsmanager:GetSecretValue\",\"Resource\":\"*\"}]}"},
		 "after_unknown": {}}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

var taskMapped = map[string]principal.Entry{"task": {Address: "aws_iam_role.task"}}

// TestRun_MappedNeeds verifies a mapped need reads the plan's policies and
// not the policy document, and an unmapped need reads the document.
func TestRun_MappedNeeds(t *testing.T) {
	res, err := Run(FromPlan(mappedPlan(t)), allowing("ecr:GetAuthorizationToken"), Options{
		Resolver:   fakeResolver{"aws_iam_role": {}, "aws_iam_role_policy": {}},
		Needs:      testNeeds,
		Principals: taskMapped,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := needActions(res.Missing); len(got) != 0 {
		t.Errorf("missing = %v, want none", got)
	}
	if res.Needs != 2 || len(res.Principals) != 1 || res.Principals[0].Label != "task" || len(res.Principals[0].Sources) != 1 {
		t.Errorf("needs = %d, principals = %+v", res.Needs, res.Principals)
	}

	// The document grants GetSecretValue, but the task role's policies
	// don't grant DescribeImages, so a mapped need on it is missing.
	needs := []iam.Need{{Sid: "Verify", Principal: "task", Actions: []string{"ecr:DescribeImages"}}}
	res, err = Run(FromPlan(mappedPlan(t)), allowing("ecr:DescribeImages"), Options{
		Resolver:   fakeResolver{"aws_iam_role": {}, "aws_iam_role_policy": {}},
		Needs:      needs,
		Principals: taskMapped,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := needActions(res.Missing); !reflect.DeepEqual(got, []string{"Verify:ecr:DescribeImages"}) || res.Missing[0].Principal != "task" {
		t.Errorf("missing = %v, want Verify of task", got)
	}
}

// TestRun_NoPolicySource verifies a run without a policy source checks the
// mapped needs only, and fails when it selects an unmapped need.
func TestRun_NoPolicySource(t *testing.T) {
	opts := Options{Needs: testNeeds[2:], Principals: taskMapped}
	if !MappedOnly(opts) {
		t.Fatal("MappedOnly = false, want true")
	}
	res, err := Run(FromPlan(mappedPlan(t)), nil, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.PlanResourcesSkipped || res.Checked != 0 || len(res.Missing) != 0 {
		t.Errorf("result = %+v, want the resources skipped and no finding", res)
	}

	opts = Options{Needs: testNeeds, Principals: taskMapped}
	if MappedOnly(opts) {
		t.Error("MappedOnly = true with a need without a principal")
	}
	if MappedOnly(Options{Needs: testNeeds[2:]}) {
		t.Error("MappedOnly = true without a principals map")
	}
	if _, err := Run(FromPlan(mappedPlan(t)), nil, opts); err == nil || !strings.Contains(err.Error(), "--policy-file") {
		t.Errorf("Run error = %v, want the policy source usage error", err)
	}
}

// TestRun_MappedNeedInStaticMode verifies static HCL mode rejects a mapped
// need, since it has no plan to read the role's policies from.
func TestRun_MappedNeedInStaticMode(t *testing.T) {
	_, err := Run(FromHCL(nil), allowing(), Options{Needs: testNeeds, Principals: taskMapped})
	if err == nil || !strings.Contains(err.Error(), "static HCL mode") {
		t.Errorf("Run error = %v, want a static mode error", err)
	}
	// An unmapped --principal selects no mapped need, so the run goes on.
	if _, err := Run(FromHCL(nil), allowing(), Options{Needs: testNeeds, Principals: taskMapped, Principal: "deploy", Resolver: fakeResolver{}}); err != nil {
		t.Errorf("Run with an unmapped principal: %v", err)
	}
}
