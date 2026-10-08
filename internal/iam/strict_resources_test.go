package iam

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// lambdaCreateResolver requires one action of a type with no target rule.
var lambdaCreateResolver = fakeResolver{actionsSchema(map[string][]string{
	"create": {"lambda:CreateFunction"},
})}

func lambdaFunctionChange() []*plan.ResourceChange {
	return []*plan.ResourceChange{{Type: "aws_lambda_function", Name: "fn", Change: "create"}}
}

func strictFilter() FilterConfig { return FilterConfig{StrictResources: true} }

func unverifiedOn(missing []MissingAction, action, resType string) bool {
	for _, m := range missing {
		if m.Action == action && m.ResourceType == resType && m.ResourceScopeUnverified {
			return true
		}
	}
	return false
}

func TestValidate_StrictScopedGrantWithoutRuleIsUnverified(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"arn:aws:lambda:*:*:function:app-*"}]}`)

	missing, err := Validate(lambdaFunctionChange(), policy, lambdaCreateResolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("without strict mode a scoped grant covers, got %+v", missing)
	}

	missing, err = Validate(lambdaFunctionChange(), policy, lambdaCreateResolver, strictFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || !unverifiedOn(missing, "lambda:CreateFunction", "aws_lambda_function") {
		t.Fatalf("strict mode must report the scoped grant unverified, got %+v", missing)
	}
	if missing[0].Class != "[required]" {
		t.Errorf("class = %q, want [required]", missing[0].Class)
	}
}

func TestValidate_StrictWildcardResourceIsCovered(t *testing.T) {
	for name, doc := range map[string]string{
		"star": `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":"lambda:*","Resource":"*"}]}`,
		"arn star": `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":"lambda:*","Resource":"arn:*"}]}`,
		"one unscoped statement among scoped ones": `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"arn:aws:lambda:*:*:function:app-*"},
			{"Effect":"Allow","Action":"lambda:*","Resource":["arn:aws:lambda:*:*:function:x","*"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			missing, err := Validate(lambdaFunctionChange(), mustPolicy(t, doc), lambdaCreateResolver, strictFilter())
			if err != nil {
				t.Fatal(err)
			}
			if len(missing) != 0 {
				t.Errorf("a grant on every resource covers in strict mode, got %+v", missing)
			}
		})
	}
}

func TestValidate_StrictNotResourceGrantIsUnverified(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"lambda:*","NotResource":"arn:aws:lambda:*:*:function:prod-*"}]}`)
	missing, err := Validate(lambdaFunctionChange(), policy, lambdaCreateResolver, strictFilter())
	if err != nil {
		t.Fatal(err)
	}
	if !unverifiedOn(missing, "lambda:CreateFunction", "aws_lambda_function") {
		t.Errorf("a NotResource grant depends on the target, want unverified, got %+v", missing)
	}
}

func TestValidate_StrictUngrantedActionStaysMissing(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b"}]}`)
	missing, err := Validate(lambdaFunctionChange(), policy, lambdaCreateResolver, strictFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].ResourceScopeUnverified {
		t.Errorf("an action the policy never grants is missing, not unverified, got %+v", missing)
	}
}

func TestValidate_StrictDerivedTargetIsChecked(t *testing.T) {
	resolver := fakeResolver{actionsSchema(map[string][]string{"create": {"sqs:CreateQueue"}})}
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs:us-east-1:111122223333:orders"}]}`)

	known := []*plan.ResourceChange{{
		Type: "aws_sqs_queue", Name: "q", Change: "create",
		AttributeValues: map[string]string{"name": "orders"},
	}}
	missing, err := Validate(known, policy, resolver, strictFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("a grant checked against the derived target covers, got %+v", missing)
	}

	// The rule exists, but the name is computed at apply time.
	unknown := []*plan.ResourceChange{{Type: "aws_sqs_queue", Name: "q", Change: "create"}}
	missing, err = Validate(unknown, policy, resolver, strictFilter())
	if err != nil {
		t.Fatal(err)
	}
	if !unverifiedOn(missing, "sqs:CreateQueue", "aws_sqs_queue") {
		t.Errorf("an underivable target with a scoped grant is unverified, got %+v", missing)
	}
}

func TestValidate_StrictKeepsOtherFilters(t *testing.T) {
	resolver := fakeResolver{actionsSchema(map[string][]string{"create": {"sqs:SendMessage"}})}
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs:*:*:x"}]}`)
	filter := DefaultFilter()
	filter.StrictResources = true
	missing, err := Validate([]*plan.ResourceChange{{Type: "aws_sqs_queue", Name: "q", Change: "create"}}, policy, resolver, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("the data-plane filter still applies in strict mode, got %+v", missing)
	}
}

func TestPassRoleMissing_StrictUnknownRole(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/app-*"}]}`)
	// The role ARN is computed at apply time from an unmanaged expression.
	rc := &plan.ResourceChange{
		Type: "aws_lambda_function", Name: "fn", Change: "create",
		Attributes: map[string]bool{"role": false},
		References: map[string][]string{"role": {"data.aws_iam_role.app.arn", "data.aws_iam_role.app"}},
	}

	if m := passRoleMissing(rc, policy, nil, false); len(m) != 0 {
		t.Errorf("without strict mode an unknown role is skipped, got %+v", m)
	}
	m := passRoleMissing(rc, policy, nil, true)
	if len(m) != 1 || !m[0].ResourceScopeUnverified || m[0].Action != "iam:PassRole" {
		t.Errorf("strict mode must report PassRole unverified, got %+v", m)
	}

	// A resource that does not set the attribute passes no role.
	unset := &plan.ResourceChange{
		Type: "aws_ecs_task_definition", Name: "td", Change: "create",
		Attributes: map[string]bool{"family": true},
	}
	if m := passRoleMissing(unset, policy, nil, true); len(m) != 0 {
		t.Errorf("an unset role attribute needs no PassRole, got %+v", m)
	}

	star := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`)
	if m := passRoleMissing(rc, star, nil, true); len(m) != 0 {
		t.Errorf("a PassRole grant on every role covers, got %+v", m)
	}
}

func TestCrossServiceMissing_StrictScopedCallback(t *testing.T) {
	rc := &plan.ResourceChange{
		Type: "aws_wafv2_web_acl_association", Name: "a", Change: "create",
		AttributeValues: map[string]string{"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/1"},
	}
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"elasticloadbalancing:SetWebACL","Resource":"arn:aws:elasticloadbalancing:*:*:loadbalancer/app/other/*"}]}`)

	if m := crossServiceMissing(rc, policy, false); len(m) != 0 {
		t.Errorf("without strict mode the callback is covered, got %+v", m)
	}
	m := crossServiceMissing(rc, policy, true)
	if len(m) != 1 || !m[0].ResourceScopeUnverified {
		t.Errorf("strict mode must report the scoped callback unverified, got %+v", m)
	}
}

func TestFormatMissing_UnverifiedSection(t *testing.T) {
	missing := []MissingAction{
		{ResourceType: "aws_s3_bucket", ResourceName: "b", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
		{ResourceType: "aws_lambda_function", ResourceName: "fn", Change: "create", Action: "lambda:CreateFunction", Class: "[required]", ResourceScopeUnverified: true},
	}
	out := FormatMissing(missing, nil)
	if !strings.Contains(out, "Missing IAM permissions (1):\n  s3:CreateBucket [required]\n") {
		t.Errorf("missing section wrong:\n%s", out)
	}
	if !strings.Contains(out, "Unverified IAM permissions (1)") ||
		!strings.Contains(out, "  lambda:CreateFunction [required] [unverified: resource scope]\n    → aws_lambda_function.fn (create)") {
		t.Errorf("unverified section wrong:\n%s", out)
	}
	if got := UnverifiedCount(missing); got != 1 {
		t.Errorf("UnverifiedCount = %d, want 1", got)
	}
	if got := DistinctCount(missing); got != 2 {
		t.Errorf("DistinctCount = %d, want 2", got)
	}

	only := FormatMissing(missing[1:], nil)
	if strings.Contains(only, "Missing IAM permissions") {
		t.Errorf("no missing section expected when every finding is unverified:\n%s", only)
	}
}

func TestFormatGitHubAnnotations_Unverified(t *testing.T) {
	out := FormatGitHubAnnotations([]MissingAction{
		{ResourceType: "aws_lambda_function", ResourceName: "fn", Change: "create", Action: "lambda:CreateFunction", Class: "[required]", ResourceScopeUnverified: true},
	}, nil)
	want := "::warning title=Unverified IAM permission::lambda:CreateFunction [unverified: resource scope] needed by: aws_lambda_function.fn (create)\n"
	if out != want {
		t.Errorf("got  %q\nwant %q", out, want)
	}
}

func TestFormatJSON_Unverified(t *testing.T) {
	out := FormatJSON([]MissingAction{
		{ResourceType: "aws_lambda_function", ResourceName: "fn", Change: "create", Action: "lambda:CreateFunction", Class: "[required]", ResourceScopeUnverified: true},
		{ResourceType: "aws_s3_bucket", ResourceName: "b", Change: "create", Action: "s3:CreateBucket", Class: "[required]"},
	}, nil, 2, "resource changes", nil)
	var res struct {
		Status  string                   `json:"status"`
		Missing []map[string]interface{} `json:"missing"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "gaps_found" {
		t.Errorf("status = %q, want gaps_found", res.Status)
	}
	if res.Missing[0]["unverified"] != "resource_scope" {
		t.Errorf("unverified = %v, want resource_scope", res.Missing[0]["unverified"])
	}
	if _, ok := res.Missing[1]["unverified"]; ok {
		t.Errorf("a plain gap must omit unverified, got %v", res.Missing[1])
	}
}

func TestParseConfig_StrictResources(t *testing.T) {
	c, err := parseConfig([]byte(`{"strict_resources": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.StrictResources {
		t.Error("strict_resources not read from config")
	}
	c, err = parseConfig([]byte(`{"exclude": []}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.StrictResources {
		t.Error("strict_resources must default to false")
	}
}
