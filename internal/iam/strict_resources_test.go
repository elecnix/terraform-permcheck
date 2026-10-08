package iam

import (
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
	// The stream makes its own management call, so PutRecords is a side
	// call classed data-plane.
	resolver := fakeResolver{actionsSchema(map[string][]string{"create": {"kinesis:CreateStream", "kinesis:PutRecords"}})}
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"kinesis:*","Resource":"arn:aws:kinesis:*:*:stream/x"}]}`)
	filter := DefaultFilter()
	filter.StrictResources = true
	missing, err := Validate([]*plan.ResourceChange{{Type: "aws_kinesis_stream", Name: "s", Change: "create"}}, policy, resolver, filter)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range missing {
		if m.Action == "kinesis:PutRecords" {
			t.Errorf("the data-plane filter still applies in strict mode, got %+v", m)
		}
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

	if m := impliedMissing(rc, policy, nil, false); len(m) != 0 {
		t.Errorf("without strict mode an unknown role is skipped, got %+v", m)
	}
	m := impliedMissing(rc, policy, nil, true)
	if len(m) != 1 || !m[0].ResourceScopeUnverified || m[0].Action != "iam:PassRole" {
		t.Errorf("strict mode must report PassRole unverified, got %+v", m)
	}

	// A resource that does not set the attribute passes no role.
	unset := &plan.ResourceChange{
		Type: "aws_ecs_task_definition", Name: "td", Change: "create",
		Attributes: map[string]bool{"family": true},
	}
	if m := impliedMissing(unset, policy, nil, true); len(m) != 0 {
		t.Errorf("an unset role attribute needs no PassRole, got %+v", m)
	}

	star := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`)
	if m := impliedMissing(rc, star, nil, true); len(m) != 0 {
		t.Errorf("a PassRole grant on every role covers, got %+v", m)
	}
}

func TestCrossServiceMissing_StrictScopedCallback(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"elasticloadbalancing:SetWebACL","Resource":"arn:aws:elasticloadbalancing:*:*:loadbalancer/app/other/*"}]}`)

	// The target is unknown, so the scoped grant may apply.
	unknown := &plan.ResourceChange{Type: "aws_wafv2_web_acl_association", Name: "a", Change: "create"}
	if hasAction(impliedMissing(unknown, policy, nil, false), "elasticloadbalancing:SetWebACL") {
		t.Error("without strict mode the scoped grant covers a callback on an unknown target")
	}
	var found bool
	for _, m := range impliedMissing(unknown, policy, nil, true) {
		if m.Action == "elasticloadbalancing:SetWebACL" {
			found = true
			if !m.ResourceScopeUnverified {
				t.Errorf("strict mode must report the scoped callback unverified, got %+v", m)
			}
		}
	}
	if !found {
		t.Error("strict mode must report the scoped callback on an unknown target")
	}

	// The target is known and the grant names another load balancer, so the
	// callback is missing in both modes.
	known := &plan.ResourceChange{
		Type: "aws_wafv2_web_acl_association", Name: "a", Change: "create",
		AttributeValues: map[string]string{"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/1"},
	}
	for _, strict := range []bool{false, true} {
		m := impliedMissing(known, policy, nil, strict)
		if len(m) != 1 || m[0].ResourceScopeUnverified {
			t.Errorf("strict=%v: a grant on another load balancer must be missing, got %+v", strict, m)
		}
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
