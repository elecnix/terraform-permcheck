package iam

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

const queueARN = "arn:aws:sqs:us-east-1:111122223333:example-queue"

// queueTargets is the target pattern sqsQueueTargetARNs derives for a queue
// named example-queue.
var queueTargets = []string{"arn:*:sqs:*:*:example-queue"}

func TestMatchesWildcard_Globs(t *testing.T) {
	tests := []struct {
		pattern string
		action  string
		match   bool
	}{
		{"secretsmanager:*SecretValue", "secretsmanager:PutSecretValue", true},
		{"secretsmanager:*SecretValue", "secretsmanager:GetSecretValue", true},
		{"secretsmanager:*SecretValue", "secretsmanager:DeleteSecret", false},
		{"s3:Get*Tagging", "s3:GetBucketTagging", true},
		{"s3:Get*Tagging", "s3:GetBucketPolicy", false},
		{"sqs:?etQueueAttributes", "sqs:GetQueueAttributes", true},
		{"sqs:?etQueueAttributes", "sqs:SetQueueAttributes", true},
		{"sqs:?QueueAttributes", "sqs:GetQueueAttributes", false},
		{"*:List*", "sqs:ListQueues", true},
		// IAM action names are case-insensitive.
		{"SQS:sendmessage", "sqs:SendMessage", true},
		{"sqs:send*", "sqs:SendMessage", true},
		{"Backup:*", "backup:CreateBackupVault", true},
	}
	for _, tt := range tests {
		if got := matchesWildcard(tt.pattern, tt.action); got != tt.match {
			t.Errorf("matchesWildcard(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.match)
		}
	}
}

func TestGlobContains(t *testing.T) {
	tests := []struct {
		outer, inner string
		want         bool
	}{
		{"*", "arn:*:sqs:*:*:q", true},
		{"arn:*:sqs:*:*:q", "arn:*:sqs:*:*:q", true},
		{"arn:aws:sqs:*:*:q", "arn:*:sqs:*:*:q", false},
		{"arn:*:sqs:*:*:*", "arn:*:sqs:*:*:q", true},
		// '?' matches exactly one character, so it cannot contain a '*'.
		{"a?c", "a*c", false},
		{"a?c", "a?c", true},
		{"a*", "a?", true},
		// Resource ARNs are case-sensitive.
		{"arn:*:sqs:*:*:Q", "arn:*:sqs:*:*:q", false},
	}
	for _, tt := range tests {
		if got := globContains(tt.outer, tt.inner); got != tt.want {
			t.Errorf("globContains(%q, %q) = %v, want %v", tt.outer, tt.inner, got, tt.want)
		}
	}
}

func TestParsePolicy_StatementObject(t *testing.T) {
	doc := mustPolicy(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*"}}`)
	if !doc.Covers("sqs:SendMessage") {
		t.Error("a single-object Statement must be read as one statement")
	}
}

func TestParsePolicy_RejectsUnknownEffect(t *testing.T) {
	// AWS treats Effect as case-sensitive and rejects any other value.
	for _, effect := range []string{"allow", "DENY", "", "Permit"} {
		raw := `{"Statement":[{"Effect":"` + effect + `","Action":"*","Resource":"*"}]}`
		if _, err := ParsePolicy([]byte(raw)); err == nil {
			t.Errorf("Effect %q: expected a parse error", effect)
		}
	}
}

func TestCovers_DenyOverridesAllow(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"*"}]}`)
	if doc.Covers("sqs:SendMessage") {
		t.Error("Deny sqs:* on every resource must override Allow sqs:*")
	}
	if doc.CoversTarget("sqs:SendMessage", queueTargets) {
		t.Error("Deny sqs:* on every resource must override a resource-scoped Allow")
	}
}

func TestCovers_DenyMatchesGlobCaseInsensitively(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"SQS:Send*","Resource":"*"}]}`)
	if doc.Covers("sqs:SendMessage") {
		t.Error("Deny SQS:Send* must deny sqs:SendMessage")
	}
	if !doc.Covers("sqs:ReceiveMessage") {
		t.Error("Deny SQS:Send* must not deny sqs:ReceiveMessage")
	}
}

func TestCovers_DenyScopedToResourceIsNotDefiniteWithoutTarget(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"`+queueARN+`"}]}`)
	// The target is unknown, so the Deny might not apply to it.
	if !doc.Covers("sqs:SendMessage") {
		t.Error("a resource-scoped Deny must not deny when the target is unknown")
	}
}

func TestCoversTarget_DenyOnOtherResource(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"arn:*:sqs:*:*:other-queue"}]}`)
	if !doc.CoversTarget("sqs:SendMessage", queueTargets) {
		t.Error("a Deny on another queue must not deny example-queue")
	}
}

func TestCoversTarget_DenyOnTarget(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"arn:*:sqs:*:*:example-*"}]}`)
	if doc.CoversTarget("sqs:SendMessage", queueTargets) {
		t.Error("a Deny whose Resource contains the target must deny it")
	}
	if !doc.CoversTarget("sqs:ReceiveMessage", queueTargets) {
		t.Error("the Deny names only sqs:SendMessage")
	}
}

func TestCoversTarget_DenyNarrowerThanTargetIsNotDefinite(t *testing.T) {
	// The target pattern spans every region and account; a Deny on one
	// region cannot prove the queue is denied.
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"`+queueARN+`"}]}`)
	if !doc.CoversTarget("sqs:SendMessage", queueTargets) {
		t.Error("a Deny that only overlaps the target must not count as definite")
	}
}

func TestCovers_ConditionalDenyIsNotDefinite(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"*",
		 "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`)
	if !doc.Covers("sqs:SendMessage") {
		t.Error("a Deny with a Condition must not count as a definite deny")
	}
	if !doc.CoversTarget("sqs:SendMessage", queueTargets) {
		t.Error("a Deny with a Condition must not count as a definite deny on a target")
	}
}

func TestCovers_EmptyConditionDenyIsDefinite(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"*","Condition":{}}]}`)
	if doc.Covers("sqs:SendMessage") {
		t.Error("an empty Condition block places no condition on the Deny")
	}
}

func TestCovers_ConditionalAllowCovers(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*",
		 "Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
	if !doc.Covers("sqs:SendMessage") {
		t.Error("an Allow with a Condition still counts as covering")
	}
}

func TestCovers_NotActionAllow(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}]}`)
	if !doc.Covers("sqs:SendMessage") {
		t.Error("NotAction iam:* must allow sqs:SendMessage")
	}
	if doc.Covers("iam:CreateRole") {
		t.Error("NotAction iam:* must not allow iam:CreateRole")
	}
	if doc.Covers("IAM:CreateRole") {
		t.Error("NotAction matching must be case-insensitive")
	}
}

func TestCovers_NotActionDeny(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","NotAction":"sqs:*","Resource":"*"}]}`)
	if !doc.Covers("sqs:SendMessage") {
		t.Error("Deny NotAction sqs:* must leave sqs actions allowed")
	}
	if doc.Covers("s3:PutObject") {
		t.Error("Deny NotAction sqs:* must deny s3:PutObject")
	}
}

func TestCoversTarget_NotResourceAllow(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"sqs:*","NotResource":"arn:*:sqs:*:*:secret-queue"}]}`)
	if !doc.CoversTarget("sqs:SendMessage", queueTargets) {
		t.Error("NotResource must allow a target outside the list")
	}
	if doc.CoversTarget("sqs:SendMessage", []string{"arn:*:sqs:*:*:secret-queue"}) {
		t.Error("NotResource must not allow a target inside the list")
	}
	if !doc.Covers("sqs:SendMessage") {
		t.Error("with no known target, a NotResource Allow still covers the action")
	}
}

func TestCoversTarget_NotResourceDeny(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","NotResource":"arn:*:sqs:*:*:app-*"}]}`)
	if doc.CoversTarget("sqs:SendMessage", queueTargets) {
		t.Error("Deny NotResource app-* must deny example-queue")
	}
	if !doc.CoversTarget("sqs:SendMessage", []string{"arn:*:sqs:*:*:app-queue"}) {
		t.Error("Deny NotResource app-* must leave app-queue allowed")
	}
	if !doc.Covers("sqs:SendMessage") {
		t.Error("with no known target, a NotResource Deny is not definite")
	}
}

func TestValidate_AllowPlusDenyReportsMissing(t *testing.T) {
	resolver := fakeResolver{fakeSchema{perms: map[string][]string{
		"create": {"sqs:CreateQueue"},
	}}}
	// No name, so the target is unknown and coverage is action-level.
	changes := []*plan.ResourceChange{{Type: "aws_sqs_queue", Name: "q", Change: "create"}}
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:*","Resource":"*"}]}`)
	missing, err := Validate(changes, doc, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasActionOn(missing, "sqs:CreateQueue", "aws_sqs_queue", "q") {
		t.Errorf("expected sqs:CreateQueue missing, got %+v", missing)
	}
}

func TestValidate_DenyOnTargetQueue(t *testing.T) {
	resolver := fakeResolver{fakeSchema{perms: map[string][]string{
		"create": {"sqs:CreateQueue"},
	}}}
	changes := []*plan.ResourceChange{{
		Type: "aws_sqs_queue", Name: "q", Change: "create",
		AttributeValues: map[string]string{"name": "example-queue"},
	}}

	denied := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:CreateQueue","Resource":"arn:*:sqs:*:*:example-*"}]}`)
	missing, err := Validate(changes, denied, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasActionOn(missing, "sqs:CreateQueue", "aws_sqs_queue", "q") {
		t.Errorf("expected sqs:CreateQueue missing, got %+v", missing)
	}

	other := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:CreateQueue","Resource":"arn:*:sqs:*:*:other-*"}]}`)
	missing, err = Validate(changes, other, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("a Deny on another queue must not report, got %+v", missing)
	}
}

func TestValidate_MidStringActionGlobCovers(t *testing.T) {
	resolver := fakeResolver{fakeSchema{perms: map[string][]string{
		"create": {"secretsmanager:PutSecretValue"},
	}}}
	changes := []*plan.ResourceChange{{Type: "aws_secretsmanager_secret_version", Name: "v", Change: "create"}}
	doc := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:*SecretValue","Resource":"*"}]}`)
	missing, err := Validate(changes, doc, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("secretsmanager:*SecretValue must cover PutSecretValue, got %+v", missing)
	}
}

func TestValidate_CrossServiceCallbackHonoursDeny(t *testing.T) {
	resolver := typeKeyedResolver{"aws_wafv2_web_acl_association": fakeSchema{perms: map[string][]string{
		"create": {"wafv2:AssociateWebACL"},
	}}}
	changes := []*plan.ResourceChange{{
		Type: "aws_wafv2_web_acl_association", Name: "this", Change: "create",
		AttributeValues: map[string]string{
			"resource_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188",
		},
	}}
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"elasticloadbalancing:*","Resource":"*"}]}`)
	missing, err := Validate(changes, doc, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(missing, "elasticloadbalancing:SetWebACL") {
		t.Errorf("a Deny on elasticloadbalancing:* must report SetWebACL, got %+v", missing)
	}
	if hasAction(missing, "wafv2:AssociateWebACL") {
		t.Errorf("wafv2:AssociateWebACL is allowed, got %+v", missing)
	}
}

func TestPassRoleMissing_HonoursDeny(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"},
		{"Effect":"Deny","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/deploy"}]}`)
	missing := passRoleMissing(lambdaChange("arn:aws:iam::111122223333:role/deploy"), doc, nil)
	if !hasAction(missing, "iam:PassRole") {
		t.Errorf("a Deny on the passed role must report iam:PassRole, got %+v", missing)
	}
}
