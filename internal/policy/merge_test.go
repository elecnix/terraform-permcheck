package policy

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"testing"
)

const secretARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-AbCdEf"

// secretTargets is the target pattern the iam package derives for a secret
// named app-db.
var secretTargets = []string{"arn:*:secretsmanager:*:*:secret:app-db-??????"}

func TestMerge_NeedCoveredOnlyByTheSecondDocument(t *testing.T) {
	logs := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}`)
	secrets := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"`+secretARN+`"}]}`)

	merged := Merge(logs, secrets)
	for _, strict := range []bool{false, true} {
		got := merged.Coverage("secretsmanager:GetSecretValue", secretTargets, nil, strict)
		if got != (Result{Verdict: Covered}) {
			t.Errorf("strict=%v: Coverage = %+v, want covered", strict, got)
		}
	}
	if got := merged.Coverage("logs:PutLogEvents", nil, nil, true); got != (Result{Verdict: Covered}) {
		t.Errorf("the first document's grant: Coverage = %+v, want covered", got)
	}
}

func TestMerge_UnknownSourceIsUnverifiedUnderStrict(t *testing.T) {
	logs := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"logs:PutLogEvents","Resource":"*"}]}`)
	merged := Merge(logs, UnknownSource())

	if got := merged.Coverage("ssm:GetParameter", []string{"arn:*:ssm:*:*:parameter/app/db"}, nil, false); got != (Result{Verdict: Covered}) {
		t.Errorf("default: Coverage = %+v, want covered", got)
	}
	want := Result{Verdict: Unverified, Reason: ReasonPolicyUnknown}
	if got := merged.Coverage("ssm:GetParameter", []string{"arn:*:ssm:*:*:parameter/app/db"}, nil, true); got != want {
		t.Errorf("strict: Coverage = %+v, want %+v", got, want)
	}
	if got := ReasonPolicyUnknown.Value(); got != "policy_unknown" {
		t.Errorf("ReasonPolicyUnknown.Value() = %q, want policy_unknown", got)
	}
}

// sqsGrant is an identity policy that grants sqs:SendMessage on every queue.
const sqsGrant = `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}`

func TestMerge_DenyInOneDocumentOverridesAllowInAnother(t *testing.T) {
	deny := mustPolicy(t, `{"Statement":[{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}]}`)
	merged := Merge(mustPolicy(t, sqsGrant), deny)

	for _, targets := range [][]string{nil, queueTargets} {
		for _, strict := range []bool{false, true} {
			if got := merged.Coverage("sqs:SendMessage", targets, nil, strict); got.Verdict != Missing {
				t.Errorf("targets=%v strict=%v: Coverage = %+v, want missing", targets, strict, got)
			}
		}
	}
	if got := merged.CoverageOfEveryResource("sqs:SendMessage", false); got.Verdict != Missing {
		t.Errorf("CoverageOfEveryResource = %+v, want missing", got)
	}
}

func TestMerge_ConditionalDenyDoesNotOverride(t *testing.T) {
	deny := mustPolicy(t, `{"Statement":[{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*",
		"Condition":{"StringNotEquals":{"aws:sourceVpce":"vpce-1a2b"}}}]}`)
	merged := Merge(mustPolicy(t, sqsGrant), deny)

	for _, targets := range [][]string{nil, queueTargets} {
		for _, strict := range []bool{false, true} {
			if got := merged.Coverage("sqs:SendMessage", targets, nil, strict); got != (Result{Verdict: Covered}) {
				t.Errorf("targets=%v strict=%v: Coverage = %+v, want covered", targets, strict, got)
			}
		}
	}
}

func TestMerge_UnknownSourceNeverOverridesADefiniteDeny(t *testing.T) {
	deny := mustPolicy(t, `{"Statement":[{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}]}`)
	merged := Merge(UnknownSource(), deny)

	for _, targets := range [][]string{nil, queueTargets} {
		for _, strict := range []bool{false, true} {
			if got := merged.Coverage("sqs:SendMessage", targets, nil, strict); got.Verdict != Missing {
				t.Errorf("targets=%v strict=%v: Coverage = %+v, want missing", targets, strict, got)
			}
		}
	}
	if got := merged.CoverageOfEveryResource("sqs:SendMessage", true); got.Verdict != Missing {
		t.Errorf("CoverageOfEveryResource = %+v, want missing", got)
	}
}

func TestMerge_KnownGrantSettlesTheNeedNextToAnUnknownSource(t *testing.T) {
	scoped := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"`+queueARN+`"}]}`)
	merged := Merge(UnknownSource(), scoped)
	if got := merged.Coverage("sqs:SendMessage", queueTargets, nil, true); got != (Result{Verdict: Covered}) {
		t.Errorf("known target: Coverage = %+v, want covered", got)
	}

	everywhere := Merge(UnknownSource(), mustPolicy(t, sqsGrant))
	if got := everywhere.Coverage("sqs:SendMessage", nil, nil, true); got != (Result{Verdict: Covered}) {
		t.Errorf("unknown target: Coverage = %+v, want covered", got)
	}
	if got := everywhere.CoverageOfEveryResource("sqs:SendMessage", true); got != (Result{Verdict: Covered}) {
		t.Errorf("CoverageOfEveryResource = %+v, want covered", got)
	}
}

func TestMerge_UnknownSourceOnEveryResource(t *testing.T) {
	merged := Merge(mustPolicy(t, `{"Statement":[]}`), UnknownSource())
	if got := merged.CoverageOfEveryResource("ssm:GetParameter", false); got != (Result{Verdict: Covered}) {
		t.Errorf("default: CoverageOfEveryResource = %+v, want covered", got)
	}
	want := Result{Verdict: Unverified, Reason: ReasonPolicyUnknown}
	if got := merged.CoverageOfEveryResource("ssm:GetParameter", true); got != want {
		t.Errorf("strict: CoverageOfEveryResource = %+v, want %+v", got, want)
	}
}

func TestMerge_UnknownSourceForANeedWithoutResources(t *testing.T) {
	scoped := `{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"` + queueARN + `"}]}`
	conditional := `{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*",
		"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`

	cases := []struct {
		name  string
		known string
		want  UnverifiedReason
	}{
		{"no known grant", `{"Statement":[]}`, ReasonPolicyUnknown},
		// A reason about a statement the tool read comes first.
		{"a scoped known grant", scoped, ReasonResourceScope},
		{"a conditional known grant", conditional, ReasonCondition},
	}
	for _, c := range cases {
		merged := Merge(mustPolicy(t, c.known), UnknownSource())
		if got := merged.Coverage("sqs:SendMessage", nil, nil, false); got != (Result{Verdict: Covered}) {
			t.Errorf("%s, default: Coverage = %+v, want covered", c.name, got)
		}
		want := Result{Verdict: Unverified, Reason: c.want}
		if got := merged.Coverage("sqs:SendMessage", nil, nil, true); got != want {
			t.Errorf("%s, strict: Coverage = %+v, want %+v", c.name, got, want)
		}
	}
}

func TestMerge_UnknownSourceInWorstVerdict(t *testing.T) {
	merged := Merge(mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"`+queueARN+`"}]}`), UnknownSource())
	targets := [][]string{queueTargets, {"arn:*:sqs:*:*:other-queue"}}
	want := Result{Verdict: Unverified, Reason: ReasonPolicyUnknown}
	if got := merged.WorstVerdict("sqs:SendMessage", targets, nil, true); got != want {
		t.Errorf("WorstVerdict = %+v, want %+v", got, want)
	}
}

func TestMerge_UnknownSourceGrantsEveryResource(t *testing.T) {
	merged := Merge(mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"`+queueARN+`"}]}`), UnknownSource())
	if got := merged.GrantedResources("sqs:SendMessage"); got != nil {
		t.Errorf("GrantedResources = %v, want nil: the unknown source may grant every resource", got)
	}
	if !merged.Covers("ssm:GetParameter", nil) {
		t.Error("Covers: the unknown source may grant any action")
	}
}

func TestStatement_UnverifiedMayGrant(t *testing.T) {
	src := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`)
	mayGrant := &Document{Statements: []Statement{src.Statements[0].Unverified(ReasonCondition)}}

	if got := mayGrant.Coverage("secretsmanager:GetSecretValue", secretTargets, nil, false); got != (Result{Verdict: Covered}) {
		t.Errorf("default: Coverage = %+v, want covered", got)
	}
	want := Result{Verdict: Unverified, Reason: ReasonCondition}
	if got := mayGrant.Coverage("secretsmanager:GetSecretValue", secretTargets, nil, true); got != want {
		t.Errorf("strict: Coverage = %+v, want %+v", got, want)
	}
	if got := mayGrant.Coverage("secretsmanager:GetSecretValue", nil, nil, true); got != want {
		t.Errorf("strict, no target: Coverage = %+v, want %+v", got, want)
	}
}

func TestStatement_UnverifiedDenyIsNeverDefinite(t *testing.T) {
	src := mustPolicy(t, `{"Statement":[{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}]}`)
	merged := Merge(mustPolicy(t, sqsGrant), &Document{Statements: []Statement{src.Statements[0].Unverified(ReasonCondition)}})
	for _, targets := range [][]string{nil, queueTargets} {
		if got := merged.Coverage("sqs:SendMessage", targets, nil, true); got != (Result{Verdict: Covered}) {
			t.Errorf("targets=%v: Coverage = %+v, want covered", targets, got)
		}
	}
	if got := merged.CoverageOfEveryResource("sqs:SendMessage", true); got != (Result{Verdict: Covered}) {
		t.Errorf("CoverageOfEveryResource = %+v, want covered", got)
	}
}

func TestStatement_UnverifiedWithAFailingConditionGrantsNothing(t *testing.T) {
	src := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*",
		"Condition":`+issueCondition+`}]}`)
	marked := &Document{Statements: []Statement{src.Statements[0].Unverified(ReasonPolicyUnknown)}}
	if got := marked.Coverage("lambda:CreateEventSourceMapping", nil, issueContext, false); got.Verdict != Missing {
		t.Errorf("Coverage = %+v, want missing", got)
	}
}

func TestStatement_UnverifiedWithAnUnknownConditionReportsTheCondition(t *testing.T) {
	src := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*",
		"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
	marked := &Document{Statements: []Statement{src.Statements[0].Unverified(ReasonPolicyUnknown)}}
	want := Result{Verdict: Unverified, Reason: ReasonCondition}
	if got := marked.Coverage("sqs:SendMessage", queueTargets, nil, true); got != want {
		t.Errorf("Coverage = %+v, want %+v", got, want)
	}
}

func TestParse_DoesNotReadTheUnverifiedMarker(t *testing.T) {
	for _, field := range []string{"unverified", "Unverified"} {
		doc := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*","`+field+`":3}]}`)
		if got := doc.Coverage("sqs:SendMessage", nil, nil, true); got != (Result{Verdict: Covered}) {
			t.Errorf("%s: Coverage = %+v, want covered: the policy's JSON cannot mark a statement", field, got)
		}
	}
}

func TestMerge_JSONFormIsUnchanged(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Sid":"Send","Effect":"Allow","Action":["sqs:SendMessage"],"Resource":["*"]}]}`
	before, err := json.Marshal(mustPolicy(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(Merge(mustPolicy(t, raw)))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("merged JSON = %s, want %s", after, before)
	}
	unknown, err := json.Marshal(UnknownSource())
	if err != nil {
		t.Fatal(err)
	}
	// Every statement prints its Condition block, empty or not, as a parsed
	// one does.
	const want = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"],"Condition":{}}]}`
	if string(unknown) != want {
		t.Errorf("UnknownSource JSON = %s, want %s", unknown, want)
	}
}

func TestMerge_SkipsNilDocuments(t *testing.T) {
	merged := Merge(nil, mustPolicy(t, sqsGrant), nil)
	if len(merged.Statements) != 1 {
		t.Errorf("Merge kept %d statements, want 1", len(merged.Statements))
	}
}

func TestUnverifiedReason_Strings(t *testing.T) {
	cases := []struct {
		reason        UnverifiedReason
		value, String string
	}{
		{ReasonNone, "", ""},
		{ReasonResourceScope, "resource_scope", "resource scope"},
		{ReasonCondition, "condition", "condition"},
		{ReasonPolicyUnknown, "policy_unknown", "policy unknown"},
		{ReasonCrossAccount, "cross_account", "cross account"},
	}
	for _, c := range cases {
		if got := c.reason.Value(); got != c.value {
			t.Errorf("%d: Value() = %q, want %q", c.reason, got, c.value)
		}
		if got := c.reason.String(); got != c.String {
			t.Errorf("%d: String() = %q, want %q", c.reason, got, c.String)
		}
	}
}

func TestFirstReason_Order(t *testing.T) {
	order := []UnverifiedReason{ReasonCondition, ReasonResourceScope, ReasonPolicyUnknown, ReasonCrossAccount}
	for i, a := range order {
		if got := firstReason(ReasonNone, a); got != a {
			t.Errorf("firstReason(none, %v) = %v, want %v", a, got, a)
		}
		for _, b := range order[i:] {
			if got := firstReason(a, b); got != a {
				t.Errorf("firstReason(%v, %v) = %v, want %v", a, b, got, a)
			}
			if got := firstReason(b, a); got != a {
				t.Errorf("firstReason(%v, %v) = %v, want %v", b, a, got, a)
			}
		}
	}
}

// splitCorpus holds the documents of the package's other tests: grants on
// every resource and on one, definite and conditional Denies, NotAction and
// NotResource, conditions the plan can and cannot decide, and a Deny that
// names its partition.
var splitCorpus = []string{
	`{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs:us-east-1:111122223333:example-a"}]}`,
	`{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"},{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}]}`,
	`{"Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:111122223333:example-queue"},
		{"Effect":"Deny","Action":"sqs:DeleteQueue","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}]}`,
	`{"Statement":[
		{"Effect":"Allow","Action":"lambda:CreateEventSourceMapping","Resource":"*","Condition":` + issueCondition + `},
		{"Effect":"Allow","Action":"lambda:*","Resource":"arn:aws:lambda:us-east-1:111122223333:function:example-*"},
		{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`,
	`{"Statement":[
		{"Effect":"Allow","NotAction":"iam:*","Resource":"*"},
		{"Effect":"Deny","NotAction":["sqs:*","lambda:*"],"Resource":"*"},
		{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","NotResource":"arn:aws:secretsmanager:*:*:secret:other-*"}]}`,
	`{"Statement":[
		{"Effect":"Allow","Action":"*","Resource":"*"},
		{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:*:*:*"},
		{"Effect":"Deny","Action":"secretsmanager:*","NotResource":"arn:aws:secretsmanager:*:*:secret:app-*"}]}`,
	`{"Statement":[
		{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"` + secretARN + `"},
		{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"` + queueARN + `"},
		{"Effect":"Deny","Action":"lambda:CreateEventSourceMapping","Resource":"*","Condition":{}}]}`,
}

// TestMerge_SplittingADocumentNeverChangesAVerdict splits each corpus
// document's statements across two documents and merges them back. Each
// question gets the same answer from the merged document as from the
// original, with and without an unknown source between the halves.
func TestMerge_SplittingADocumentNeverChangesAVerdict(t *testing.T) {
	actions := []string{"sqs:SendMessage", "sqs:DeleteQueue", "lambda:CreateEventSourceMapping", "secretsmanager:GetSecretValue", "iam:PassRole"}
	targetSets := [][]string{nil, queueTargets, secretTargets,
		{"arn:*:sqs:*:*:example-a"}, {"arn:*:lambda:*:*:function:example-new-consumer"},
		{"arn:*:secretsmanager:*:*:secret:other-??????"}}
	contexts := []Conditions{nil, issueContext}

	rng := rand.New(rand.NewSource(175))
	for i, raw := range splitCorpus {
		whole := mustPolicy(t, raw)
		for trial := 0; trial < 32; trial++ {
			var first, second Document
			for _, s := range whole.Statements {
				if rng.Intn(2) == 0 {
					first.Statements = append(first.Statements, s)
				} else {
					second.Statements = append(second.Statements, s)
				}
			}
			pairs := []struct {
				name       string
				want, have *Document
			}{
				{"split", whole, Merge(&first, &second)},
				{"split around an unknown source", Merge(whole, UnknownSource()), Merge(&second, UnknownSource(), &first)},
			}
			for _, p := range pairs {
				for _, action := range actions {
					for _, strict := range []bool{false, true} {
						if w, h := p.want.CoverageOfEveryResource(action, strict), p.have.CoverageOfEveryResource(action, strict); w != h {
							t.Errorf("doc %d, %s, %s strict=%v: CoverageOfEveryResource = %+v, want %+v", i, p.name, action, strict, h, w)
						}
						for _, conds := range contexts {
							for _, targets := range targetSets {
								if w, h := p.want.Coverage(action, targets, conds, strict), p.have.Coverage(action, targets, conds, strict); w != h {
									t.Errorf("doc %d, %s, %s %v strict=%v: Coverage = %+v, want %+v", i, p.name, action, targets, strict, h, w)
								}
							}
						}
					}
					if w, h := p.want.GrantedResources(action), p.have.GrantedResources(action); !reflect.DeepEqual(w, h) {
						t.Errorf("doc %d, %s, %s: GrantedResources = %v, want %v", i, p.name, action, h, w)
					}
				}
			}
		}
	}
}
