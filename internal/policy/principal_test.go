package policy

import (
	"encoding/json"
	"testing"
)

// The principal a need belongs to, as the tool may know it.
var (
	// taskRole is a role whose ARN the plan shows, as for a role that exists.
	taskRole = Principal{
		Kind: KindRole,
		ARN:  "arn:aws:iam::123456789012:role/app-task",
	}
	// taskRoleNameOnly is a role whose name the plan shows and whose ARN it
	// computes at apply time, so its account is unknown.
	taskRoleNameOnly = Principal{Kind: KindRole, Name: "app-task"}
	// taskRoleUnknown is a role created with name_prefix: the plan shows
	// neither its name nor its ARN.
	taskRoleUnknown = Principal{Kind: KindRole}
	// taskRoleBounded is taskRole with a permissions boundary.
	taskRoleBounded = Principal{
		Kind:                KindRole,
		ARN:                 "arn:aws:iam::123456789012:role/app-task",
		PermissionsBoundary: true,
	}
	// otherAccountRole is a role in account 444455556666.
	otherAccountRole = Principal{
		Kind: KindRole,
		ARN:  "arn:aws:iam::444455556666:role/app-task",
	}
)

// outcome names what ForPrincipal does with one statement.
type outcome string

const (
	grants   outcome = "grants"     // kept as is, an Allow
	mayGrant outcome = "may grant"  // kept, marked Unverified(ReasonCondition)
	definite outcome = "definite"   // kept as is, a Deny
	dropped  outcome = "dropped"    // removed
	unknownO outcome = "unexpected" // anything else
)

// forPrincipalOutcome runs ForPrincipal on a document with one statement and
// names what it did with the statement.
func forPrincipalOutcome(t *testing.T, statement string, p Principal, opts ...PrincipalOption) outcome {
	t.Helper()
	doc := mustPolicy(t, `{"Version":"2012-10-17","Statement":[`+statement+`]}`)
	got := doc.ForPrincipal(p, opts...)
	switch len(got.Statements) {
	case 0:
		return dropped
	case 1:
	default:
		return unknownO
	}
	s := got.Statements[0]
	switch {
	case s.Effect == "Allow" && s.unverified == ReasonNone:
		return grants
	case s.Effect == "Allow" && s.unverified == ReasonCondition:
		return mayGrant
	case s.Effect == "Deny" && s.unverified == ReasonNone:
		return definite
	}
	return unknownO
}

// withPrincipal returns an Allow or Deny statement on secretsmanager with the
// given Principal element.
func withPrincipal(effect, principal string) string {
	return `{"Effect":"` + effect + `","Principal":` + principal + `,"Action":"secretsmanager:GetSecretValue","Resource":"*"}`
}

// withNotPrincipal returns an Allow or Deny statement on secretsmanager with
// the given NotPrincipal element.
func withNotPrincipal(effect, notPrincipal string) string {
	return `{"Effect":"` + effect + `","NotPrincipal":` + notPrincipal + `,"Action":"secretsmanager:GetSecretValue","Resource":"*"}`
}

type principalCase struct {
	name      string
	principal string
	p         Principal
	allow     outcome
	deny      outcome
}

func runPrincipalCases(t *testing.T, cases []principalCase, opts ...PrincipalOption) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := forPrincipalOutcome(t, withPrincipal("Allow", c.principal), c.p, opts...); got != c.allow {
				t.Errorf("Allow: %s, want %s", got, c.allow)
			}
			if got := forPrincipalOutcome(t, withPrincipal("Deny", c.principal), c.p, opts...); got != c.deny {
				t.Errorf("Deny: %s, want %s", got, c.deny)
			}
		})
	}
}

// One case per row of the Principal table in the design.
func TestForPrincipal_PrincipalTable(t *testing.T) {
	runPrincipalCases(t, []principalCase{
		{"the role ARN", `{"AWS":"arn:aws:iam::123456789012:role/app-task"}`, taskRole, grants, definite},
		{"a bare wildcard", `"*"`, taskRole, grants, definite},
		{"an AWS wildcard", `{"AWS":"*"}`, taskRole, grants, definite},
		{"the account root ARN", `{"AWS":"arn:aws:iam::123456789012:root"}`, taskRole, dropped, definite},
		{"the bare account id", `{"AWS":"123456789012"}`, taskRole, dropped, definite},
		{"another account", `{"AWS":"arn:aws:iam::444455556666:root"}`, taskRole, dropped, dropped},
		{"an account the tool cannot compare", `{"AWS":"123456789012"}`, taskRoleNameOnly, dropped, dropped},
		{"a name match with an unknown account", `{"AWS":"arn:aws:iam::123456789012:role/app-task"}`, taskRoleNameOnly, mayGrant, dropped},
		{"a role session", `{"AWS":"arn:aws:sts::123456789012:assumed-role/app-task/session-1"}`, taskRole, mayGrant, dropped},
		{"a service", `{"Service":"ecs-tasks.amazonaws.com"}`, taskRole, dropped, dropped},
		{"a federated provider", `{"Federated":"cognito-identity.amazonaws.com"}`, taskRole, dropped, dropped},
		{"a canonical user", `{"CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}`, taskRole, dropped, dropped},
		{"another role", `{"AWS":"arn:aws:iam::123456789012:role/app-web"}`, taskRole, dropped, dropped},
	})
}

func TestForPrincipal_NotPrincipalAllowGrantsNothing(t *testing.T) {
	for _, list := range []string{
		`{"AWS":"arn:aws:iam::123456789012:role/app-web"}`,
		`{"AWS":"arn:aws:iam::123456789012:role/app-task"}`,
	} {
		if got := forPrincipalOutcome(t, withNotPrincipal("Allow", list), taskRole); got != dropped {
			t.Errorf("NotPrincipal %s, Allow: %s, want dropped", list, got)
		}
	}
}

// More cases of the "Principal matching" item of the test plan.
func TestForPrincipal_MoreForms(t *testing.T) {
	pathRole := Principal{Kind: KindRole, ARN: "arn:aws:iam::123456789012:role/service/app-task"}
	runPrincipalCases(t, []principalCase{
		{"the account id under AWS, other account", `{"AWS":"111122223333"}`, taskRole, dropped, dropped},
		{"a list that holds the role", `{"AWS":["arn:aws:iam::123456789012:role/app-web","arn:aws:iam::123456789012:role/app-task"]}`, taskRole, grants, definite},
		{"a list without the role", `{"AWS":["arn:aws:iam::123456789012:role/app-web","arn:aws:iam::123456789012:role/app-worker"]}`, taskRole, dropped, dropped},
		{"a mix of keys", `{"Service":"ecs-tasks.amazonaws.com","AWS":"arn:aws:iam::123456789012:role/app-task"}`, taskRole, grants, definite},
		{"a role with a path", `{"AWS":"arn:aws:iam::123456789012:role/service/app-task"}`, pathRole, grants, definite},
		{"a path and a name match", `{"AWS":"arn:aws:iam::123456789012:role/service/app-task"}`, taskRoleNameOnly, mayGrant, dropped},
		{"the role ARN without the path", `{"AWS":"arn:aws:iam::123456789012:role/app-task"}`, pathRole, dropped, dropped},
		{"a role session of the role with a path", `{"AWS":"arn:aws:sts::123456789012:assumed-role/app-task/session-1"}`, pathRole, mayGrant, dropped},
		{"a session of another role", `{"AWS":"arn:aws:sts::123456789012:assumed-role/app-web/session-1"}`, taskRole, dropped, dropped},
		{"a name that ends like the role's", `{"AWS":"arn:aws:iam::123456789012:role/myapp-task"}`, taskRoleNameOnly, dropped, dropped},
		{"a user with the role's name", `{"AWS":"arn:aws:iam::123456789012:user/app-task"}`, taskRoleNameOnly, dropped, dropped},
		{"the role ARN in another account", `{"AWS":"arn:aws:iam::444455556666:role/app-task"}`, taskRole, dropped, dropped},
		{"the role ARN with other capitalisation", `{"AWS":"arn:aws:iam::123456789012:role/App-Task"}`, taskRole, mayGrant, dropped},
		{"the user ARN with other capitalisation", `{"AWS":"arn:aws:iam::123456789012:user/CI"}`, Principal{Kind: KindUser, ARN: "arn:aws:iam::123456789012:user/ci"}, mayGrant, dropped},
		{"a role whose name the tool cannot read", `{"AWS":"arn:aws:iam::123456789012:role/app-task"}`, taskRoleUnknown, mayGrant, dropped},
		{"a wildcard entry that may match", `{"AWS":"arn:aws:iam::123456789012:role/app-*"}`, taskRole, mayGrant, dropped},
		{"a wildcard entry that cannot match", `{"AWS":"arn:aws:iam::123456789012:role/web-*"}`, taskRole, dropped, dropped},
		{"a unique id the tool cannot compare", `{"AWS":"AROAEXAMPLEID1234567"}`, taskRole, mayGrant, dropped},
		{"a principal type the tool does not know", `{"Other":"value"}`, taskRole, mayGrant, dropped},
	})
}

func TestForPrincipal_AccountGrantsOnTheResourceSideOfACrossAccountNeed(t *testing.T) {
	runPrincipalCases(t, []principalCase{
		{"the account root ARN", `{"AWS":"arn:aws:iam::444455556666:root"}`, otherAccountRole, grants, definite},
		{"the bare account id", `{"AWS":"444455556666"}`, otherAccountRole, grants, definite},
		{"another account", `{"AWS":"123456789012"}`, otherAccountRole, dropped, dropped},
		{"an account the tool cannot compare", `{"AWS":"444455556666"}`, taskRoleNameOnly, mayGrant, dropped},
		{"the role ARN", `{"AWS":"arn:aws:iam::444455556666:role/app-task"}`, otherAccountRole, grants, definite},
	}, ResourceSide())
}

// The NotPrincipal cases of the "Principal matching" item of the test plan.
func TestForPrincipal_NotPrincipalDeny(t *testing.T) {
	cases := []struct {
		name string
		list string
		p    Principal
		want outcome
	}{
		{"another role only", `{"AWS":"arn:aws:iam::123456789012:role/app-web"}`, taskRole, definite},
		{"the role and its account", `{"AWS":["arn:aws:iam::123456789012:role/app-task","arn:aws:iam::123456789012:root"]}`, taskRole, dropped},
		{"the role only", `{"AWS":"arn:aws:iam::123456789012:role/app-task"}`, taskRole, dropped},
		{"the account only", `{"AWS":"123456789012"}`, taskRole, dropped},
		{"another account only", `{"AWS":"444455556666"}`, taskRole, definite},
		{"a name match with an unknown account", `{"AWS":"arn:aws:iam::123456789012:role/app-task"}`, taskRoleNameOnly, dropped},
		{"an account the tool cannot compare", `{"AWS":"arn:aws:iam::123456789012:root"}`, taskRoleNameOnly, dropped},
		{"a session of the role", `{"AWS":"arn:aws:sts::123456789012:assumed-role/app-task/session-1"}`, taskRole, dropped},
		{"a role whose name the tool cannot read", `{"AWS":"arn:aws:iam::123456789012:role/app-web"}`, taskRoleUnknown, dropped},
		{"a wildcard entry that may match", `{"AWS":"arn:aws:iam::444455556666:role/*"}`, otherAccountRole, dropped},
		{"a wildcard entry in another account", `{"AWS":"arn:aws:iam::444455556666:role/*"}`, taskRole, definite},
		{"a wildcard that matches every principal", `"*"`, taskRole, dropped},
		{"a service only", `{"Service":"ecs-tasks.amazonaws.com"}`, taskRole, definite},
		{"another role while the role has a boundary", `{"AWS":"arn:aws:iam::123456789012:role/app-web"}`, taskRoleBounded, definite},
		{"the role and its account while the role has a boundary", `{"AWS":["arn:aws:iam::123456789012:role/app-task","123456789012"]}`, taskRoleBounded, definite},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := forPrincipalOutcome(t, withNotPrincipal("Deny", c.list), c.p); got != c.want {
				t.Errorf("%s, want %s", got, c.want)
			}
		})
	}
}

// A resource policy statement with neither Principal nor NotPrincipal has no
// principal to match. AWS rejects such a policy for most services, but the
// tool cannot prove that the service rejects it, so its Allow may grant and
// its Deny is not definite.
func TestForPrincipal_StatementWithoutPrincipal(t *testing.T) {
	const allow = `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}`
	const deny = `{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}`
	if got := forPrincipalOutcome(t, allow, taskRole); got != mayGrant {
		t.Errorf("Allow: %s, want %s", got, mayGrant)
	}
	if got := forPrincipalOutcome(t, deny, taskRole); got != dropped {
		t.Errorf("Deny: %s, want %s", got, dropped)
	}
}

// A statement with both elements is invalid. Its Allow grants nothing, as a
// NotPrincipal Allow does, and its Deny is not definite.
func TestForPrincipal_StatementWithBothElements(t *testing.T) {
	both := func(effect string) string {
		return `{"Effect":"` + effect + `","Principal":"*","NotPrincipal":{"AWS":"arn:aws:iam::123456789012:role/app-web"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}`
	}
	if got := forPrincipalOutcome(t, both("Allow"), taskRole); got != dropped {
		t.Errorf("Allow: %s, want %s", got, dropped)
	}
	if got := forPrincipalOutcome(t, both("Deny"), taskRole); got != dropped {
		t.Errorf("Deny: %s, want %s", got, dropped)
	}
}

func TestForPrincipal_KeepsOrderAndDoesNotChangeTheDocument(t *testing.T) {
	doc := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Sid":"A","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/app-task"},"Action":"sqs:*","Resource":"*"},
		{"Sid":"B","Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:*","Resource":"*"},
		{"Sid":"C","Effect":"Allow","Principal":{"AWS":"arn:aws:sts::123456789012:assumed-role/app-task/s"},"Action":"sqs:*","Resource":"*"},
		{"Sid":"D","Effect":"Deny","Principal":"*","Action":"sqs:DeleteQueue","Resource":"*"}
	]}`)
	got := doc.ForPrincipal(taskRole)
	var sids []string
	for _, s := range got.Statements {
		sids = append(sids, s.Sid)
	}
	if want := []string{"A", "C", "D"}; len(sids) != len(want) || sids[0] != "A" || sids[1] != "C" || sids[2] != "D" {
		t.Errorf("kept %v, want %v", sids, want)
	}
	if got.Version != doc.Version {
		t.Errorf("Version = %q, want %q", got.Version, doc.Version)
	}
	if len(doc.Statements) != 4 || doc.Statements[2].unverified != ReasonNone {
		t.Errorf("ForPrincipal changed the document it read")
	}
}

func TestPrincipal_DerivesNameAndAccountFromTheARN(t *testing.T) {
	cases := []struct {
		p             Principal
		name, account string
	}{
		{Principal{Kind: KindRole, ARN: "arn:aws:iam::123456789012:role/app-task"}, "app-task", "123456789012"},
		{Principal{Kind: KindRole, ARN: "arn:aws:iam::123456789012:role/service/app-task"}, "app-task", "123456789012"},
		{Principal{Kind: KindUser, ARN: "arn:aws:iam::123456789012:user/ci/deploy"}, "deploy", "123456789012"},
		{Principal{Kind: KindRole, Name: "app-task", Account: "123456789012"}, "app-task", "123456789012"},
		{Principal{Kind: KindRole}, "", ""},
	}
	for _, c := range cases {
		if got := c.p.name(); got != c.name {
			t.Errorf("%+v: name() = %q, want %q", c.p, got, c.name)
		}
		if got := c.p.account(); got != c.account {
			t.Errorf("%+v: account() = %q, want %q", c.p, got, c.account)
		}
	}
}

// Identity policies ignore Principal and NotPrincipal, as AWS does: Coverage
// on a parsed document reads neither.
func TestCoverage_IgnoresPrincipalElements(t *testing.T) {
	doc := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/app-web"},"Action":"sqs:*","Resource":"*"},
		{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::123456789012:role/app-task"},"Action":"sqs:DeleteQueue","Resource":"*"}
	]}`)
	if got := doc.Coverage("sqs:SendMessage", nil, nil, true); got != (Result{Verdict: Covered}) {
		t.Errorf("SendMessage: Coverage = %+v, want covered", got)
	}
	if got := doc.Coverage("sqs:DeleteQueue", nil, nil, true); got.Verdict != Missing {
		t.Errorf("DeleteQueue: Coverage = %+v, want missing", got)
	}
}

func TestStatement_PrincipalJSONForms(t *testing.T) {
	forms := []string{
		`"*"`,
		`{"AWS":"*"}`,
		`{"AWS":"arn:aws:iam::123456789012:role/app-task"}`,
		`{"AWS":["arn:aws:iam::123456789012:role/app-task","123456789012"]}`,
		`{"AWS":"123456789012"}`,
		`{"Service":["ecs-tasks.amazonaws.com","lambda.amazonaws.com"]}`,
		`{"Federated":"cognito-identity.amazonaws.com"}`,
		`{"CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}`,
		`{"AWS":"arn:aws:iam::123456789012:root","Service":"sns.amazonaws.com"}`,
	}
	for _, form := range forms {
		for _, field := range []string{"Principal", "NotPrincipal"} {
			raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","` + field + `":` + form + `,"Action":["sqs:SendMessage"],"Resource":["*"]}]}`
			doc, err := Parse([]byte(raw))
			if err != nil {
				t.Errorf("%s %s: %v", field, form, err)
				continue
			}
			out, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			want := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","` + field + `":` + form + `,"Action":["sqs:SendMessage"],"Resource":["*"],"Condition":{}}]}`
			if string(out) != want {
				t.Errorf("%s %s: JSON = %s, want %s", field, form, out, want)
			}
		}
	}
}

func TestStatement_JSONWithoutPrincipalIsUnchanged(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Sid":"Send","Effect":"Allow","Action":["sqs:SendMessage"],"Resource":["*"]}]}`
	out, err := json.Marshal(mustPolicy(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"Version":"2012-10-17","Statement":[{"Sid":"Send","Effect":"Allow","Action":["sqs:SendMessage"],"Resource":["*"],"Condition":{}}]}`
	if string(out) != want {
		t.Errorf("JSON = %s, want %s", out, want)
	}
}

// End to end: an identity policy merged with the statements of a resource
// policy that apply to the principal, through Coverage.
func TestForPrincipal_MergedWithIdentityPolicy(t *testing.T) {
	logs := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"logs:PutLogEvents","Resource":"*"}]}`)
	secretsAll := mustPolicy(t, `{"Statement":[{"Effect":"Allow","Action":"secretsmanager:*","Resource":"*"}]}`)
	resource := func(statement string) *Document {
		return mustPolicy(t, `{"Version":"2012-10-17","Statement":[`+statement+`]}`)
	}
	grantTo := func(principal string) *Document {
		return resource(`{"Effect":"Allow","Principal":` + principal + `,"Action":"secretsmanager:GetSecretValue","Resource":"` + secretARN + `"}`)
	}
	cases := []struct {
		name     string
		identity *Document
		resource *Document
		p        Principal
		want     Result
		strict   Result
	}{
		{
			name:     "a grant to the role ARN",
			identity: logs,
			resource: grantTo(`{"AWS":"arn:aws:iam::123456789012:role/app-task"}`),
			p:        taskRole,
			want:     Result{Verdict: Covered},
			strict:   Result{Verdict: Covered},
		},
		{
			name:     "a grant that may reach the role",
			identity: logs,
			resource: grantTo(`{"AWS":"arn:aws:iam::123456789012:role/app-task"}`),
			p:        taskRoleNameOnly,
			want:     Result{Verdict: Covered},
			strict:   Result{Verdict: Unverified, Reason: ReasonCondition},
		},
		{
			name:     "a definite Deny on every principal",
			identity: secretsAll,
			resource: resource(`{"Effect":"Deny","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}`),
			p:        taskRole,
			want:     Result{Verdict: Missing},
			strict:   Result{Verdict: Missing},
		},
		{
			name:     "an account root grant with no identity grant",
			identity: logs,
			resource: grantTo(`{"AWS":"arn:aws:iam::123456789012:root"}`),
			p:        taskRole,
			want:     Result{Verdict: Missing},
			strict:   Result{Verdict: Missing},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			merged := Merge(c.identity, c.resource.ForPrincipal(c.p))
			if got := merged.Coverage("secretsmanager:GetSecretValue", secretTargets, nil, false); got != c.want {
				t.Errorf("default: Coverage = %+v, want %+v", got, c.want)
			}
			if got := merged.Coverage("secretsmanager:GetSecretValue", secretTargets, nil, true); got != c.strict {
				t.Errorf("strict: Coverage = %+v, want %+v", got, c.strict)
			}
		})
	}
}

// BeyondBoundary keeps the Allow statements whose grant a permissions
// boundary doesn't limit. A grant to the role's ARN is limited, and so is a
// grant to its account, which delegates to the identity policies. A grant to
// a session of the role, or to an IAM user's own ARN, isn't. A Deny is
// dropped, since the caller applies every Deny apart.
func TestForPrincipal_BeyondBoundary(t *testing.T) {
	user := Principal{Kind: KindUser, ARN: "arn:aws:iam::123456789012:user/app-ci"}
	session := `{"AWS":"arn:aws:sts::123456789012:assumed-role/app-task/app-session"}`
	cases := []struct {
		name      string
		statement string
		p         Principal
		want      outcome
	}{
		{"the role ARN", withPrincipal("Allow", `{"AWS":"arn:aws:iam::123456789012:role/app-task"}`), taskRole, dropped},
		{"the account", withPrincipal("Allow", `{"AWS":"123456789012"}`), taskRole, dropped},
		{"a session of the role", withPrincipal("Allow", session), taskRole, mayGrant},
		{"a session of the role, name only", withPrincipal("Allow", session), taskRoleNameOnly, mayGrant},
		{"the role ARN and a session", withPrincipal("Allow", `{"AWS":["arn:aws:iam::123456789012:role/app-task","arn:aws:sts::123456789012:assumed-role/app-task/app-session"]}`), taskRole, mayGrant},
		{"a session of another role", withPrincipal("Allow", `{"AWS":"arn:aws:sts::123456789012:assumed-role/app-web/app-session"}`), taskRole, dropped},
		{"every principal", withPrincipal("Allow", `"*"`), taskRole, mayGrant},
		{"every AWS principal", withPrincipal("Allow", `{"AWS":"*"}`), taskRole, mayGrant},
		{"an id the tool can't compare", withPrincipal("Allow", `{"AWS":"AROAEXAMPLEID"}`), taskRole, mayGrant},
		{"a service", withPrincipal("Allow", `{"Service":"ecs-tasks.amazonaws.com"}`), taskRole, dropped},
		{"no Principal element", `{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}`, taskRole, mayGrant},
		{"the user's ARN", withPrincipal("Allow", `{"AWS":"arn:aws:iam::123456789012:user/app-ci"}`), user, grants},
		{"a Deny for every principal", withPrincipal("Deny", `"*"`), taskRole, dropped},
		{"a NotPrincipal Deny", withNotPrincipal("Deny", `{"AWS":"arn:aws:iam::123456789012:role/app-web"}`), taskRoleBounded, dropped},
	}
	for _, c := range cases {
		if got := forPrincipalOutcome(t, c.statement, c.p, BeyondBoundary()); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// Denies keeps the Deny statements of a document, in order.
func TestDocument_Denies(t *testing.T) {
	doc := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
		{"Effect":"Deny","Action":"s3:PutObject","Resource":"*"}]}`)
	got := doc.Denies()
	if len(got.Statements) != 1 || got.Statements[0].Effect != "Deny" {
		t.Errorf("Denies = %+v, want the Deny alone", got.Statements)
	}
}
