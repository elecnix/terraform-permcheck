package iam

import (
	"reflect"
	"strings"
	"testing"
)

// needFindings collapses findings to "sid:action@resource" for assertions,
// with a trailing "?" on an unverified one.
func needFindings(missing []MissingAction) []string {
	var out []string
	for _, m := range missing {
		s := m.Need + ":" + m.Action + "@" + m.NeedResource
		if m.ResourceScopeUnverified {
			s += "?"
		}
		out = append(out, s)
	}
	return out
}

const repoA = "arn:aws:ecr:us-east-1:111111111111:repository/app-a"
const repoB = "arn:aws:ecr:us-east-1:111111111111:repository/app-b"

func TestCheckNeeds(t *testing.T) {
	policy := `{"Statement":[
		{"Effect":"Allow","Action":"ecr:DescribeImages","Resource":"` + repoA + `"},
		{"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"},
		{"Effect":"Allow","Action":"ecr:BatchGetImage","Resource":"` + repoA + `"},
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret-bucket/*"}
	]}`

	tests := []struct {
		name   string
		need   Need
		strict bool
		want   []string
	}{
		{
			name: "action granted on the needed repository",
			need: Need{Sid: "Verify", Actions: []string{"ecr:DescribeImages"}, Resources: []string{repoA}},
		},
		{
			name: "action granted on another repository",
			need: Need{Sid: "Verify", Actions: []string{"ecr:DescribeImages"}, Resources: []string{repoA, repoB}},
			want: []string{"Verify:ecr:DescribeImages@" + repoB},
		},
		{
			name: "action not granted at all",
			need: Need{Sid: "Push", Actions: []string{"ecr:PutImage"}},
			want: []string{"Push:ecr:PutImage@"},
		},
		{
			name: "star need granted on every resource",
			need: Need{Sid: "Auth", Actions: []string{"ecr:GetAuthorizationToken"}, Resources: []string{"*"}},
		},
		{
			name: "star need granted on one repository only",
			need: Need{Sid: "Pull", Actions: []string{"ecr:BatchGetImage"}, Resources: []string{"*"}},
			want: []string{"Pull:ecr:BatchGetImage@*"},
		},
		{
			name: "need without resources accepts a scoped grant",
			need: Need{Sid: "Pull", Actions: []string{"ecr:BatchGetImage"}},
		},
		{
			name:   "strict mode flags a scoped grant for a need without resources",
			need:   Need{Sid: "Pull", Actions: []string{"ecr:BatchGetImage"}},
			strict: true,
			want:   []string{"Pull:ecr:BatchGetImage@?"},
		},
		{
			name: "deny on the needed resource",
			need: Need{Sid: "Read", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::secret-bucket/config.json", "arn:aws:s3:::open-bucket/x"}},
			want: []string{"Read:s3:GetObject@arn:aws:s3:::secret-bucket/config.json"},
		},
		{
			name: "action names compare case-insensitively",
			need: Need{Sid: "Auth", Actions: []string{"ECR:getauthorizationtoken"}, Resources: []string{"*"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := needFindings(CheckNeeds([]Need{tt.need}, mustPolicy(t, policy), tt.strict))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckNeeds_FindingShape(t *testing.T) {
	got := CheckNeeds([]Need{{Sid: "Push", Actions: []string{"ecr:PutImage"}}}, mustPolicy(t, `{"Statement":[]}`), false)
	want := []MissingAction{{Action: "ecr:PutImage", Service: "ecr", Class: "[required]", Need: "Push"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if s := got[0].Source(); s != `needs "Push"` {
		t.Errorf("Source() = %q", s)
	}
}

func TestSelectNeeds(t *testing.T) {
	needs := []Need{
		{Sid: "Shared"},
		{Sid: "Deploy", Principal: "deploy"},
		{Sid: "Task", Principal: "task"},
	}
	sids := func(ns []Need) []string {
		var out []string
		for _, n := range ns {
			out = append(out, n.Sid)
		}
		return out
	}

	got, err := SelectNeeds(needs, "")
	if err != nil || !reflect.DeepEqual(sids(got), []string{"Shared"}) {
		t.Errorf("no principal: got %v, %v; want [Shared]", sids(got), err)
	}
	got, err = SelectNeeds(needs, "deploy")
	if err != nil || !reflect.DeepEqual(sids(got), []string{"Shared", "Deploy"}) {
		t.Errorf("deploy: got %v, %v; want [Shared Deploy]", sids(got), err)
	}
	if _, err := SelectNeeds(needs, "deploi"); err == nil || !strings.Contains(err.Error(), `"deploi"`) {
		t.Errorf("unknown principal: want an error naming it, got %v", err)
	}
}

func TestParseConfig_Needs(t *testing.T) {
	c, err := parseConfig([]byte(`{"needs":[{"sid":"Auth","principal":"ci","actions":["ecr:GetAuthorizationToken"],"resources":["*"],"reason":"docker login"}]}`))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	want := []Need{{Sid: "Auth", Principal: "ci", Actions: []string{"ecr:GetAuthorizationToken"}, Resources: []string{"*"}, Reason: "docker login"}}
	if !reflect.DeepEqual(c.Needs, want) {
		t.Errorf("Needs = %+v, want %+v", c.Needs, want)
	}

	for _, tt := range []struct{ raw, want string }{
		{`{"needs":[{"actions":["s3:GetObject"]}]}`, "sid is required"},
		{`{"needs":[{"sid":"A"}]}`, "actions is required"},
		{`{"needs":[{"sid":"A","actions":["GetObject"]}]}`, "single service:Action"},
		{`{"needs":[{"sid":"A","actions":["s3:Get*"]}]}`, "single service:Action"},
		{`{"needs":[{"sid":"A","actions":["s3:GetObject"],"resources":["my-bucket"]}]}`, "must be \"*\" or an ARN"},
		{`{"needs":[{"sid":"A","actions":["s3:GetObject"]},{"sid":"A","actions":["s3:PutObject"]}]}`, "duplicate sid"},
		// A need without a principal runs with every principal, so its sid
		// clashes with the same sid under a named principal, in either order.
		{`{"needs":[{"sid":"A","actions":["s3:GetObject"]},{"sid":"A","principal":"ci","actions":["s3:PutObject"]}]}`, "duplicate sid"},
		{`{"needs":[{"sid":"A","principal":"ci","actions":["s3:GetObject"]},{"sid":"A","actions":["s3:PutObject"]}]}`, "duplicate sid"},
	} {
		if _, err := parseConfig([]byte(tt.raw)); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("parseConfig(%s): want error containing %q, got %v", tt.raw, tt.want, err)
		}
	}

	// Needs under two different principals never run together, so they may
	// share a sid.
	if _, err := parseConfig([]byte(`{"needs":[{"sid":"A","principal":"ci","actions":["s3:GetObject"]},{"sid":"A","principal":"app","actions":["s3:PutObject"]}]}`)); err != nil {
		t.Errorf("parseConfig: one sid under two principals: %v", err)
	}
}

// TestExclusions_MatchNeeds verifies an exclusion suppresses a need finding
// by permission, and a resource pattern matches "needs.<sid>".
func TestExclusions_MatchNeeds(t *testing.T) {
	missing := []MissingAction{
		{Action: "ecr:PutImage", Need: "Push"},
		{Action: "ecr:PutImage", Need: "Other"},
		{Action: "ecr:PutImage", ResourceType: "aws_ecr_repository", ResourceName: "a", Change: "create"},
	}
	kept, excluded := ApplyExclusions(missing, []Exclusion{{Permission: "ecr:*", Resource: "needs.Push"}})
	if len(excluded) != 1 || excluded[0].Need != "Push" || len(kept) != 2 {
		t.Errorf("kept %+v, excluded %+v", kept, excluded)
	}
	// An operations filter names terraform operations, which a need has none of.
	kept, _ = ApplyExclusions(missing[:1], []Exclusion{{Permission: "ecr:PutImage", Operations: []string{"create"}}})
	if len(kept) != 1 {
		t.Errorf("an operations exclusion must not match a need, kept %+v", kept)
	}
}

// TestFormat_NeedSource verifies every format names the need as the source.
func TestFormat_NeedSource(t *testing.T) {
	missing := []MissingAction{{Action: "ecr:DescribeImages", Service: "ecr", Class: "[required]", Need: "EcrImageVerification", NeedResource: repoA}}

	if got := FormatMissing(missing, nil); !strings.Contains(got, `→ needs "EcrImageVerification" on `+repoA) {
		t.Errorf("FormatMissing:\n%s", got)
	}
	if got := FormatGitHubAnnotations(missing, nil); !strings.Contains(got, `ecr:DescribeImages needed by: needs "EcrImageVerification" on `+repoA) {
		t.Errorf("FormatGitHubAnnotations:\n%s", got)
	}
	got := FormatJSON(missing, nil, 0, "resource changes", nil)
	for _, want := range []string{`"need": "EcrImageVerification"`, `"need_resource": "` + repoA + `"`} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatJSON missing %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"resource_type"`) {
		t.Errorf("FormatJSON should omit the empty resource fields of a need:\n%s", got)
	}
	excluded := []ExcludedAction{{MissingAction: missing[0], Reason: "later"}}
	if got := FormatExcluded(excluded); !strings.Contains(got, `→ needs "EcrImageVerification"`) {
		t.Errorf("FormatExcluded:\n%s", got)
	}
	if got := FormatExcludedAnnotations(excluded); !strings.Contains(got, `for: needs "EcrImageVerification"`) {
		t.Errorf("FormatExcludedAnnotations:\n%s", got)
	}
}
