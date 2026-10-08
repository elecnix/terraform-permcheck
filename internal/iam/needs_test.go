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
	want := []MissingAction{{Action: "ecr:PutImage", Service: "ecr", Class: ClassManagement, Need: "Push"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
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
