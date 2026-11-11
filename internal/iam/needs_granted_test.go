package iam

import (
	"reflect"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/policy"
)

const slrARN = "arn:aws:iam::*:role/aws-service-role/securityhubv2.amazonaws.com/AWSServiceRoleForSecurityHubV2"

func TestCheckNeeds_GrantedOn(t *testing.T) {
	narrow := mustPolicy(t, `{"Statement":[
		{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"`+slrARN+`"},
		{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":["arn:aws:iam::*:role/aws-service-role/a.amazonaws.com/*","`+slrARN+`"]}
	]}`)
	tests := []struct {
		name string
		doc  *policy.Document
		need Need
		want []string
	}{
		{
			name: "star need on a narrow grant lists the grant, sorted and deduplicated",
			doc:  narrow,
			need: Need{Sid: "S", Actions: []string{"iam:CreateServiceLinkedRole"}, Resources: []string{"*"}},
			want: []string{"arn:aws:iam::*:role/aws-service-role/a.amazonaws.com/*", slrARN},
		},
		{
			name: "resource need outside the grant lists the grant",
			doc:  narrow,
			need: Need{Sid: "S", Actions: []string{"iam:CreateServiceLinkedRole"}, Resources: []string{"arn:aws:iam::111111111111:role/other"}},
			want: []string{"arn:aws:iam::*:role/aws-service-role/a.amazonaws.com/*", slrARN},
		},
		{
			name: "action not granted at all has no list",
			doc:  narrow,
			need: Need{Sid: "S", Actions: []string{"iam:DeleteRole"}, Resources: []string{"*"}},
		},
		{
			name: "need without resources has no list",
			doc:  narrow,
			need: Need{Sid: "S", Actions: []string{"iam:DeleteRole"}},
		},
		{
			name: "a Deny on every resource is not a narrow grant",
			doc: mustPolicy(t, `{"Statement":[
				{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"`+slrARN+`"},
				{"Effect":"Deny","Action":"iam:CreateServiceLinkedRole","Resource":"*"}]}`),
			need: Need{Sid: "S", Actions: []string{"iam:CreateServiceLinkedRole"}, Resources: []string{slrARN}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckNeeds([]Need{tt.need}, tt.doc, false)
			if len(got) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
			}
			if !reflect.DeepEqual(got[0].GrantedOn, tt.want) {
				t.Errorf("GrantedOn = %v, want %v", got[0].GrantedOn, tt.want)
			}
		})
	}
}
