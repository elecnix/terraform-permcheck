package iam

import (
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// bucketSchema is the shape the provider source gives aws_s3_bucket: the
// policy and website calls run when their attribute changes, and the tagging
// call shows no gate.
var bucketSchema = fakeSchema{"create": {
	{Action: "s3:CreateBucket"},
	{Action: "s3:PutBucketPolicy", Gate: Gate{Changed: "policy"}},
	{Action: "s3:DeleteBucketPolicy", Gate: Gate{Changed: "policy"}},
	{Action: "s3:PutBucketWebsite", Gate: Gate{Changed: "website"}},
	{Action: "s3:PutBucketTagging"},
}}

// defaultFindings validates one change under the default filter against a
// policy that grants only s3:CreateBucket, and returns the finding per action.
func defaultFindings(t *testing.T, rc *plan.ResourceChange, others ...string) map[string]MissingAction {
	t.Helper()
	changes := []*plan.ResourceChange{rc}
	for _, typ := range others {
		changes = append(changes, &plan.ResourceChange{Type: typ, Name: "other", Change: "create"})
	}
	missing, err := Validate(changes, grantActions("s3:CreateBucket"), fakeResolver{bucketSchema}, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]MissingAction)
	for _, m := range missing {
		if m.ResourceType == rc.Type {
			out[m.Action] = m
		}
	}
	return out
}

// An optional feature that the plan sets is not optional for this apply: the
// provider makes the call, and the apply fails without it.
func TestValidate_UsedOptionalFeatureIsRequired(t *testing.T) {
	rc := &plan.ResourceChange{
		Type: "aws_s3_bucket", Name: "b", Change: "create",
		Attributes:        map[string]bool{"policy": true},
		ChangedAttributes: map[string]bool{"policy": true},
	}
	got := defaultFindings(t, rc)
	m, ok := got["s3:PutBucketPolicy"]
	if !ok {
		t.Fatalf("s3:PutBucketPolicy not reported with policy set: %v", got)
	}
	if m.Class != ClassManagement || m.ConditionAttribute != "policy" {
		t.Errorf("s3:PutBucketPolicy class, condition = %q, %q; want \"management\", policy", m.Class, m.ConditionAttribute)
	}
	if _, ok := got["s3:PutBucketWebsite"]; ok {
		t.Errorf("s3:PutBucketWebsite reported with no website set")
	}
	// The provider deletes the policy only when the change unsets it.
	if _, ok := got["s3:DeleteBucketPolicy"]; ok {
		t.Errorf("s3:DeleteBucketPolicy reported when the policy is set")
	}
}

// A change that unsets the policy makes the provider delete it, and not put
// one.
func TestValidate_UnsetFeatureNeedsTheDelete(t *testing.T) {
	rc := &plan.ResourceChange{
		Type: "aws_s3_bucket", Name: "b", Change: "update",
		Attributes:        map[string]bool{"bucket": true},
		ChangedAttributes: map[string]bool{"policy": true},
	}
	schema := fakeSchema{"update": bucketSchema["create"]}
	missing, err := Validate([]*plan.ResourceChange{rc}, grantNothing(), fakeResolver{schema}, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range missing {
		got = append(got, m.Action)
	}
	if strings.Join(got, ",") != "s3:CreateBucket,s3:DeleteBucketPolicy" {
		t.Errorf("missing = %v, want s3:CreateBucket and s3:DeleteBucketPolicy", got)
	}
}

// Static mode shows which attributes a block sets, so a set attribute is
// evidence that the feature is used.
func TestValidate_UsedOptionalFeatureIsRequired_Static(t *testing.T) {
	rc := &plan.ResourceChange{Type: "aws_s3_bucket", Name: "b", Change: "create", Attributes: map[string]bool{"website": true}}
	got := defaultFindings(t, rc)
	if _, ok := got["s3:PutBucketWebsite"]; !ok {
		t.Errorf("s3:PutBucketWebsite not reported with website set: %v", got)
	}
	if _, ok := got["s3:PutBucketPolicy"]; ok {
		t.Errorf("s3:PutBucketPolicy reported with no policy set")
	}
}

// With nothing that shows the attribute set, the gate holds only because the
// plan cannot rule it out, and the action stays optional.
func TestValidate_UnknownGateKeepsOptional(t *testing.T) {
	got := defaultFindings(t, &plan.ResourceChange{Type: "aws_s3_bucket", Name: "b", Change: "create"})
	for _, a := range []string{"s3:PutBucketPolicy", "s3:PutBucketWebsite", "s3:PutBucketTagging"} {
		if _, ok := got[a]; ok {
			t.Errorf("%s reported with no attribute shown set", a)
		}
	}
}

// A sub-resource in the plan still takes the action over.
func TestValidate_UsedFeatureOwnedBySubresourceIsAbsorbed(t *testing.T) {
	rc := &plan.ResourceChange{
		Type: "aws_s3_bucket", Name: "b", Change: "create",
		Attributes:        map[string]bool{"policy": true},
		ChangedAttributes: map[string]bool{"policy": true},
	}
	if _, ok := defaultFindings(t, rc, "aws_s3_bucket_policy")["s3:PutBucketPolicy"]; ok {
		t.Error("s3:PutBucketPolicy reported on the bucket with aws_s3_bucket_policy in the plan")
	}
}

// The provider tags a bucket only when it has tags. The tagging call shows no
// gate in the schema, so the tool gates it on tags and tags_all.
func TestValidate_BucketTaggingNeededWithTags(t *testing.T) {
	for _, attr := range []string{"tags", "tags_all"} {
		rc := &plan.ResourceChange{Type: "aws_s3_bucket", Name: "b", Change: "create", Attributes: map[string]bool{attr: true}}
		m, ok := defaultFindings(t, rc)["s3:PutBucketTagging"]
		if !ok {
			t.Errorf("%s set: s3:PutBucketTagging not reported", attr)
			continue
		}
		if m.Class != ClassManagement || m.ConditionAttribute != attr {
			t.Errorf("%s set: class, condition = %q, %q; want \"management\", %s", attr, m.Class, m.ConditionAttribute, attr)
		}
	}
	rc := &plan.ResourceChange{Type: "aws_s3_bucket", Name: "b", Change: "create", Attributes: map[string]bool{"bucket": true}}
	if _, ok := defaultFindings(t, rc)["s3:PutBucketTagging"]; ok {
		t.Error("s3:PutBucketTagging reported on a bucket without tags")
	}
}

// A best-effort call stays optional even when its feature is used, since its
// failure does not fail the apply.
func TestValidate_UsedBestEffortStaysOptional(t *testing.T) {
	schema := fakeSchema{"create": {{Action: "s3:PutBucketPolicy", Gate: Gate{Changed: "policy", BestEffort: true}}}}
	rc := &plan.ResourceChange{Type: "aws_s3_bucket", Name: "b", Change: "create", ChangedAttributes: map[string]bool{"policy": true}}
	missing, err := Validate([]*plan.ResourceChange{rc}, grantNothing(), fakeResolver{schema}, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("missing = %+v, want the best-effort call filtered", missing)
	}
}
