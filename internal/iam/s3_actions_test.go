package iam

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// The two S3 name spaces that reach classifyPermission. The CloudFormation
// registry resolves aws_s3_bucket when the provider checkout is unavailable,
// and the provider-source parser resolves the aws_s3_bucket_* sub-resources.
// Both fixtures are golden copies, so these tests stay hermetic.
const (
	cfnS3BucketFixture      = "../../testdata/cfn/aws-s3-bucket.json"
	parserS3BucketFixture   = "../../testdata/provider-aws/s3-bucket-actions.json"
	parserS3ParentFixtureID = "aws_s3_bucket"
)

// s3RequiredActions lists the S3 actions that stay [required]: the bucket's
// own lifecycle and location, its ACL, and the object-level calls of
// aws_s3_bucket_object.
// Every other S3 action either side emits is an optional bucket feature.
var s3RequiredActions = map[string]bool{
	"s3:CreateBucket":       true,
	"s3:DeleteBucket":       true,
	"s3:GetBucketLocation":  true,
	"s3:ListBucket":         true,
	"s3:ListAllMyBuckets":   true,
	"s3:GetBucketAcl":       true,
	"s3:PutBucketAcl":       true,
	"iam:PassRole":          true,
	"s3:PutObjectLegalHold": true,
	"s3:PutObjectRetention": true,
}

// cfnS3BucketHandlers returns the handler permissions of AWS::S3::Bucket,
// keyed by operation.
func cfnS3BucketHandlers(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(cfnS3BucketFixture)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Handlers map[string]struct {
			Permissions []string `json:"permissions"`
		} `json:"handlers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	perms := make(map[string][]string, len(doc.Handlers))
	for op, h := range doc.Handlers {
		perms[op] = h.Permissions
	}
	return perms
}

// parserS3BucketResources returns the actions the provider-source parser
// emits for each aws_s3_bucket* type, keyed by type, then operation.
func parserS3BucketResources(t *testing.T) map[string]map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(parserS3BucketFixture)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Resources map[string]map[string][]string `json:"resources"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Resources
}

// actionSet flattens per-operation action lists into a set.
func actionSet(perms map[string][]string) map[string]bool {
	set := make(map[string]bool)
	for _, actions := range perms {
		for _, a := range actions {
			set[a] = true
		}
	}
	return set
}

// emittedS3Actions returns every action either name space emits for the
// aws_s3_bucket family.
func emittedS3Actions(t *testing.T) map[string]bool {
	t.Helper()
	set := actionSet(cfnS3BucketHandlers(t))
	for _, perms := range parserS3BucketResources(t) {
		for a := range actionSet(perms) {
			set[a] = true
		}
	}
	return set
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestS3OptionalPrefixes_EveryRowClassifiesOptional(t *testing.T) {
	for _, p := range s3OptionalPrefixes {
		if got := classifyPermission(p); got != ClassOptional {
			t.Errorf("classifyPermission(%q) = %d, want ClassOptional", p, got)
		}
	}
}

// The table matches by prefix, so a longer name that starts with a row is
// optional too.
func TestS3OptionalPrefixes_PrefixMatchesSuffix(t *testing.T) {
	for _, p := range s3OptionalPrefixes {
		if got := classifyPermission(p + "SomethingElse"); got != ClassOptional {
			t.Errorf("classifyPermission(%q) = %d, want ClassOptional", p+"SomethingElse", got)
		}
	}
}

// A row that matches no emitted name is a misspelling: it can never fire.
func TestS3OptionalPrefixes_EveryRowMatchesAnEmittedName(t *testing.T) {
	emitted := sortedKeys(emittedS3Actions(t))
	for _, p := range s3OptionalPrefixes {
		found := false
		for _, a := range emitted {
			if strings.HasPrefix(a, p) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("s3OptionalPrefixes row %q matches no action the schema or the parser emits", p)
		}
	}
}

// classifyPermission returns on the first row that matches, so a row another
// row already covers is dead: it reads as coverage but can never be the reason
// an action is optional.
func TestS3OptionalPrefixes_NoRowIsShadowedByAnEarlierRow(t *testing.T) {
	for i, p := range s3OptionalPrefixes {
		first := ""
		for _, q := range s3OptionalPrefixes {
			if strings.HasPrefix(p, q) {
				first = q
				break
			}
		}
		if first != p {
			t.Errorf("s3OptionalPrefixes[%d] %q is shadowed by the earlier row %q", i, p, first)
		}
		if got := classifyPermission(p); got != ClassOptional {
			t.Errorf("classifyPermission(%q) = %d, want ClassOptional", p, got)
		}
	}
}

// Every S3 action that either name space emits for the bucket family is an
// optional feature, data-plane, or on the short required list.
func TestSchemaEmittedS3Actions_AreClassified(t *testing.T) {
	for _, a := range sortedKeys(emittedS3Actions(t)) {
		if s3RequiredActions[a] {
			if got := classifyPermission(a); got != ClassManagement {
				t.Errorf("classifyPermission(%q) = %d, want ClassManagement", a, got)
			}
			continue
		}
		if got := classifyPermission(a); got != ClassOptional && got != ClassDataPlane {
			t.Errorf("classifyPermission(%q) = %d, want ClassOptional or ClassDataPlane", a, got)
		}
	}
}

// A dedicated aws_s3_bucket_* resource exists to make its configuration call,
// so on that resource the call is [required], not [optional].
func TestS3SubresourceActions_AreRequiredOnTheSubresource(t *testing.T) {
	for tfType, perms := range parserS3BucketResources(t) {
		if tfType == parserS3ParentFixtureID {
			continue
		}
		for _, a := range sortedKeys(actionSet(perms)) {
			// aws_s3_bucket_object is the object resource, not a bucket-feature
			// configurator: its s3:PutObjectAcl is data-plane on purpose, so it
			// is excluded by name. Every aws_s3_bucket_* configurator exists to
			// make its call, which is [required] and nothing else.
			if tfType == "aws_s3_bucket_object" {
				continue
			}
			got := classifyResourcePermission(tfType, a)
			if got != ClassManagement {
				t.Errorf("classifyResourcePermission(%q, %q) = %s, want ClassManagement",
					tfType, a, classTag(got))
			}
		}
	}
}

// Absorption removes a parent action because a sub-resource owns it, so each
// row must be a name the parent schema emits or that the sub-resource itself
// emits (the parser's spelling of the same call).
func TestS3SubresourcePermissions_EveryRowMatchesASchemaName(t *testing.T) {
	parent := actionSet(cfnS3BucketHandlers(t))
	parser := parserS3BucketResources(t)
	for subType, actions := range s3SubresourcePermissions {
		own := actionSet(parser[subType])
		for _, a := range actions {
			if !parent[a] && !own[a] {
				t.Errorf("s3SubresourcePermissions[%q] has %q, which neither the parent schema nor the sub-resource emits", subType, a)
			}
		}
	}
}

// TestValidate_BareS3Bucket reproduces issue #75: a bucket with only a name,
// resolved through the CloudFormation schema, against an empty policy.
func TestValidate_BareS3Bucket(t *testing.T) {
	resolver := fakeResolver{fakeSchema{perms: cfnS3BucketHandlers(t)}}
	tests := []struct {
		change string
		want   []string
	}{
		{"create", []string{"iam:PassRole", "s3:CreateBucket", "s3:GetBucketAcl", "s3:ListBucket"}},
		{"delete", []string{"s3:DeleteBucket", "s3:ListBucket"}},
	}
	for _, tt := range tests {
		t.Run(tt.change, func(t *testing.T) {
			changes := []*plan.ResourceChange{{Type: "aws_s3_bucket", Name: "logs", Change: tt.change}}
			missing, err := Validate(changes, denyAll{}, resolver, DefaultFilter())
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[string]bool)
			for _, m := range missing {
				got[m.Action] = true
				if m.Class != "[required]" {
					t.Errorf("%s: class %s, want [required]", m.Action, m.Class)
				}
			}
			if strings.Join(sortedKeys(got), ",") != strings.Join(tt.want, ",") {
				t.Errorf("missing = %v, want %v", sortedKeys(got), tt.want)
			}
		})
	}
}

// A dedicated sub-resource still reports its own call as [required] under the
// default filter, even though the same call is optional on aws_s3_bucket.
func TestValidate_S3SubresourceKeepsItsOwnAction(t *testing.T) {
	resolver := fakeResolver{fakeSchema{perms: map[string][]string{
		"update": {"s3:PutBucketVersioning"},
	}}}
	changes := []*plan.ResourceChange{{Type: "aws_s3_bucket_versioning", Name: "logs", Change: "update"}}
	missing, err := Validate(changes, denyAll{}, resolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].Action != "s3:PutBucketVersioning" || missing[0].Class != "[required]" {
		t.Errorf("missing = %+v, want s3:PutBucketVersioning [required]", missing)
	}
}

// typeResolver resolves each terraform type to its own schema.
type typeResolver map[string]SchemaLike

func (r typeResolver) Resolve(tfType string) (SchemaLike, error) {
	if s, ok := r[tfType]; ok {
		return s, nil
	}
	return fakeSchema{}, nil
}

// With every sub-resource in the plan, the parent bucket's update keeps only
// the actions that no sub-resource owns. Optional actions are kept here, so
// absorption alone has to remove the CloudFormation spellings.
func TestValidate_S3SubresourcesAbsorbParentSchemaNames(t *testing.T) {
	resolver := typeResolver{"aws_s3_bucket": fakeSchema{perms: cfnS3BucketHandlers(t)}}
	changes := []*plan.ResourceChange{{Type: "aws_s3_bucket", Name: "logs", Change: "update"}}
	for subType := range s3SubresourcePermissions {
		changes = append(changes, &plan.ResourceChange{Type: subType, Name: "logs", Change: "update"})
	}
	missing, err := Validate(changes, denyAll{}, resolver, FilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool)
	for _, m := range missing {
		if m.ResourceType == "aws_s3_bucket" && m.Service == "s3" {
			got[m.Action] = true
		}
	}
	want := []string{
		"s3:CreateBucketMetadataTableConfiguration",
		"s3:DeleteBucketMetadataTableConfiguration",
		"s3:GetBucketMetadataTableConfiguration",
		"s3:ListBucket",
		"s3:PutBucketAbac",
		"s3:PutBucketTagging",
		"s3:TagResource",
		"s3:UntagResource",
		"s3:UpdateBucketMetadataAnnotationTableConfiguration",
		"s3:UpdateBucketMetadataInventoryTableConfiguration",
		"s3:UpdateBucketMetadataJournalTableConfiguration",
	}
	if strings.Join(sortedKeys(got), ",") != strings.Join(want, ",") {
		t.Errorf("parent actions left = %v, want %v", sortedKeys(got), want)
	}
}
