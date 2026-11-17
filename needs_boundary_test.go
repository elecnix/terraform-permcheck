package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The permissions boundary cases of issue #175. Each role of
// testdata/principals/boundaries.json is one case. Every role exists, so the
// plan knows its ARN, and a statement that names the role's ARN grants it
// under --strict-resources too:
//
//   - limited: an inline policy allows s3:GetObject on app-data, and the
//     boundary aws_iam_policy.logs_only allows logs:* only.
//   - allowed: the same inline policy, and the boundary
//     aws_iam_policy.s3_read allows s3:GetObject.
//   - computed: the same inline policy, and the text of the boundary
//     aws_iam_policy.computed is known only after apply.
//   - denied: the same inline policy, and the boundary aws_iam_policy.deny_data
//     allows every action but denies s3:GetObject on app-data.
//   - managed: an inline policy allows s3:GetObject and sqs:SendMessage, and
//     the boundary is the AWS managed AmazonS3ReadOnlyAccess, whose text a
//     data "aws_iam_policy" block gives.
//   - managed_unread: the same inline policy, and the boundary is the AWS
//     managed PowerUserAccess, which no data block reads.
//   - bucket_reader: no identity policy. The bucket policy of app-shared
//     grants s3:GetObject to the role's ARN, and the boundary allows logs:*
//     only.
//   - session_reader: no identity policy. The bucket policy of app-shared
//     grants s3:GetObject to a session of the role, and the boundary allows
//     logs:* only.
//   - excluded: an inline policy allows s3:GetObject on app-locked, whose
//     bucket policy denies every principal but the role and its account
//     through NotPrincipal. The role's boundary allows s3:GetObject.
//   - plain: the inline policy of limited, and no boundary.
const boundariesPlan = "testdata/principals/boundaries.json"

// The needs of the boundary cases.
const (
	readData     = `"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::app-data/report.csv"]`
	writeData    = `"actions": ["s3:PutObject"], "resources": ["arn:aws:s3:::app-data/report.csv"]`
	writeLogs    = `"actions": ["logs:PutLogEvents"], "resources": ["arn:aws:logs:us-east-1:123456789012:log-group:app:*"]`
	sendJobsNeed = `"actions": ["sqs:SendMessage"], "resources": ["arn:aws:sqs:us-east-1:123456789012:app-jobs"]`
	readShared   = `"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::app-shared/report.csv"]`
	readLocked   = `"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::app-locked/report.csv"]`
)

// boundaryConfig maps one role of the boundaries plan to the label of the
// same name and gives it the needs, each a sid and its need body.
func boundaryConfig(t *testing.T, label string, needs ...[2]string) string {
	t.Helper()
	var list []string
	for _, n := range needs {
		list = append(list, `{"sid": "`+n[0]+`", "principal": "`+label+`", `+n[1]+`}`)
	}
	return writeConfig(t, t.TempDir(), `{
		"principals": {"`+label+`": {"address": "aws_iam_role.`+label+`"}},
		"needs": [`+strings.Join(list, ",")+`]
	}`)
}

// boundaryFindings runs the boundaries plan with the config in json format,
// in the default mode or under --strict-resources, and collapses each
// finding to "sid action [unverified reason] [boundary name]".
func boundaryFindings(t *testing.T, config string, strict bool) []string {
	t.Helper()
	args := []string{"--plan-file", boundariesPlan, "--config", config, "--format", "json"}
	if strict {
		args = append(args, "--strict-resources")
	}
	stdout, stderr, err := runValidate(t, args...)
	if err != nil && !errors.Is(err, errGapsFound) {
		t.Fatalf("strict %v: %v\nstderr:\n%s", strict, err, stderr)
	}
	var out struct {
		Missing []struct {
			Need          string   `json:"need"`
			MissingAction string   `json:"missing_action"`
			Unverified    string   `json:"unverified"`
			Boundary      string   `json:"boundary"`
			GrantedOn     []string `json:"granted_on"`
		} `json:"missing"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &out); jerr != nil {
		t.Fatalf("invalid JSON: %v\nstdout:\n%s", jerr, stdout)
	}
	var got []string
	for _, m := range out.Missing {
		s := m.Need + " " + m.MissingAction
		if m.Unverified != "" {
			s += " unverified " + m.Unverified
		}
		if m.Boundary != "" {
			s += " boundary " + m.Boundary
		}
		if len(m.GrantedOn) > 0 {
			s += " granted_on " + strings.Join(m.GrantedOn, ",")
		}
		got = append(got, s)
	}
	return got
}

// checkBoundaryCase checks the findings of one config in both modes.
func checkBoundaryCase(t *testing.T, config string, want, wantStrict []string) {
	t.Helper()
	if got := boundaryFindings(t, config, false); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("default findings =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := boundaryFindings(t, config, true); strings.Join(got, "\n") != strings.Join(wantStrict, "\n") {
		t.Errorf("strict findings =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantStrict, "\n"))
	}
}

// The identity policies and a boundary give "the intersection of the two
// categories". An inline policy allows s3:GetObject, and the boundary in the
// plan allows logs:* only, so the need is missing in both modes. The
// finding names the boundary, in the json entry and in the text report.
func TestBoundary_DoesNotAllowMakesNeedMissing(t *testing.T) {
	config := boundaryConfig(t, "limited", [2]string{"ReadData", readData})
	want := []string{"ReadData s3:GetObject boundary aws_iam_policy.logs_only"}
	checkBoundaryCase(t, config, want, want)

	// The text report goes to stderr.
	_, text, err := runValidate(t, "--plan-file", boundariesPlan, "--config", config)
	if !errors.Is(err, errGapsFound) {
		t.Fatalf("text: want errGapsFound, got %v", err)
	}
	if line := "      not allowed by the permissions boundary aws_iam_policy.logs_only\n"; !strings.Contains(text, line) {
		t.Errorf("text report has no line %q:\n%s", line, text)
	}
	if strings.Contains(text, "granted only on") {
		t.Errorf("text report lists the resources the identity policy grants, which cover the need:\n%s", text)
	}

	stdout, _, _ := runValidate(t, "--plan-file", boundariesPlan, "--config", config, "--format", "github-annotations")
	if note := "; not allowed by the permissions boundary aws_iam_policy.logs_only"; !strings.Contains(stdout, note) {
		t.Errorf("annotations have no %q:\n%s", note, stdout)
	}
}

// A boundary that allows the action doesn't change the verdict: the need is
// covered, and covered under --strict-resources too.
func TestBoundary_AllowsKeepsNeedCovered(t *testing.T) {
	checkBoundaryCase(t, boundaryConfig(t, "allowed", [2]string{"ReadData", readData}), nil, nil)
}

// A boundary whose text is known only after apply may limit the need but
// can't prove a gap. The need is covered with a notice, and unverified with
// the reason policy_unknown under --strict-resources.
func TestBoundary_UnknownText(t *testing.T) {
	config := boundaryConfig(t, "computed", [2]string{"ReadData", readData})
	checkBoundaryCase(t, config, nil, []string{"ReadData s3:GetObject unverified policy_unknown"})

	_, stderr, _ := runValidate(t, "--plan-file", boundariesPlan, "--config", config)
	if line := `notice: aws_iam_role.computed: the text of aws_iam_policy.computed is known only after apply; needs of "computed" may be limited by it` + "\n"; !strings.Contains(stderr, line) {
		t.Errorf("stderr has no line %q:\n%s", line, stderr)
	}
	r, _ := runValidateJSON(t, "--plan-file", boundariesPlan, "--config", config)
	if got, want := sourcesOf(t, r, "computed"), []string{
		"aws_iam_role.computed aws_iam_policy.computed unknown computed yes",
		"aws_iam_role_policy.computed  known  yes",
	}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// An explicit Deny in the boundary denies the need, although the boundary
// allows every other action. The finding names the boundary.
func TestBoundary_ExplicitDeny(t *testing.T) {
	want := []string{"ReadData s3:GetObject boundary aws_iam_policy.deny_data"}
	checkBoundaryCase(t, boundaryConfig(t, "denied", [2]string{"ReadData", readData}), want, want)
}

// An AWS managed boundary with a data "aws_iam_policy" block: its text
// decides. AmazonS3ReadOnlyAccess allows s3:GetObject, so ReadData is
// covered. It doesn't allow sqs:SendMessage, so SendJobs is missing, and the
// finding names the data block. No notice is printed for the boundary.
func TestBoundary_AWSManagedWithDataBlock(t *testing.T) {
	config := boundaryConfig(t, "managed", [2]string{"ReadData", readData}, [2]string{"SendJobs", sendJobsNeed})
	want := []string{"SendJobs sqs:SendMessage boundary data.aws_iam_policy.s3_read_only"}
	checkBoundaryCase(t, config, want, want)

	_, stderr, _ := runValidate(t, "--plan-file", boundariesPlan, "--config", config)
	if strings.Contains(stderr, "aws_iam_role.managed") {
		t.Errorf("stderr has a notice for the boundary, whose text the data block gives:\n%s", stderr)
	}
	r, _ := runValidateJSON(t, "--plan-file", boundariesPlan, "--config", config)
	var kinds []string
	for _, p := range r.PolicySources {
		for _, s := range p.Sources {
			kinds = append(kinds, s.Address+" "+s.Kind+" "+s.Text)
		}
	}
	if got, want := strings.Join(kinds, "\n"), "aws_iam_role.managed boundary known\naws_iam_role_policy.managed identity known"; got != want {
		t.Errorf("sources =\n%s\nwant\n%s", got, want)
	}
}

// An AWS managed boundary without a data block is an unknown source. Both
// needs are covered by default, with a notice that gives the fix, and
// unverified with the reason policy_unknown under --strict-resources.
func TestBoundary_AWSManagedWithoutDataBlock(t *testing.T) {
	config := boundaryConfig(t, "managed_unread", [2]string{"ReadData", readData}, [2]string{"SendJobs", sendJobsNeed})
	checkBoundaryCase(t, config, nil, []string{
		"ReadData s3:GetObject unverified policy_unknown",
		"SendJobs sqs:SendMessage unverified policy_unknown",
	})
	_, stderr, _ := runValidate(t, "--plan-file", boundariesPlan, "--config", config)
	line := `notice: aws_iam_role.managed_unread: arn:aws:iam::aws:policy/PowerUserAccess is a managed policy that the plan doesn't contain; needs of "managed_unread" may be limited by it; a data "aws_iam_policy" block with this arn gives PermCheck its text` + "\n"
	if !strings.Contains(stderr, line) {
		t.Errorf("stderr has no line %q:\n%s", line, stderr)
	}
}

// A resource policy that grants the role's ARN is limited by the boundary,
// as the identity policies are. The boundary doesn't allow s3:GetObject, so
// the need is missing, and the finding names the boundary.
func TestBoundary_LimitsResourcePolicyGrantToRoleARN(t *testing.T) {
	want := []string{"ReadShared s3:GetObject boundary aws_iam_policy.logs_only"}
	checkBoundaryCase(t, boundaryConfig(t, "bucket_reader", [2]string{"ReadShared", readShared}), want, want)
}

// A resource policy that grants a session of the role grants the session
// directly, and the boundary doesn't limit that grant. A session ARN may or
// may not be the session that makes the request, so the need is covered by
// default and unverified with the reason condition under
// --strict-resources.
func TestBoundary_DoesNotLimitGrantToSession(t *testing.T) {
	checkBoundaryCase(t, boundaryConfig(t, "session_reader", [2]string{"ReadShared", readShared}),
		nil, []string{"ReadShared s3:GetObject unverified condition"})
}

// A NotPrincipal Deny always denies a principal with a boundary, whatever its
// list holds. The bucket policy lists the role and its account, so the Deny
// is definite and the need is missing. The boundary allows the action, so
// the finding doesn't name it. It lists the resources the inline policy
// grants, as for any finding that a Deny on part of a grant causes.
func TestBoundary_NotPrincipalDenyIsDefinite(t *testing.T) {
	want := []string{"ReadLocked s3:GetObject granted_on arn:aws:s3:::app-locked/*"}
	checkBoundaryCase(t, boundaryConfig(t, "excluded", [2]string{"ReadLocked", readLocked}), want, want)
}

// A need that the identity policies don't grant is missing whatever the
// boundary allows. The boundary isn't the cause, so the finding doesn't name
// it.
func TestBoundary_IdentityGapHasNoBoundaryNote(t *testing.T) {
	want := []string{"WriteLogs logs:PutLogEvents"}
	checkBoundaryCase(t, boundaryConfig(t, "limited", [2]string{"WriteLogs", writeLogs}), want, want)
}

// A role without a boundary keeps its verdicts: the inline policy covers
// ReadData, and no policy grants WriteData, which is missing. The json
// report lists no boundary source.
func TestBoundary_RoleWithoutBoundaryUnchanged(t *testing.T) {
	want := []string{"WriteData s3:PutObject"}
	checkBoundaryCase(t, boundaryConfig(t, "plain", [2]string{"ReadData", readData}, [2]string{"WriteData", writeData}), want, want)
	r, _ := runValidateJSON(t, "--plan-file", boundariesPlan, "--config", boundaryConfig(t, "plain", [2]string{"ReadData", readData}))
	for _, p := range r.PolicySources {
		for _, s := range p.Sources {
			if s.Kind == "boundary" {
				t.Errorf("a role without a boundary lists the boundary source %+v", s)
			}
		}
	}
}
