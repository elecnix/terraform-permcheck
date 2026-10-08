package iam

import (
	"os"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// logsResolver serves the permissions the provider source yields for the
// CloudWatch Logs resources in testdata/logs_plan.json.
var logsResolver = typeKeyedResolver{
	"aws_cloudwatch_log_group": fakeSchema{perms: map[string][]string{
		"create": {"logs:CreateLogGroup", "logs:PutRetentionPolicy"},
	}},
	"aws_cloudwatch_log_stream": fakeSchema{perms: map[string][]string{
		"create": {"logs:CreateLogStream"},
	}},
}

// logsPlan parses the plan from issue #54: a log group under
// /aws/kinesisfirehose and a log stream in it.
func logsPlan(t *testing.T) []*plan.ResourceChange {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/logs_plan.json")
	if err != nil {
		t.Fatal(err)
	}
	changes, err := plan.Parse(raw, "aws_")
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

func TestLogGroupTargetARNs(t *testing.T) {
	changes := logsPlan(t)
	group := resourceTargetARNs(changes[0], changes)
	want := []string{
		"arn:*:logs:*:*:log-group:/aws/kinesisfirehose/example-stream",
		"arn:*:logs:*:*:log-group:/aws/kinesisfirehose/example-stream:*",
	}
	if !equalStrings(group, want) {
		t.Errorf("log group targets = %v, want %v", group, want)
	}
	stream := resourceTargetARNs(changes[1], changes)
	want = []string{
		"arn:*:logs:*:*:log-group:/aws/kinesisfirehose/example-stream",
		"arn:*:logs:*:*:log-group:/aws/kinesisfirehose/example-stream:*",
		"arn:*:logs:*:*:log-group:/aws/kinesisfirehose/example-stream:log-stream:delivery",
	}
	if !equalStrings(stream, want) {
		t.Errorf("log stream targets = %v, want %v", stream, want)
	}
}

func TestLogStreamTargetFromReference(t *testing.T) {
	// The group's name is unknown in the stream's planned values, so the
	// target comes from the referenced aws_cloudwatch_log_group.
	changes := logsPlan(t)
	delete(changes[1].AttributeValues, "log_group_name")
	got := resourceTargetARNs(changes[1], changes)
	if len(got) == 0 || got[0] != "arn:*:logs:*:*:log-group:/aws/kinesisfirehose/example-stream" {
		t.Errorf("log stream targets = %v, want the referenced group's ARN first", got)
	}
}

// TestValidate_LogGroupGrantScopedElsewhere is case 2 of issue #54: the policy
// grants the log-group actions on two other prefixes only.
func TestValidate_LogGroupGrantScopedElsewhere(t *testing.T) {
	changes := logsPlan(t)
	raw, err := os.ReadFile("../../testdata/logs_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := Validate(changes, policy, logsResolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"logs:CreateLogGroup", "logs:PutRetentionPolicy"} {
		if !hasActionOn(missing, action, "aws_cloudwatch_log_group", "x") {
			t.Errorf("expected %s missing on aws_cloudwatch_log_group.x, got %+v", action, missing)
		}
	}
	if !hasActionOn(missing, "logs:CreateLogStream", "aws_cloudwatch_log_stream", "y") {
		t.Errorf("expected logs:CreateLogStream missing on aws_cloudwatch_log_stream.y, got %+v", missing)
	}
}

// TestValidate_LogGroupGrantMatchingPrefix grants the same actions on the
// plan's prefix in each ARN form IAM policies use for log groups.
func TestValidate_LogGroupGrantMatchingPrefix(t *testing.T) {
	for _, resource := range []string{
		"arn:aws:logs:us-east-1:111111111111:log-group:/aws/kinesisfirehose/*",
		"arn:aws:logs:us-east-1:111111111111:log-group:/aws/kinesisfirehose/example-stream:*",
		"arn:aws:logs:*:*:log-group:/aws/kinesisfirehose/example-*:*",
		"arn:aws:logs:us-east-1:111111111111:*",
	} {
		t.Run(resource, func(t *testing.T) {
			policy, err := ParsePolicy([]byte(`{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": ["logs:CreateLogGroup", "logs:PutRetentionPolicy", "logs:CreateLogStream"],
					"Resource": "` + resource + `"
				}]
			}`))
			if err != nil {
				t.Fatal(err)
			}
			changes := logsPlan(t)
			missing, err := Validate(changes, policy, logsResolver, DefaultFilter())
			if err != nil {
				t.Fatal(err)
			}
			if len(missing) != 0 {
				t.Errorf("expected no findings, got %+v", missing)
			}
		})
	}
}

// TestValidate_LogGroupGrantOtherPrefixWithStarSuffix checks the `:*` grant
// form against a different prefix. Its segment count differs from the plain
// log-group ARN, so it is compared against the `:*` target.
func TestValidate_LogGroupGrantOtherPrefixWithStarSuffix(t *testing.T) {
	policy, err := ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["logs:CreateLogGroup", "logs:PutRetentionPolicy", "logs:CreateLogStream"],
			"Resource": "arn:aws:logs:us-east-1:111111111111:log-group:/aws/lambda/*:*"
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	changes := logsPlan(t)
	missing, err := Validate(changes, policy, logsResolver, DefaultFilter())
	if err != nil {
		t.Fatal(err)
	}
	if !hasActionOn(missing, "logs:CreateLogGroup", "aws_cloudwatch_log_group", "x") {
		t.Errorf("expected logs:CreateLogGroup missing, got %+v", missing)
	}
	if !hasActionOn(missing, "logs:CreateLogStream", "aws_cloudwatch_log_stream", "y") {
		t.Errorf("expected logs:CreateLogStream missing, got %+v", missing)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
