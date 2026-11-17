package main

import (
	"errors"
	"strings"
	"testing"
)

// The resource policies of S3, SQS, SNS and ECR join the check of a mapped
// need, as the Secrets Manager policies do. Each fixture maps the role
// aws_iam_role.task, whose ARN the plan knows, so a statement that names the
// role's ARN grants it under --strict-resources too.

// serviceConfig returns a config that maps the task role and gives it the
// needs, each one a JSON object without its principal.
func serviceConfig(t *testing.T, needs ...string) string {
	t.Helper()
	for i, n := range needs {
		needs[i] = `{"principal": "task", ` + n + `}`
	}
	return writeConfig(t, t.TempDir(), `{
		"principals": {"task": {"address": "aws_iam_role.task"}},
		"needs": [`+strings.Join(needs, ",")+`]
	}`)
}

// noticeFor is the notice line that the text report prints for a policy
// source of the task role whose text is computed.
func noticeFor(address string) string {
	return "notice: " + address + `: policy text is known only after apply; needs of "task" may be granted by it`
}

// checkNotice runs the plan in the default mode and checks whether stderr
// has the notice of the address.
func checkNotice(t *testing.T, plan, config, address string, want bool) {
	t.Helper()
	_, stderr, err := runValidate(t, "--plan-file", plan, "--config", config)
	if err != nil && !errors.Is(err, errGapsFound) {
		t.Fatalf("%s: %v", plan, err)
	}
	if got := strings.Contains(stderr, noticeFor(address)); got != want {
		t.Errorf("%s: notice for %s = %v, want %v\nstderr:\n%s", plan, address, got, want, stderr)
	}
}

// The S3 needs: one on objects under a prefix, and one on the bucket.
const (
	readReports  = `"sid": "ReadReports", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::app-data/reports/*"]`
	listData     = `"sid": "ListData", "actions": ["s3:ListBucket"], "resources": ["arn:aws:s3:::app-data"]`
	readReportsF = "ReadReports s3:GetObject"
	listDataF    = "ListData s3:ListBucket"
)

func TestServicePolicies_S3(t *testing.T) {
	config := serviceConfig(t, readReports, listData)
	both := []string{readReportsF, listDataF}
	for _, c := range []resourcePolicyCase{
		{
			// The bucket policy grants GetObject on the objects and
			// ListBucket on the bucket, and no identity policy grants
			// either.
			name: "bucket policy grants the role",
			plan: "testdata/principals/s3_grant.json",
		},
		{
			name:       "no bucket policy",
			plan:       "testdata/principals/s3_no_policy.json",
			want:       both,
			wantStrict: both,
		},
		{
			// An identity policy grants both actions on every resource.
			name:       "bucket policy Deny for every principal",
			plan:       "testdata/principals/s3_deny.json",
			want:       both,
			wantStrict: both,
		},
		{
			name:       "policy of another bucket",
			plan:       "testdata/principals/s3_other_bucket.json",
			want:       both,
			wantStrict: both,
		},
		{
			name:       "bucket policy text computed",
			plan:       "testdata/principals/s3_policy_computed.json",
			wantStrict: []string{readReportsF + " unverified policy_unknown", listDataF + " unverified policy_unknown"},
		},
		{
			// GetObject on the bucket ARN grants no object, and ListBucket
			// on the objects doesn't grant the bucket.
			name:       "statements on the wrong level",
			plan:       "testdata/principals/s3_swapped_resources.json",
			want:       both,
			wantStrict: both,
		},
		{
			// The deprecated policy attribute of aws_s3_bucket.
			name: "policy attribute of the bucket",
			plan: "testdata/principals/s3_bucket_policy_attribute.json",
		},
	} {
		c.config = config
		t.Run(c.name, c.check)
	}
	checkNotice(t, "testdata/principals/s3_policy_computed.json", config, "aws_s3_bucket_policy.data", true)
	// A bucket whose configuration doesn't write its policy attribute sets no
	// policy, so it gets no notice.
	checkNotice(t, "testdata/principals/s3_no_policy.json", config, "aws_s3_bucket.data", false)
}

const (
	sendJobs  = `"sid": "SendJobs", "actions": ["sqs:SendMessage"], "resources": ["arn:aws:sqs:us-east-1:123456789012:app-jobs"]`
	sendJobsF = "SendJobs sqs:SendMessage"
)

func TestServicePolicies_SQS(t *testing.T) {
	config := serviceConfig(t, sendJobs)
	missing := []string{sendJobsF}
	for _, c := range []resourcePolicyCase{
		{
			name: "queue policy grants the role",
			plan: "testdata/principals/sqs_grant.json",
		},
		{
			name:       "no queue policy",
			plan:       "testdata/principals/sqs_no_policy.json",
			want:       missing,
			wantStrict: missing,
		},
		{
			name:       "queue policy Deny for every principal",
			plan:       "testdata/principals/sqs_deny.json",
			want:       missing,
			wantStrict: missing,
		},
		{
			name:       "policy of another queue",
			plan:       "testdata/principals/sqs_other_queue.json",
			want:       missing,
			wantStrict: missing,
		},
		{
			name:       "queue policy text computed",
			plan:       "testdata/principals/sqs_policy_computed.json",
			wantStrict: []string{sendJobsF + " unverified policy_unknown"},
		},
		{
			name: "policy attribute of the queue",
			plan: "testdata/principals/sqs_queue_policy_attribute.json",
		},
		{
			// The queue is outside the plan, and queue_url holds its known
			// URL.
			name: "queue named by its known URL",
			plan: "testdata/principals/sqs_known_url.json",
		},
		{
			name:       "known URL of another queue",
			plan:       "testdata/principals/sqs_known_url.json",
			config:     serviceConfig(t, `"sid": "SendJobs", "actions": ["sqs:SendMessage"], "resources": ["arn:aws:sqs:us-east-1:123456789012:app-other"]`),
			want:       missing,
			wantStrict: missing,
		},
	} {
		if c.config == "" {
			c.config = config
		}
		t.Run(c.name, c.check)
	}
	checkNotice(t, "testdata/principals/sqs_policy_computed.json", config, "aws_sqs_queue_policy.jobs", true)
}

const (
	publishEvents  = `"sid": "PublishEvents", "actions": ["sns:Publish"], "resources": ["arn:aws:sns:us-east-1:123456789012:app-events"]`
	publishEventsF = "PublishEvents sns:Publish"
)

func TestServicePolicies_SNS(t *testing.T) {
	config := serviceConfig(t, publishEvents)
	missing := []string{publishEventsF}
	for _, c := range []resourcePolicyCase{
		{
			name: "topic policy grants the role",
			plan: "testdata/principals/sns_grant.json",
		},
		{
			// The topic gets AWS's default policy, which the plan doesn't
			// show. It grants the role nothing (see the README).
			name:       "no topic policy",
			plan:       "testdata/principals/sns_no_policy.json",
			want:       missing,
			wantStrict: missing,
		},
		{
			name:       "topic policy Deny for every principal",
			plan:       "testdata/principals/sns_deny.json",
			want:       missing,
			wantStrict: missing,
		},
		{
			name:       "policy of another topic",
			plan:       "testdata/principals/sns_other_topic.json",
			want:       missing,
			wantStrict: missing,
		},
		{
			name:       "topic policy text computed",
			plan:       "testdata/principals/sns_policy_computed.json",
			wantStrict: []string{publishEventsF + " unverified policy_unknown"},
		},
		{
			// A FIFO topic's name ends in .fifo, and so does its ARN.
			name:   "policy attribute of a FIFO topic",
			plan:   "testdata/principals/sns_fifo_topic_policy_attribute.json",
			config: serviceConfig(t, `"sid": "PublishEvents", "actions": ["sns:Publish"], "resources": ["arn:aws:sns:us-east-1:123456789012:app-events.fifo"]`),
		},
	} {
		if c.config == "" {
			c.config = config
		}
		t.Run(c.name, c.check)
	}
	checkNotice(t, "testdata/principals/sns_policy_computed.json", config, "aws_sns_topic_policy.events", true)
	// The default policy that AWS gives the topic is no source.
	checkNotice(t, "testdata/principals/sns_no_policy.json", config, "aws_sns_topic.events", false)
}

const (
	pullImage  = `"sid": "PullImage", "actions": ["ecr:BatchGetImage"], "resources": ["arn:aws:ecr:us-east-1:123456789012:repository/app"]`
	pullImageF = "PullImage ecr:BatchGetImage"
)

func TestServicePolicies_ECR(t *testing.T) {
	config := serviceConfig(t, pullImage)
	missing := []string{pullImageF}
	for _, c := range []resourcePolicyCase{
		{
			name: "repository policy grants the role",
			plan: "testdata/principals/ecr_grant.json",
		},
		{
			name:       "no repository policy",
			plan:       "testdata/principals/ecr_no_policy.json",
			want:       missing,
			wantStrict: missing,
		},
		{
			name:       "repository policy Deny for every principal",
			plan:       "testdata/principals/ecr_deny.json",
			want:       missing,
			wantStrict: missing,
		},
		{
			name:       "policy of another repository",
			plan:       "testdata/principals/ecr_other_repository.json",
			want:       missing,
			wantStrict: missing,
		},
		{
			name:       "repository policy text computed",
			plan:       "testdata/principals/ecr_policy_computed.json",
			wantStrict: []string{pullImageF + " unverified policy_unknown"},
		},
	} {
		c.config = config
		t.Run(c.name, c.check)
	}
	checkNotice(t, "testdata/principals/ecr_policy_computed.json", config, "aws_ecr_repository_policy.app", true)
}
