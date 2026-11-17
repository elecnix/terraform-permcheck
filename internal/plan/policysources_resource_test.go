package plan

import (
	"strings"
	"testing"
)

// secretPoliciesPlan has two secrets, app and other, and a secret policy for each
// way its secret_arn can name a secret: a reference, a known ARN, and a
// variable. The secret app also sets its policy inline, and other leaves
// its computed policy attribute out of the configuration.
const secretPoliciesPlan = `{
	"resource_changes": [
		{"address": "aws_secretsmanager_secret.app", "type": "aws_secretsmanager_secret", "name": "app",
		 "change": {"actions": ["create"], "after": {"name": "app-db", "policy": "{\"Statement\":[]}"}, "after_unknown": {"arn": true}}},
		{"address": "aws_secretsmanager_secret.other", "type": "aws_secretsmanager_secret", "name": "other",
		 "change": {"actions": ["create"], "after": {"name": "other-db"}, "after_unknown": {"arn": true, "policy": true}}},
		{"address": "aws_secretsmanager_secret_policy.by_ref", "type": "aws_secretsmanager_secret_policy", "name": "by_ref",
		 "change": {"actions": ["create"], "after": {"policy": "{}"}, "after_unknown": {"secret_arn": true}}},
		{"address": "aws_secretsmanager_secret_policy.by_arn", "type": "aws_secretsmanager_secret_policy", "name": "by_arn",
		 "change": {"actions": ["create"], "after": {"policy": "{}", "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"}, "after_unknown": {}}},
		{"address": "aws_secretsmanager_secret_policy.by_var", "type": "aws_secretsmanager_secret_policy", "name": "by_var",
		 "change": {"actions": ["create"], "after": {"policy": "{}"}, "after_unknown": {"secret_arn": true}}}
	],
	"configuration": {"root_module": {"resources": [
		{"address": "aws_secretsmanager_secret.app", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "app",
		 "expressions": {"name": {}, "policy": {}}},
		{"address": "aws_secretsmanager_secret.other", "mode": "managed", "type": "aws_secretsmanager_secret", "name": "other",
		 "expressions": {"name": {}}},
		{"address": "aws_secretsmanager_secret_policy.by_ref", "mode": "managed", "type": "aws_secretsmanager_secret_policy", "name": "by_ref",
		 "expressions": {"policy": {}, "secret_arn": {"references": ["aws_secretsmanager_secret.app.arn", "aws_secretsmanager_secret.app"]}}},
		{"address": "aws_secretsmanager_secret_policy.by_arn", "mode": "managed", "type": "aws_secretsmanager_secret_policy", "name": "by_arn",
		 "expressions": {"policy": {}, "secret_arn": {}}},
		{"address": "aws_secretsmanager_secret_policy.by_var", "mode": "managed", "type": "aws_secretsmanager_secret_policy", "name": "by_var",
		 "expressions": {"policy": {}, "secret_arn": {"references": ["var.secret_arn"]}}}
	]}}
}`

// TestPolicySources_SecretsManager checks that this version reads both
// Secrets Manager source types, and resolves each one to the secret it
// attaches to.
func TestPolicySources_SecretsManager(t *testing.T) {
	sources := PolicySources(parseRaw(t, secretPoliciesPlan), nil)
	var got []string
	for _, s := range sources {
		line := s.Address + " " + s.Path + " " + string(s.Kind) + " " + s.Service + " text=" + s.Text
		if s.Unknown || s.Unread {
			line += " unknown"
		}
		for _, r := range s.Resources {
			to := r.ARN
			if r.Change != nil {
				to = r.Change.Address
			}
			line += " -> " + to + " " + r.Match.String()
		}
		if s.ResourceUnknown {
			line += " -> unknown"
		}
		got = append(got, line)
	}
	want := []string{
		`aws_secretsmanager_secret.app policy resource secretsmanager text={"Statement":[]} -> aws_secretsmanager_secret.app yes`,
		`aws_secretsmanager_secret_policy.by_ref policy resource secretsmanager text={} -> aws_secretsmanager_secret.app yes`,
		`aws_secretsmanager_secret_policy.by_arn policy resource secretsmanager text={} -> arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf yes`,
		`aws_secretsmanager_secret_policy.by_var policy resource secretsmanager text={} -> unknown`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// servicePoliciesPlan has a resource policy of S3, SQS, SNS and ECR for each
// way its link can name the resource: a reference, and a known value that
// isn't an ARN. The queue sets its policy itself, and the topic leaves its
// computed policy attribute out of the configuration.
const servicePoliciesPlan = `{
	"resource_changes": [
		{"address": "aws_s3_bucket.data", "type": "aws_s3_bucket", "name": "data",
		 "change": {"actions": ["create"], "after": {"bucket": "app-data"}, "after_unknown": {"arn": true, "policy": true}}},
		{"address": "aws_s3_bucket_policy.by_ref", "type": "aws_s3_bucket_policy", "name": "by_ref",
		 "change": {"actions": ["create"], "after": {"policy": "{}"}, "after_unknown": {"bucket": true}}},
		{"address": "aws_s3_bucket_policy.by_name", "type": "aws_s3_bucket_policy", "name": "by_name",
		 "change": {"actions": ["create"], "after": {"policy": "{}", "bucket": "app-logs"}, "after_unknown": {}}},
		{"address": "aws_sqs_queue.jobs", "type": "aws_sqs_queue", "name": "jobs",
		 "change": {"actions": ["create"], "after": {"name": "app-jobs", "policy": "{}"}, "after_unknown": {"url": true}}},
		{"address": "aws_sqs_queue_policy.by_url", "type": "aws_sqs_queue_policy", "name": "by_url",
		 "change": {"actions": ["create"], "after": {"policy": "{}", "queue_url": "https://sqs.us-east-1.amazonaws.com/123456789012/app-jobs"}, "after_unknown": {}}},
		{"address": "aws_sns_topic.events", "type": "aws_sns_topic", "name": "events",
		 "change": {"actions": ["create"], "after": {"name": "app-events"}, "after_unknown": {"arn": true, "policy": true}}},
		{"address": "aws_sns_topic_policy.by_ref", "type": "aws_sns_topic_policy", "name": "by_ref",
		 "change": {"actions": ["create"], "after": {"policy": "{}"}, "after_unknown": {"arn": true}}},
		{"address": "aws_ecr_repository_policy.by_name", "type": "aws_ecr_repository_policy", "name": "by_name",
		 "change": {"actions": ["create"], "after": {"policy": "{}", "repository": "app"}, "after_unknown": {}}}
	],
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.data", "mode": "managed", "type": "aws_s3_bucket", "name": "data",
		 "expressions": {"bucket": {}}},
		{"address": "aws_s3_bucket_policy.by_ref", "mode": "managed", "type": "aws_s3_bucket_policy", "name": "by_ref",
		 "expressions": {"policy": {}, "bucket": {"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]}}},
		{"address": "aws_s3_bucket_policy.by_name", "mode": "managed", "type": "aws_s3_bucket_policy", "name": "by_name",
		 "expressions": {"policy": {}, "bucket": {}}},
		{"address": "aws_sqs_queue.jobs", "mode": "managed", "type": "aws_sqs_queue", "name": "jobs",
		 "expressions": {"name": {}, "policy": {}}},
		{"address": "aws_sqs_queue_policy.by_url", "mode": "managed", "type": "aws_sqs_queue_policy", "name": "by_url",
		 "expressions": {"policy": {}, "queue_url": {}}},
		{"address": "aws_sns_topic.events", "mode": "managed", "type": "aws_sns_topic", "name": "events",
		 "expressions": {"name": {}}},
		{"address": "aws_sns_topic_policy.by_ref", "mode": "managed", "type": "aws_sns_topic_policy", "name": "by_ref",
		 "expressions": {"policy": {}, "arn": {"references": ["aws_sns_topic.events.arn", "aws_sns_topic.events"]}}},
		{"address": "aws_ecr_repository_policy.by_name", "mode": "managed", "type": "aws_ecr_repository_policy", "name": "by_name",
		 "expressions": {"policy": {}, "repository": {}}}
	]}}
}`

// TestPolicySources_ServiceResourcePolicies checks that this version reads
// the resource policies of S3, SQS, SNS and ECR. A link attribute with a
// known value that isn't an ARN, such as a bucket name or a queue URL, names
// its resource by that value.
func TestPolicySources_ServiceResourcePolicies(t *testing.T) {
	sources := PolicySources(parseRaw(t, servicePoliciesPlan), nil)
	var got []string
	for _, s := range sources {
		line := s.Address + " " + s.Service
		if s.Unknown || s.Unread {
			line += " unknown"
		}
		for _, r := range s.Resources {
			to := r.ARN + r.Value
			if r.Change != nil {
				to = r.Change.Address
			}
			line += " -> " + to + " " + r.Match.String()
		}
		if s.ResourceUnknown {
			line += " -> unknown"
		}
		got = append(got, line)
	}
	want := []string{
		`aws_s3_bucket_policy.by_ref s3 -> aws_s3_bucket.data yes`,
		`aws_s3_bucket_policy.by_name s3 -> app-logs yes`,
		`aws_sqs_queue.jobs sqs -> aws_sqs_queue.jobs yes`,
		`aws_sqs_queue_policy.by_url sqs -> https://sqs.us-east-1.amazonaws.com/123456789012/app-jobs yes`,
		`aws_sns_topic_policy.by_ref sns -> aws_sns_topic.events yes`,
		`aws_ecr_repository_policy.by_name ecr -> app yes`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
