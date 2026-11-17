package iam

import (
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// TestResourceARNPatterns checks the ARN patterns of each resource type that
// a resource policy attaches to, from its known arn or its known attributes.
func TestResourceARNPatterns(t *testing.T) {
	for _, c := range []struct {
		typ   string
		attrs map[string]string
		want  string
	}{
		{"aws_secretsmanager_secret", map[string]string{"name": "app-db"}, "arn:*:secretsmanager:*:*:secret:app-db-??????"},
		// A bucket policy covers the bucket and its objects.
		{"aws_s3_bucket", map[string]string{"bucket": "app-data"}, "arn:*:s3:::app-data arn:*:s3:::app-data/*"},
		{"aws_s3_bucket", map[string]string{"bucket": "app-data", "arn": "arn:aws:s3:::app-data"}, "arn:aws:s3:::app-data arn:aws:s3:::app-data/*"},
		{"aws_s3_bucket", map[string]string{}, ""},
		{"aws_sqs_queue", map[string]string{"name": "app-jobs"}, "arn:*:sqs:*:*:app-jobs"},
		{"aws_sns_topic", map[string]string{"name": "app-events.fifo"}, "arn:*:sns:*:*:app-events.fifo"},
		{"aws_sns_topic", map[string]string{"arn": "arn:aws:sns:us-east-1:123456789012:app-events"}, "arn:aws:sns:us-east-1:123456789012:app-events"},
		{"aws_ecr_repository", map[string]string{"name": "team/app"}, "arn:*:ecr:*:*:repository/team/app"},
		{"aws_kms_key", map[string]string{"key_id": "1234abcd-12ab-34cd-56ef-1234567890ab"}, "arn:*:kms:*:*:key/1234abcd-12ab-34cd-56ef-1234567890ab"},
		// AWS assigns the key id, so a key that the plan creates has no
		// pattern.
		{"aws_kms_key", map[string]string{}, ""},
	} {
		rc := &plan.ResourceChange{Type: c.typ, AttributeValues: c.attrs}
		if got := strings.Join(ResourceARNPatterns(rc), " "); got != c.want {
			t.Errorf("%s %v: patterns = %q, want %q", c.typ, c.attrs, got, c.want)
		}
	}
}

// TestLinkValueARNPatterns checks the ARN patterns of a resource that the
// known value of a link attribute names, such as a bucket name or a queue
// URL.
func TestLinkValueARNPatterns(t *testing.T) {
	for _, c := range []struct {
		typ, value, want string
	}{
		{"aws_s3_bucket", "app-data", "arn:*:s3:::app-data arn:*:s3:::app-data/*"},
		{"aws_sqs_queue", "https://sqs.us-east-1.amazonaws.com/123456789012/app-jobs", "arn:*:sqs:us-east-1:123456789012:app-jobs"},
		{"aws_sqs_queue", "https://sqs.cn-north-1.amazonaws.com.cn/123456789012/app-jobs.fifo", "arn:*:sqs:cn-north-1:123456789012:app-jobs.fifo"},
		// A legacy host doesn't give the region.
		{"aws_sqs_queue", "https://queue.amazonaws.com/123456789012/app-jobs", "arn:*:sqs:*:123456789012:app-jobs"},
		{"aws_sqs_queue", "app-jobs", ""},
		{"aws_sqs_queue", "https://sqs.us-east-1.amazonaws.com/app-jobs", ""},
		{"aws_ecr_repository", "app", "arn:*:ecr:*:*:repository/app"},
		{"aws_sns_topic", "app-events", ""},
		{"aws_kms_key", "1234abcd-12ab-34cd-56ef-1234567890ab", "arn:*:kms:*:*:key/1234abcd-12ab-34cd-56ef-1234567890ab"},
	} {
		if got := strings.Join(LinkValueARNPatterns(c.typ, c.value), " "); got != c.want {
			t.Errorf("%s %q: patterns = %q, want %q", c.typ, c.value, got, c.want)
		}
	}
}
