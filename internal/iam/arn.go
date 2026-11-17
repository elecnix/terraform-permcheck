package iam

import (
	"net/url"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// ARN forms.
//
// AWS builds a resource's ARN from its partition, service, region, account
// and a resource part. The plan rarely knows them all, so these functions
// build ARN patterns from what it does know: a wildcard stands for each part
// the plan does not show. Coverage then compares the patterns with the
// Resource patterns of the policy (see policy.Document.CoversTarget).

// isARN reports whether the string is a well-formed AWS ARN.
func isARN(s string) bool {
	parts := strings.SplitN(s, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[1] != ""
}

// arnService extracts the service prefix from an AWS ARN
// (arn:partition:service:region:account:resource). Returns "" when the string
// is empty or not a well-formed ARN.
func arnService(arn string) string {
	if arn == "" {
		return ""
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 3 || parts[0] != "arn" || parts[2] == "" {
		return ""
	}
	return parts[2]
}

// secretARNPatterns builds the ARN pattern of a planned secret from its
// name, or returns nil when the name is unknown.
func secretARNPatterns(secret *plan.ResourceChange) []string {
	name := secret.AttributeValues["name"]
	if name == "" {
		return nil
	}
	return []string{secretARPattern(name)}
}

// secretARPattern builds the ARN pattern for a secretsmanager secret named
// name. AWS appends a hyphen and six random characters to the name, so the
// pattern matches `name-??????`. A pattern of `name-*` would also match the
// secrets named name-<anything>, so a grant on app-production-* would count
// for the secret app.
func secretARPattern(name string) string {
	return "arn:*:secretsmanager:*:*:secret:" + name + "-??????"
}

// sqsQueueARNPatterns builds the ARN pattern of a planned SQS queue from its
// name, the last ARN segment. It returns nil when the name is unknown.
func sqsQueueARNPatterns(queue *plan.ResourceChange) []string {
	name := queue.AttributeValues["name"]
	if name == "" {
		return nil
	}
	return []string{"arn:*:sqs:*:*:" + name}
}

// lambdaInvocationARNPatterns builds the ARN pattern a planned Lambda
// invocation acts on: the function, plus the qualifier when the plan shows
// one. function_name is a name or an ARN.
//
// An invoke with no qualifier targets $LATEST, and IAM authorizes that against
// the unqualified function ARN, function:<name>. An explicit qualifier, even
// "$LATEST", authorizes against the qualified ARN, function:<name>:<qualifier>:
// a grant on the bare function ARN does not cover it, and the apply fails with
// a 403.
//
// It returns nil when the function is unknown.
func lambdaInvocationARNPatterns(inv *plan.ResourceChange) []string {
	fn := inv.AttributeValues["function_name"]
	if fn == "" {
		return nil
	}
	arn := fn
	if !isARN(fn) {
		arn = "arn:*:lambda:*:*:function:" + fn
	}
	if q := inv.AttributeValues["qualifier"]; q != "" {
		arn += ":" + q
	}
	return []string{arn}
}

// logGroupARNsOf builds the ARN patterns of a planned log group from its
// name. It returns nil when the name is unknown.
func logGroupARNsOf(group *plan.ResourceChange) []string {
	name := group.AttributeValues["name"]
	if name == "" {
		return nil
	}
	return logGroupARNPatterns(name)
}

// logGroupARNPatterns builds the two ARN forms of a log group named name.
// IAM evaluates CreateLogGroup against log-group:<name>, and most other
// log-group actions against log-group:<name>:*, so policies grant either.
func logGroupARNPatterns(name string) []string {
	arn := "arn:*:logs:*:*:log-group:" + name
	return []string{arn, arn + ":*"}
}

// roleARNPatterns builds the ARN patterns of a planned role from its path and
// name: role/<path><name>, where the path starts and ends with a slash. When
// the path is unknown, the role may sit at the root or under any path. It
// returns nil when the name is unknown.
func roleARNPatterns(role *plan.ResourceChange) []string {
	name := role.AttributeValues["name"]
	if name == "" {
		return nil
	}
	const prefix = "arn:*:iam::*:role"
	if path := role.AttributeValues["path"]; path != "" {
		return []string{prefix + path + name}
	}
	return []string{prefix + "/" + name, prefix + "/*/" + name}
}

// albARNPatterns derives the ARN pattern of a planned application load
// balancer from its name. AWS appends an ID it assigns, so the last segment
// is a wildcard.
func albARNPatterns(lb *plan.ResourceChange) []string {
	name := lb.AttributeValues["name"]
	if name == "" {
		return nil
	}
	return []string{"arn:*:elasticloadbalancing:*:*:loadbalancer/app/" + name + "/*"}
}

// apiStageARNPatterns derives the ARN pattern of a planned API Gateway REST
// stage from its API ID and stage name.
func apiStageARNPatterns(stage *plan.ResourceChange) []string {
	api, name := stage.AttributeValues["rest_api_id"], stage.AttributeValues["stage_name"]
	if api == "" || name == "" {
		return nil
	}
	return []string{"arn:*:apigateway:*::/restapis/" + api + "/stages/" + name}
}

// plannedARN returns the ARN patterns of a planned resource: its arn when the
// plan knows it, or what derive builds from its known attributes. It returns
// nil when neither is known.
func plannedARN(c *plan.ResourceChange, derive func(*plan.ResourceChange) []string) []string {
	if arn := c.AttributeValues["arn"]; isARN(arn) {
		return []string{arn}
	}
	if derive == nil {
		return nil
	}
	return derive(c)
}

// ownARN says how to build the ARN patterns of a resource type that a
// resource policy attaches to.
type ownARN struct {
	// derive builds the pattern from the known attributes of a planned
	// resource whose arn the plan doesn't know.
	derive func(*plan.ResourceChange) []string
	// value builds the pattern from the known value of a link attribute
	// that names the resource without its ARN, such as the bucket of an
	// aws_s3_bucket_policy. It is nil when the link attribute holds an ARN.
	value func(string) []string
	// objects marks a resource whose policy also covers the objects inside
	// it, as a bucket policy covers the bucket's objects. Each pattern then
	// gets a second form that ends in "/*".
	objects bool
}

// ownARNPatterns maps a resource type that a resource policy attaches to
// onto the functions that build its ARN patterns. A type that the plan reads
// resource policies for has a row here.
var ownARNPatterns = map[string]ownARN{
	"aws_secretsmanager_secret": {derive: secretARNPatterns},
	"aws_s3_bucket":             {derive: attributePatterns("bucket", s3BucketARNPatterns), value: s3BucketARNPatterns, objects: true},
	"aws_sqs_queue":             {derive: sqsQueueARNPatterns, value: sqsQueueURLPatterns},
	"aws_sns_topic":             {derive: snsTopicARNPatterns},
	"aws_ecr_repository":        {derive: attributePatterns("name", ecrRepositoryARNPatterns), value: ecrRepositoryARNPatterns},
	"aws_kms_key":               {derive: attributePatterns("key_id", kmsKeyARNPatterns), value: kmsKeyARNPatterns},
}

// ResourceARNPatterns returns the ARN patterns of a planned resource that a
// resource policy attaches to: its arn when the plan knows it, or the target
// pattern built from its known attributes, such as a secret's name followed
// by AWS's random suffix. It returns nil when the arn is unknown and
// ownARNPatterns has no row for the type, or the row can't build a pattern.
//
// A bucket gives two patterns, one for the bucket and one for its objects,
// since a bucket policy grants on both.
func ResourceARNPatterns(rc *plan.ResourceChange) []string {
	own := ownARNPatterns[rc.Type]
	return own.withObjects(plannedARN(rc, own.derive))
}

// LinkValueARNPatterns returns the ARN patterns of the resource of type typ
// that the known value of a link attribute names, such as a bucket name or
// a queue URL. It returns nil when the type's link attribute holds an ARN,
// or when the value doesn't give the resource's name.
func LinkValueARNPatterns(typ, value string) []string {
	own := ownARNPatterns[typ]
	if own.value == nil {
		return nil
	}
	return own.withObjects(own.value(value))
}

// withObjects adds the pattern of the objects inside each pattern, for a
// type whose policy covers them.
func (o ownARN) withObjects(patterns []string) []string {
	if !o.objects {
		return patterns
	}
	out := make([]string, 0, 2*len(patterns))
	for _, p := range patterns {
		out = append(out, p, p+"/*")
	}
	return out
}

// attributePatterns builds the ARN pattern of a planned resource from the
// known value of the attribute attr, such as the bucket of an aws_s3_bucket.
func attributePatterns(attr string, build func(string) []string) func(*plan.ResourceChange) []string {
	return func(rc *plan.ResourceChange) []string {
		v := rc.AttributeValues[attr]
		if v == "" {
			return nil
		}
		return build(v)
	}
}

// s3BucketARNPatterns builds the ARN pattern of the bucket named name. A
// bucket ARN has no region and no account: arn:aws:s3:::name.
func s3BucketARNPatterns(name string) []string {
	return []string{"arn:*:s3:::" + name}
}

// sqsQueueURLPatterns builds the ARN pattern of the queue at a queue URL,
// such as https://sqs.us-east-1.amazonaws.com/123456789012/app-jobs. The
// last path part is the queue's name, and the part before it is its account.
// A host of the form sqs.REGION.DOMAIN gives the region, and any other host
// leaves it a wildcard. It returns nil when the value isn't such a URL.
func sqsQueueURLPatterns(value string) []string {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		return nil
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || !isAccountID(parts[0]) || parts[1] == "" {
		return nil
	}
	region := "*"
	if labels := strings.Split(u.Hostname(), "."); len(labels) > 2 && labels[0] == "sqs" {
		region = labels[1]
	}
	return []string{"arn:*:sqs:" + region + ":" + parts[0] + ":" + parts[1]}
}

// isAccountID reports whether s is a 12-digit AWS account ID.
func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// snsTopicARNPatterns builds the ARN pattern of a planned SNS topic from its
// name, the last ARN segment. The name of a FIFO topic ends in .fifo, and
// so does its ARN. It returns nil when the name is unknown.
func snsTopicARNPatterns(topic *plan.ResourceChange) []string {
	name := topic.AttributeValues["name"]
	if name == "" {
		return nil
	}
	return []string{"arn:*:sns:*:*:" + name}
}

// ecrRepositoryARNPatterns builds the ARN pattern of the ECR repository
// named name: arn:aws:ecr:REGION:ACCOUNT:repository/name.
func ecrRepositoryARNPatterns(name string) []string {
	return []string{"arn:*:ecr:*:*:repository/" + name}
}

// kmsKeyARNPatterns builds the ARN pattern of the KMS key whose key id is
// id: arn:aws:kms:REGION:ACCOUNT:key/id. AWS assigns the id when it creates
// the key, so a key that the plan creates has no pattern. A key ARN in the
// value gives itself.
func kmsKeyARNPatterns(id string) []string {
	if isARN(id) {
		return []string{id}
	}
	return []string{"arn:*:kms:*:*:key/" + id}
}
