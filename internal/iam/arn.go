package iam

import (
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// ARN forms.
//
// AWS builds a resource's ARN from its partition, service, region, account
// and a resource part. The plan rarely knows them all, so these functions
// build ARN patterns from what it does know: a wildcard stands for each part
// the plan does not show. Coverage then compares the patterns with the
// Resource patterns of the policy (see arnIntersect).

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
