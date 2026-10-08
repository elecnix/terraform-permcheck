package iam

import "github.com/elecnix/terraform-permcheck/internal/plan"

// Resource rules.
//
// A schema lists the calls the provider makes for a resource type. A few
// types need more than that: the resources the calls act on, a role the
// resource hands to a service, or a callback AWS makes into another service.
// resourceRules has one row per such type, so every fact about a type is in
// one place.

// resourceRule is what the tool knows about a resource type beyond its
// schema.
type resourceRule struct {
	// targets derives the resources the provider's calls act on, one list of
	// ARN patterns per resource. Every target must be covered. Nil means the
	// action alone decides coverage.
	targets func(rc *plan.ResourceChange, set *changeSet) [][]string
	// passesRole lists the attributes that carry a role the resource hands
	// to a service. AWS checks iam:PassRole on that role, though the
	// provider never calls it.
	passesRole []string
	// callbacks are the actions AWS calls in the target's service, or nil.
	callbacks *crossServiceRule
}

// resourceRules maps a terraform resource type to its rule. A type with no
// row has only its schema.
var resourceRules = map[string]resourceRule{
	// A secret version acts on the secret named in secret_id
	// (aws_secretsmanager_secret.b). The secret's name is a literal in the
	// plan, so the version's ARN pattern is derivable even though the
	// version's own ARN is computed at apply time.
	"aws_secretsmanager_secret_version": {targets: secretVersionTargetARNs},
	// A secret is its own target. Its name carries into its ARN.
	"aws_secretsmanager_secret": {targets: ownTarget(secretARNPatterns)},
	// A queue is its own target. The queue name is the last ARN segment.
	"aws_sqs_queue": {targets: ownTarget(sqsQueueARNPatterns)},
	// A log group is its own target. The group name carries into its ARN.
	"aws_cloudwatch_log_group": {targets: ownTarget(logGroupARNsOf)},
	// A log stream acts on the group named in log_group_name, either a known
	// value or a reference to a managed log group.
	"aws_cloudwatch_log_stream": {targets: logStreamTargetARNs},

	"aws_lambda_function":          {passesRole: []string{"role"}},
	"aws_sfn_state_machine":        {passesRole: []string{"role_arn"}},
	"aws_codebuild_project":        {passesRole: []string{"service_role"}},
	"aws_ecs_task_definition":      {passesRole: []string{"execution_role_arn", "task_role_arn"}},
	"aws_cloudwatch_event_target":  {passesRole: []string{"role_arn"}},
	"aws_apigatewayv2_integration": {passesRole: []string{"credentials_arn"}},

	"aws_wafv2_web_acl_association": {callbacks: &crossServiceRule{
		arnAttribute: "resource_arn",
		callbacks: []crossServiceCallback{
			{targetService: "elasticloadbalancing", action: "elasticloadbalancing:SetWebACL"},
			{targetService: "apigateway", action: "apigateway:SetWebACL"},
			{targetService: "appsync", action: "appsync:SetWebACL"},
		},
		// The types resource_arn accepts, from the provider's documentation
		// of aws_wafv2_web_acl_association. Cognito, App Runner and Verified
		// Access have no callback above, so a reference to one selects none.
		targetTypes: map[string]targetType{
			"aws_lb":                      {service: "elasticloadbalancing", arnPatterns: albARNPatterns},
			"aws_alb":                     {service: "elasticloadbalancing", arnPatterns: albARNPatterns},
			"aws_api_gateway_stage":       {service: "apigateway", arnPatterns: apiStageARNPatterns},
			"aws_appsync_graphql_api":     {service: "appsync"},
			"aws_cognito_user_pool":       {service: "cognito-idp"},
			"aws_apprunner_service":       {service: "apprunner"},
			"aws_verifiedaccess_instance": {service: "ec2"},
		},
	}},
}
