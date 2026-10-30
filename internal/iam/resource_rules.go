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
	// passedToService is the service principal that receives the role, such
	// as "lambda.amazonaws.com". AWS sets iam:PassedToService to it on the
	// iam:PassRole check, so a grant limited to another service does not
	// cover the resource.
	passedToService string
	// callbacks are the actions AWS calls in the target's service, or nil.
	callbacks *crossServiceRule
	// serviceLinkedRoles lists the service principals whose service-linked
	// role AWS may create for the resource, such as
	// "ops.apigateway.amazonaws.com". AWS checks iam:CreateServiceLinkedRole
	// on each, though the provider never calls it.
	serviceLinkedRoles []string
	// managedSecret describes the Secrets Manager secret the service creates
	// for the resource, or is nil.
	managedSecret *managedSecret
	// conditionKeys lists the condition keys the plan can supply for the
	// resource, and the actions each one gates. A policy may grant an
	// action only when such a key holds a value, and the tool can check
	// that grant against the value the plan shows.
	conditionKeys []conditionKeyRule
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

	"aws_lambda_function":          {passesRole: []string{"role"}, passedToService: "lambda.amazonaws.com"},
	"aws_sfn_state_machine":        {passesRole: []string{"role_arn"}, passedToService: "states.amazonaws.com"},
	"aws_codebuild_project":        {passesRole: []string{"service_role"}, passedToService: "codebuild.amazonaws.com"},
	"aws_ecs_task_definition":      {passesRole: []string{"execution_role_arn", "task_role_arn"}, passedToService: "ecs-tasks.amazonaws.com"},
	"aws_cloudwatch_event_target":  {passesRole: []string{"role_arn"}, passedToService: "events.amazonaws.com"},
	"aws_apigatewayv2_integration": {passesRole: []string{"credentials_arn"}, passedToService: "apigateway.amazonaws.com"},

	// A Lambda event source mapping is authorized on Resource: "*", so a
	// least-privilege policy scopes it with the lambda:FunctionArn
	// condition key. The key holds the ARN of the function the mapping
	// points at, which the plan shows in function_name.
	"aws_lambda_event_source_mapping": {conditionKeys: []conditionKeyRule{{
		actions: []string{
			"lambda:CreateEventSourceMapping",
			"lambda:UpdateEventSourceMapping",
			"lambda:DeleteEventSourceMapping",
		},
		key: conditionKey{name: "lambda:FunctionArn", attribute: "function_name", arn: true},
	}}},

	// A regional custom domain makes API Gateway create its service-linked
	// role.
	"aws_apigatewayv2_domain_name": {serviceLinkedRoles: []string{"ops.apigateway.amazonaws.com"}},
	// A connection makes EventBridge create the service-linked role its API
	// destinations use, and a secret for its credentials.
	"aws_cloudwatch_event_connection": {
		serviceLinkedRoles: []string{"apidestinations.events.amazonaws.com"},
		managedSecret: &managedSecret{
			prefix: "events!connection/",
			actions: map[string][]string{
				"create": {"secretsmanager:CreateSecret", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"},
				"update": {"secretsmanager:CreateSecret", "secretsmanager:UpdateSecret", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"},
			},
		},
	},
	// Enabling Inspector creates its service-linked role.
	"aws_inspector2_enabler": {serviceLinkedRoles: []string{"inspector2.amazonaws.com"}},

	// The first use of these services in an account makes AWS create the
	// service-linked role the service runs under.
	"aws_ecs_cluster":       {serviceLinkedRoles: []string{"ecs.amazonaws.com"}},
	"aws_autoscaling_group": {serviceLinkedRoles: []string{"autoscaling.amazonaws.com"}},
	"aws_lb":                {serviceLinkedRoles: []string{"elasticloadbalancing.amazonaws.com"}},
	"aws_db_instance":       {serviceLinkedRoles: []string{"rds.amazonaws.com"}},
	"aws_rds_cluster":       {serviceLinkedRoles: []string{"rds.amazonaws.com"}},
	"aws_eks_cluster":       {serviceLinkedRoles: []string{"eks.amazonaws.com"}},

	"aws_wafv2_web_acl_association": {callbacks: &crossServiceRule{
		arnAttribute: "resource_arn",
		callbacks: []crossServiceCallback{
			{targetService: "elasticloadbalancing", action: "elasticloadbalancing:SetWebACL"},
			{targetService: "apigateway", action: "apigateway:SetWebACL"},
			{targetService: "appsync", action: "appsync:SetWebACL"},
			{targetService: "cognito-idp", action: "cognito-idp:AssociateWebACL"},
			{targetService: "apprunner", action: "apprunner:AssociateWebAcl"},
			{targetService: "ec2", action: "ec2:AssociateVerifiedAccessInstanceWebAcl"},
		},
		// The types resource_arn accepts, from the provider's documentation
		// of aws_wafv2_web_acl_association. The callbacks above are the ones
		// the AWS WAF Developer Guide lists under "Permissions for
		// AssociateWebACL".
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
