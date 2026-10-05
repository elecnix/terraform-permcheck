// Package provideraws parses terraform-provider-aws Go source files to
// extract the exact AWS SDK API calls required by each resource type.
//
// This provides a more precise alternative to CloudFormation schema resolution,
// capturing only the permissions actually used by the provider, not the
// maximal set of permissions the resource *could* need.
package provideraws

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// ConditionKind says what a gated SDK call needs from its gating attribute.
// The two kinds are evaluated from different data: presence from the planned
// state, change from the difference between prior and planned state.
type ConditionKind string

const (
	// ConditionPresence gates on the attribute being set, from a d.GetOk or
	// d.Get guard.
	ConditionPresence ConditionKind = "presence"
	// ConditionChange gates on the attribute having changed, from a d.HasChange
	// guard.
	ConditionChange ConditionKind = "change"
)

// ExtractedAction represents an AWS IAM action extracted from a provider
// source file, with metadata about whether it is conditionally called and on
// what.
type ExtractedAction struct {
	Action        string        // e.g., "backup:CreateBackupVault"
	Conditional   bool          // true if this SDK call is inside a conditional block
	Condition     string        // attribute name guarding the call, e.g. "kms_key_arn"
	ConditionKind ConditionKind // what the guard requires of that attribute; empty if unconditional
}

// helperCall records a helper function call and the conditional context at the
// call site (e.g., if d.GetOk("replica") { removeSecretReplicas(...) }).
type helperCall struct {
	Name       string        // helper function name
	CondReason string        // attribute from call-site d.GetOk/d.Get/d.HasChange guard, empty if unconditional
	CondKind   ConditionKind // kind of the call-site guard, empty if unconditional
}

// ParseResourceFile parses a Go source file from the terraform-provider-aws
// and extracts the IAM permissions (actions) required by each CRUD function.
//
// It handles:
// - Direct conn.Method() calls in CRUD function bodies
// - Conditional calls gated by d.GetOk(), d.Get(), or d.HasChange()
// - Helper function calls: retryCreateRole(ctx, conn, ...) → conn.CreateRole
// - Recursive helper chains: findRoleByName → findRole → conn.GetRole
// - Anonymous function bodies (via tfresource.RetryWhen)
// - Function return following (Create returns Read → include Read permissions)
//
// Returns all actions (both unconditional and conditional) as plain strings.
func ParseResourceFile(src string, tfType string, resourceName string) (map[string][]string, error) {
	structured, err := ParseResourceFileStructured(src, tfType, resourceName)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]string)
	for k, v := range structured {
		for _, ea := range v {
			result[k] = append(result[k], ea.Action)
		}
		result[k] = dedup(result[k])
	}
	return result, nil
}

// ParseResourceFileStructured parses a Go source file and returns extracted
// actions with conditional metadata (whether the call sits inside a block gated
// by d.GetOk(), d.Get(), or d.HasChange(), and on which attribute). Follows
// helper function call chains transitively within the same file.
func ParseResourceFileStructured(src string, tfType string, resourceName string) (map[string][]ExtractedAction, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, tfType+".go", src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse Go source: %w", err)
	}

	// Phase 1: Extract direct SDK calls from ALL functions (helpers + CRUD)
	allSdkCalls := make(map[string][]ExtractedAction) // funcName -> actions
	funcConnVar := make(map[string]string)            // funcName -> connVar
	funcService := make(map[string]string)            // funcName -> service

	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		calls, connVar, service := extractSDKCallsWithConnInfo(fd)
		if len(calls) > 0 {
			allSdkCalls[name] = dedupActions(calls)
		}
		if connVar != "" {
			funcConnVar[name] = connVar
		}
		if service != "" {
			funcService[name] = service
		}
	}

	// Phase 1b: Build call graph — for each function, track which helpers it calls
	callGraph := make(map[string][]helperCall) // funcName -> helper calls
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		connVar := funcConnVar[fd.Name.Name]
		if connVar == "" {
			continue
		}
		helpers := findHelperCalls(fd, connVar, f)
		if len(helpers) > 0 {
			callGraph[fd.Name.Name] = helpers
		}
	}

	// Phase 1c: Resolve transitive SDK calls for each resource function
	resolvedCalls := make(map[string][]ExtractedAction) // funcName -> resolved actions
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if !strings.HasPrefix(name, "resource") || !containsIgnoreCase(name, resourceName) {
			continue
		}
		resolved := resolveTransitiveExtracted(name, allSdkCalls, callGraph, make(map[string]bool), 0)
		if len(resolved) > 0 {
			resolvedCalls[name] = dedupActions(resolved)
		}
	}

	// Phase 2: Map to CRUD operations
	actions := make(map[string][]ExtractedAction)
	operationMap := map[string]string{"Create": "create", "Read": "read", "Update": "update", "Delete": "delete", "Import": "import"}

	for funcName, funcCalls := range resolvedCalls {
		for opSuffix, opKey := range operationMap {
			if strings.HasSuffix(funcName, opSuffix) {
				actions[opKey] = append(actions[opKey], funcCalls...)
				break
			}
		}
	}

	// Phase 3: Follow function returns for implicit reads.
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(fd.Name.Name, "resource") || !strings.HasSuffix(fd.Name.Name, "Create") {
			continue
		}
		calledFuncs := findReturnedResourceCalls(fd)
		for _, calledName := range calledFuncs {
			if calledActions, ok := resolvedCalls[calledName]; ok {
				actions["create"] = append(actions["create"], calledActions...)
			}
		}
	}

	// Deduplicate
	for k, v := range actions {
		actions[k] = dedupActions(v)
	}

	return actions, nil
}

// extractSDKCalls walks the body of a function and extracts all AWS SDK API
// calls, distinguishing unconditional calls from those inside a block gated on
// an attribute (e.g., if d.GetOk("attribute"), d.Get(...), d.HasChange(...)).
func extractSDKCalls(fd *ast.FuncDecl) []ExtractedAction {
	if fd.Body == nil {
		return nil
	}

	state := &extractionState{}
	walkWithConditionals(fd.Body, state)
	return state.actions
}

// extractionState tracks the current state during conditional-aware AST walking.
type extractionState struct {
	service    string
	connVar    string
	actions    []ExtractedAction
	condDepth  int           // how many conditional if-blocks deep we are
	condReason string        // attribute name from the innermost conditional guard
	condKind   ConditionKind // kind of that guard
}

// walkWithConditionals recursively walks an AST node, tracking the guard
// context from if-statements that gate on d.GetOk(), d.Get(), or d.HasChange().
func walkWithConditionals(node ast.Node, state *extractionState) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.BlockStmt:
		for _, stmt := range n.List {
			walkWithConditionals(stmt, state)
		}

	case *ast.ExprStmt:
		walkWithConditionals(n.X, state)

	case *ast.IfStmt:
		// Save current connVar/service so they can be restored after the if-block
		savedConnVar := state.connVar
		savedService := state.service

		// Check if this if-statement gates the body on an attribute
		guard := extractConditionGuard(n)
		if guard.Attribute != "" {
			// Enter conditional context
			state.condDepth++
			if state.condReason == "" {
				state.condReason = guard.Attribute
				state.condKind = guard.Kind
			}

			// Walk body inside conditional context
			walkWithConditionals(n.Body, state)

			// Also walk else if present (also conditional, could be different attribute)
			walkWithConditionals(n.Else, state)

			// Leave conditional context
			state.condDepth--
			if state.condDepth == 0 {
				state.condReason = ""
				state.condKind = ""
			}
		} else {
			// Normal if — walk without changing conditional state
			walkWithConditionals(n.Body, state)
			walkWithConditionals(n.Else, state)
		}

		// Restore connVar/service in case inner assignments changed them
		state.connVar = savedConnVar
		state.service = savedService

	case *ast.AssignStmt:
		// Also walk the init statement of if-statements (which may contain d.GetOk)
		// This is covered by the IfStmt.Init handling, but general assignments
		// need to be checked for client assignments
		if svc, conn := findClientAssignment(n); svc != "" {
			state.service = svc
			state.connVar = conn
		}
		// Walk children (RHS might have calls)
		for _, expr := range n.Lhs {
			walkWithConditionals(expr, state)
		}
		for _, expr := range n.Rhs {
			walkWithConditionals(expr, state)
		}

	case *ast.ReturnStmt:
		for _, expr := range n.Results {
			walkWithConditionals(expr, state)
		}

	case *ast.CallExpr:
		// Check for SDK API call: conn.MethodName(ctx, ...)
		if action := extractCallAction(n, state.connVar, state.service); action != "" {
			ea := ExtractedAction{
				Action:        action,
				Conditional:   state.condDepth > 0,
				Condition:     state.condReason,
				ConditionKind: state.condKind,
			}
			state.actions = append(state.actions, ea)
			return
		}
		// Walk arguments (recursive calls might contain more SDK calls)
		for _, arg := range n.Args {
			walkWithConditionals(arg, state)
		}

	case *ast.ForStmt:
		walkWithConditionals(n.Body, state)

	case *ast.RangeStmt:
		walkWithConditionals(n.Body, state)

	case *ast.SwitchStmt:
		walkWithConditionals(n.Body, state)

	case *ast.CaseClause:
		for _, stmt := range n.Body {
			walkWithConditionals(stmt, state)
		}

	case *ast.DeferStmt:
		walkWithConditionals(n.Call, state)

	case *ast.GoStmt:
		walkWithConditionals(n.Call, state)

	case *ast.LabeledStmt:
		walkWithConditionals(n.Stmt, state)

	case *ast.SendStmt:
		// Channel send — no SDK calls here

	case *ast.IncDecStmt:
		// Increment/decrement — no SDK calls here

	case *ast.BranchStmt:
		// break, continue, goto

	default:
		// Ident, Literal, etc. — not relevant
	}
}

// condGuard is a gating attribute found on an if-statement, with the kind of
// gate the provider applies to it.
type condGuard struct {
	Attribute string
	Kind      ConditionKind
}

// extractConditionGuard checks if an if-statement's condition involves a
// d.GetOk("attr"), d.Get("attr"), or d.HasChange("attr") guard and returns the
// gating attribute together with the kind of gate.
func extractConditionGuard(ifStmt *ast.IfStmt) condGuard {
	// Check Init statement: if v, ok := d.GetOk("attr"); ok { ...
	if ifStmt.Init != nil {
		if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok {
			for _, rhs := range assign.Rhs {
				if guard := extractGuardAttribute(rhs); guard.Attribute != "" {
					return guard
				}
			}
		}
	}

	// Check condition expression: d.Get("attr").(bool)
	// The condition may be wrapped in a type assertion or a negation.
	cond := ifStmt.Cond
	if ta, ok := cond.(*ast.TypeAssertExpr); ok {
		cond = ta.X
	}
	return extractGuardAttribute(cond)
}

// extractGuardAttribute checks if an expression is d.GetOk("attr"),
// d.Get("attr"), or d.HasChange("attr") on the resource data and returns the
// attribute name with the kind of gate. Parenthesised and negated expressions
// are unwrapped, so `!d.HasChange("attr")` reads the same as the plain form.
func extractGuardAttribute(expr ast.Expr) condGuard {
	expr = unwrapExpr(expr)

	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return condGuard{}
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return condGuard{}
	}

	// Must be a method call on something named "d"
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "d" {
		return condGuard{}
	}

	// Map the guard method to the kind of gate it applies. Only the
	// single-attribute forms count: d.HasChanges spans several attributes and
	// d.HasChangesExcept is a filter, so neither names one gating attribute.
	var kind ConditionKind
	switch sel.Sel.Name {
	case "GetOk", "Get":
		kind = ConditionPresence
	case "HasChange":
		kind = ConditionChange
	default:
		return condGuard{}
	}

	// First argument must be a string literal
	if len(call.Args) < 1 {
		return condGuard{}
	}

	bl, ok := call.Args[0].(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return condGuard{}
	}

	// Return the attribute name without quotes
	return condGuard{Attribute: strings.Trim(bl.Value, "\""), Kind: kind}
}

// unwrapExpr strips parentheses and negations from an expression, so a guard
// written as `!(d.HasChange("attr"))` or `!d.HasChange("attr")` is recognized.
func unwrapExpr(expr ast.Expr) ast.Expr {
	for {
		switch n := expr.(type) {
		case *ast.ParenExpr:
			expr = n.X
		case *ast.UnaryExpr:
			expr = n.X
		default:
			return expr
		}
	}
}

// findClientAssignment detects a client connection assignment like:
//
//	conn := meta.(*conns.AWSClient).BackupClient(ctx)
//
// Returns (service, connVar) where service is "backup" and connVar is "conn".
func findClientAssignment(stmt *ast.AssignStmt) (string, string) {
	if len(stmt.Lhs) != 1 || stmt.Tok != token.DEFINE {
		return "", ""
	}

	lhsIdent, ok := stmt.Lhs[0].(*ast.Ident)
	if !ok {
		return "", ""
	}

	if len(stmt.Rhs) != 1 {
		return "", ""
	}

	// Unwrap the chain: meta.(*conns.AWSClient).BackupClient(ctx)
	call, ok := stmt.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "", ""
	}

	// The method call itself: .BackupClient(ctx)
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}

	clientMethod := sel.Sel.Name // e.g., "BackupClient"
	if !strings.HasSuffix(clientMethod, "Client") {
		return "", ""
	}

	service := clientMethodToService(clientMethod)
	return service, lhsIdent.Name
}

// extractCallAction checks if a call expression is an AWS SDK API call on the
// connection variable, e.g., conn.CreateBackupVault(ctx, input).
// Returns the IAM action string (e.g., "backup:CreateBackupVault") or "".
func extractCallAction(call *ast.CallExpr, connVar string, service string) string {
	if connVar == "" || service == "" {
		return ""
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}

	if ident.Name != connVar {
		return ""
	}

	method := sel.Sel.Name // e.g., "CreateBackupVault"
	if isAWSMethod(method) {
		return sdKMethodToIAMAction(method, service)
	}

	return ""
}

// findReturnedResourceCalls finds resource function calls in return
// statements, like:
//
//	return append(diags, resourceVaultRead(ctx, d, meta)...)
//
// Returns the names of called resource functions (e.g., ["resourceVaultRead"]).
func findReturnedResourceCalls(fd *ast.FuncDecl) []string {
	if fd.Body == nil {
		return nil
	}

	var calls []string

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}

		for _, expr := range ret.Results {
			calls = append(calls, extractResourceFuncCalls(expr)...)
		}
		return true
	})

	return calls
}

// extractResourceFuncCalls extracts resource function names from an expression.
// e.g., from "append(diags, resourceVaultRead(ctx, d, meta)...)" returns ["resourceVaultRead"].
func extractResourceFuncCalls(expr ast.Expr) []string {
	var calls []string

	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if isResourceFunc(fn.Name) {
				calls = append(calls, fn.Name)
			}
		case *ast.SelectorExpr:
			if isResourceFunc(fn.Sel.Name) {
				calls = append(calls, fn.Sel.Name)
			}
		}
		return true
	})

	return calls
}

// isResourceFunc checks if a function name looks like a resource CRUD function.
func isResourceFunc(name string) bool {
	return strings.HasPrefix(name, "resource") &&
		(strings.HasSuffix(name, "Create") ||
			strings.HasSuffix(name, "Read") ||
			strings.HasSuffix(name, "Update") ||
			strings.HasSuffix(name, "Delete") ||
			strings.HasSuffix(name, "Import"))
}

// isAWSMethod checks if a method name looks like an AWS SDK API method
// (PascalCase, not something like Error, HandleError, etc.).
func isAWSMethod(name string) bool {
	if len(name) == 0 {
		return false
	}
	// Must start with uppercase
	if name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	return true
}

// sdKMethodToIAMAction converts an AWS SDK method name and service to an IAM
// action string. Convention: backup + CreateBackupVault -> backup:CreateBackupVault.
// Also normalizes SDK v2 method names where they diverge from canonical IAM action
// names (e.g., S3 v2 SDK drops the "Bucket" infix in methods like
// PutPublicAccessBlock, which maps to the canonical s3:PutBucketPublicAccessBlock).
func sdKMethodToIAMAction(method string, service string) string {
	if canonical := normalizeSDKMethod(service, method); canonical != "" {
		return service + ":" + canonical
	}
	return service + ":" + method
}

// normalizeSDKMethod translates known AWS SDK v2 method names to their canonical
// IAM action names. Returns empty string if no normalization is needed.
func normalizeSDKMethod(service, method string) string {
	// S3 SDK v2 drops the "Bucket" infix on some methods and adds "Configuration"
	// suffix on others. These need canonical IAM action names.
	if service == "s3" {
		return s3SDKMethodNormalization(method)
	}
	return ""
}

// s3SDKMethodNormalization maps S3 SDK v2 method names to canonical IAM action
// names where they diverge.
func s3SDKMethodNormalization(original string) string {
	s3Names := map[string]string{
		"PutPublicAccessBlock":               "PutBucketPublicAccessBlock",
		"GetPublicAccessBlock":               "GetBucketPublicAccessBlock",
		"DeletePublicAccessBlock":            "DeleteBucketPublicAccessBlock",
		"PutBucketNotificationConfiguration": "PutBucketNotification",
		"GetBucketNotificationConfiguration": "GetBucketNotification",
		"PutBucketObjectLockConfiguration":   "PutObjectLockConfiguration",
		"GetBucketObjectLockConfiguration":   "GetObjectLockConfiguration",
		"PutBucketTagging":                   "PutBucketTagging",
		"GetBucketTagging":                   "GetBucketTagging",
		"DeleteBucketTagging":                "DeleteBucketTagging",
	}
	if canonical, ok := s3Names[original]; ok {
		return canonical
	}
	return ""
}

// clientMethodToService extracts the AWS service name from a client accessor
// method name (e.g., "BackupClient" -> "backup", "DynamoDBClient" -> "dynamodb").
func clientMethodToService(clientMethod string) string {
	// Common mapping for client method names
	known := map[string]string{
		"BackupClient":             "backup",
		"DynamoDBClient":           "dynamodb",
		"IAMClient":                "iam",
		"S3Client":                 "s3",
		"STSClient":                "sts",
		"KMSClient":                "kms",
		"LambdaClient":             "lambda",
		"EC2Client":                "ec2",
		"SQSClient":                "sqs",
		"SNSClient":                "sns",
		"RDSClient":                "rds",
		"CloudWatchLogsClient":     "logs",
		"SecretsManagerClient":     "secretsmanager",
		"CloudWatchClient":         "cloudwatch",
		"CloudTrailClient":         "cloudtrail",
		"Route53Client":            "route53",
		"ELBv2Client":              "elasticloadbalancing",
		"EFSClient":                "elasticfilesystem",
		"SSMClient":                "ssm",
		"SESClient":                "ses",
		"SFNClient":                "states",
		"CognitoIdentityClient":    "cognito-identity",
		"CognitoIDPClient":         "cognito-idp",
		"APIGatewayClient":         "apigateway",
		"APIGatewayV2Client":       "apigateway",
		"AutoscalingClient":        "autoscaling",
		"CloudFormationClient":     "cloudformation",
		"CloudFrontClient":         "cloudfront",
		"CodeBuildClient":          "codebuild",
		"CodeDeployClient":         "codedeploy",
		"CodePipelineClient":       "codepipeline",
		"ECRClient":                "ecr",
		"ECSClient":                "ecs",
		"EKSClient":                "eks",
		"ElastiCacheClient":        "elasticache",
		"ElasticBeanstalkClient":   "elasticbeanstalk",
		"ElasticsearchClient":      "es",
		"EMRClient":                "elasticmapreduce",
		"EventBridgeClient":        "events",
		"FirehoseClient":           "firehose",
		"GlueClient":               "glue",
		"GuardDutyClient":          "guardduty",
		"IoTClient":                "iot",
		"KinesisClient":            "kinesis",
		"OpsWorksClient":           "opsworks",
		"OrganizationsClient":      "organizations",
		"PinpointClient":           "mobiletargeting",
		"RedshiftClient":           "redshift",
		"RedshiftServerlessClient": "redshift-serverless",
		"Route53DomainsClient":     "route53domains",
		"Route53ResolverClient":    "route53resolver",
		"SageMakerClient":          "sagemaker",
		"SecurityHubClient":        "securityhub",
		"ServiceCatalogClient":     "servicecatalog",
		"ServiceDiscoveryClient":   "servicediscovery",
		"SESv2Client":              "ses",
		"ShieldClient":             "shield",
		"StepFunctionsClient":      "states",
		"TransferClient":           "transfer",
		"WAFClient":                "waf",
		"WAFV2Client":              "wafv2",
		"WorkLinkClient":           "worklink",
		"WorkSpacesClient":         "workspaces",
		"XRayClient":               "xray",
	}

	if svc, ok := known[clientMethod]; ok {
		return svc
	}

	// Fallback: strip "Client" suffix and lowercase
	base := strings.TrimSuffix(clientMethod, "Client")
	base = strings.TrimSuffix(base, "Regional")
	base = strings.TrimSuffix(base, "Global")
	return strings.ToLower(base)
}

// containsIgnoreCase reports whether s contains substr, case-insensitively.
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && len(substr) > 0 &&
		strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// dedup removes duplicate strings while preserving order.
func dedup(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// dedupActions removes duplicate ExtractedActions (by Action string) while
// preserving order. When deduplicating, marks the action as unconditional
// if any occurrence was unconditional (union).
func dedupActions(actions []ExtractedAction) []ExtractedAction {
	seen := make(map[string]bool)
	var out []ExtractedAction
	for _, ea := range actions {
		if !seen[ea.Action] {
			seen[ea.Action] = true
			out = append(out, ea)
		} else {
			// If a duplicate exists and this one is unconditional, upgrade
			for i := range out {
				if out[i].Action == ea.Action && !ea.Conditional {
					out[i].Conditional = false
					out[i].Condition = ""
					out[i].ConditionKind = ""
				}
			}
		}
	}
	return out
}

// extractSDKCallsWithConnInfo walks the body of a function and extracts all AWS
// SDK API calls, detecting the connection variable and service from either a
// client assignment (conn := meta.(*conns.AWSClient).XxxClient) or a typed
// parameter (func helper(ctx, conn *iam.Client)).
// Returns (actions, connVar, service).
func extractSDKCallsWithConnInfo(fd *ast.FuncDecl) ([]ExtractedAction, string, string) {
	if fd.Body == nil {
		return nil, "", ""
	}

	state := &extractionState{}

	// First, check for conn in function parameters (helper functions)
	findConnParam(fd, &state.connVar, &state.service)

	// Then walk the body for client assignments and SDK calls
	walkWithConditionals(fd.Body, state)

	return dedupActions(state.actions), state.connVar, state.service
}

// findConnParam checks function parameters for a conn variable with a typed
// SDK client (e.g., conn *iam.Client, conn *backup.Client).
// Sets connVar and service if found.
func findConnParam(fd *ast.FuncDecl, connVar *string, service *string) {
	if fd.Type.Params == nil {
		return
	}
	for _, param := range fd.Type.Params.List {
		for _, name := range param.Names {
			if isConnParamName(name.Name) {
				if svc := paramTypeToService(param.Type); svc != "" {
					*connVar = name.Name
					*service = svc
					return
				}
			}
		}
	}
}

// isConnParamName checks if a parameter name looks like a connection variable.
func isConnParamName(name string) bool {
	switch name {
	case "conn", "c", "client":
		return true
	}
	return false
}

// paramTypeToService extracts the AWS service name from a parameter type
// like *iam.Client -> iam, *backup.Client -> backup, *dynamodb.Client -> dynamodb.
// Falls back to a lookup table for package names that differ from IAM service names
// (e.g., *cloudwatchlogs.Client -> "logs", not "cloudwatchlogs").
func paramTypeToService(expr ast.Expr) string {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return ""
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	// ident.Name is the package, e.g., "iam", "backup", "dynamodb"
	pkg := ident.Name
	// Some SDK v2 package names differ from canonical IAM service names.
	// Fall through to a lookup table to normalize them.
	if svc := sdkPackageToIAMService(pkg); svc != "" {
		return svc
	}
	return pkg
}

// sdkPackageToIAMService maps AWS SDK v2 Go package names to their canonical
// IAM service names where they diverge (e.g., "cloudwatchlogs" → "logs").
// Many packages match exactly ("s3" → "s3", "iam" → "iam"), so only mismatches
// are listed.
func sdkPackageToIAMService(pkg string) string {
	pkgToService := map[string]string{
		"cloudwatchlogs":         "logs",
		"eventbridge":            "events", // EventBridge authorizes under its CloudWatch Events IAM prefix
		"s3control":              "s3",
		"elasticloadbalancingv2": "elasticloadbalancing",
		"sfn":                    "states",
		"mobiletargeting":        "mobiletargeting", // pinpoint → mobiletargeting
	}
	return pkgToService[pkg]
}

// findHelperCalls finds all helper function calls (functions defined in the same
// file that use the given connVar as an argument) within a function body,
// tracking the conditional context at each call site.
func findHelperCalls(fd *ast.FuncDecl, connVar string, f *ast.File) []helperCall {
	if fd.Body == nil || connVar == "" {
		return nil
	}

	state := &findHelperState{
		connVar: connVar,
		f:       f,
	}
	walkForHelpers(fd.Body, state)
	return state.helpers
}

// findHelperState tracks state while walking for helper calls.
type findHelperState struct {
	connVar    string
	f          *ast.File
	helpers    []helperCall
	condDepth  int
	condReason string
	condKind   ConditionKind
}

// walkForHelpers is a recursive AST walker that finds helper function calls
// and records the conditional context at each call site. It mirrors the
// structure of walkWithConditionals but records helper calls instead of
// SDK calls.
func walkForHelpers(node ast.Node, state *findHelperState) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.BlockStmt:
		for _, stmt := range n.List {
			walkForHelpers(stmt, state)
		}

	case *ast.ExprStmt:
		walkForHelpers(n.X, state)

	case *ast.IfStmt:
		// Save state for restoration after the if-block
		savedCondDepth := state.condDepth
		savedCondReason := state.condReason
		savedCondKind := state.condKind

		// Check if this if-statement gates the body on an attribute
		guard := extractConditionGuard(n)
		if guard.Attribute != "" {
			state.condDepth++
			if state.condReason == "" {
				state.condReason = guard.Attribute
				state.condKind = guard.Kind
			}

			walkForHelpers(n.Body, state)
			walkForHelpers(n.Else, state)

			state.condDepth--
			if state.condDepth == 0 {
				state.condReason = ""
				state.condKind = ""
			}
		} else {
			walkForHelpers(n.Body, state)
			walkForHelpers(n.Else, state)
		}

		// Restore state (inner if-blocks might have changed it)
		state.condDepth = savedCondDepth
		state.condReason = savedCondReason
		state.condKind = savedCondKind

	case *ast.CallExpr:
		if hc := findHelperCall(n, state.connVar, state.f, state.condReason, state.condKind); hc != nil {
			state.helpers = append(state.helpers, *hc)
			return
		}
		// Walk arguments (recursive calls might contain more helper calls)
		for _, arg := range n.Args {
			walkForHelpers(arg, state)
		}

	case *ast.ReturnStmt:
		for _, expr := range n.Results {
			walkForHelpers(expr, state)
		}

	case *ast.AssignStmt:
		for _, expr := range n.Lhs {
			walkForHelpers(expr, state)
		}
		for _, expr := range n.Rhs {
			walkForHelpers(expr, state)
		}

	case *ast.ForStmt:
		walkForHelpers(n.Body, state)

	case *ast.RangeStmt:
		walkForHelpers(n.Body, state)

	case *ast.SwitchStmt:
		walkForHelpers(n.Body, state)

	case *ast.CaseClause:
		for _, stmt := range n.Body {
			walkForHelpers(stmt, state)
		}

	case *ast.DeferStmt:
		walkForHelpers(n.Call, state)

	case *ast.GoStmt:
		walkForHelpers(n.Call, state)

	case *ast.LabeledStmt:
		walkForHelpers(n.Stmt, state)
	}
}

// findHelperCall checks if a CallExpr is a call to a helper function (defined
// in the same file) that passes connVar. If so, returns a helperCall populated
// with the current guard.
func findHelperCall(call *ast.CallExpr, connVar string, f *ast.File, condReason string, condKind ConditionKind) *helperCall {
	fnName := ""
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		fnName = fn.Name
	case *ast.SelectorExpr:
		fnName = fn.Sel.Name
	default:
		return nil
	}

	if !funcDefinedInFile(f, fnName) {
		return nil
	}

	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && ident.Name == connVar {
			return &helperCall{Name: fnName, CondReason: condReason, CondKind: condKind}
		}
	}

	return nil
}

// funcDefinedInFile checks if a function with the given name is declared in the
// same Go source file.
func funcDefinedInFile(f *ast.File, name string) bool {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if ok && fd.Name.Name == name {
			return true
		}
	}
	return false
}

// resolveTransitiveExtracted recursively collects SDK calls from a function and
// all helpers it transitively calls. When a helper is called at a call site
// inside a guarded block (if d.GetOk("attr") or if d.HasChange("attr")), the
// call-site guard is propagated to the helper's resolved actions — unless the
// helper already has a more specific guard on the action itself.
// Uses a depth limit (5) and a visited set to prevent infinite recursion.
func resolveTransitiveExtracted(funcName string, allSdkCalls map[string][]ExtractedAction, callGraph map[string][]helperCall, visited map[string]bool, depth int) []ExtractedAction {
	const maxHelperDepth = 5
	if depth > maxHelperDepth || visited[funcName] {
		return nil
	}
	visited[funcName] = true

	var resolved []ExtractedAction

	// Include this function's own SDK calls
	if calls, ok := allSdkCalls[funcName]; ok {
		resolved = append(resolved, calls...)
	}

	// Follow helper calls
	if helpers, ok := callGraph[funcName]; ok {
		for _, hc := range helpers {
			// Copy visited map to isolate each branch
			branchVisited := make(map[string]bool)
			for k := range visited {
				branchVisited[k] = true
			}
			helperActions := resolveTransitiveExtracted(hc.Name, allSdkCalls, callGraph, branchVisited, depth+1)

			// Propagate call-site condition to helper-resolved actions.
			// Do NOT override a more specific condition the helper itself
			// carries (i.e., if the helper's action already has a non-empty
			// Condition, keep it — it's more precise).
			if hc.CondReason != "" {
				for i := range helperActions {
					if helperActions[i].Condition == "" {
						helperActions[i].Conditional = true
						helperActions[i].Condition = hc.CondReason
						helperActions[i].ConditionKind = hc.CondKind
					}
				}
			}

			resolved = append(resolved, helperActions...)
		}
	}

	return resolved
}
