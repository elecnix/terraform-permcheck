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

// ExtractedAction represents an AWS IAM action extracted from a provider
// source file, with metadata about whether it is conditionally called.
type ExtractedAction struct {
	Action      string // e.g., "backup:CreateBackupVault"
	Conditional bool   // true if this SDK call is inside a conditional block
	Condition   string // attribute name guarding the call, e.g. "kms_key_arn"
}

// ParseResourceFile parses a Go source file from the terraform-provider-aws
// and extracts the IAM permissions (actions) required by each CRUD function.
// Returns all actions (both unconditional and conditional) as plain strings.
//
// For structured results with conditional metadata, use ParseResourceFileStructured.
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
// actions with conditional metadata (whether the call is inside an if-statement
// guarded by d.GetOk() or d.Get()).
func ParseResourceFileStructured(src string, tfType string, resourceName string) (map[string][]ExtractedAction, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, tfType+".go", src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse Go source: %w", err)
	}

	// Phase 1: Find all resource functions and extract their SDK calls
	funcActions := make(map[string][]ExtractedAction) // funcName -> actions

	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if !containsIgnoreCase(name, resourceName) || !strings.HasPrefix(name, "resource") {
			continue
		}

		funcCalls := extractSDKCalls(fd)
		if len(funcCalls) > 0 {
			funcActions[name] = dedupActions(funcCalls)
		}
	}

	// Phase 2: Map to CRUD operations
	actions := make(map[string][]ExtractedAction)

	operationMap := map[string]string{
		"Create": "create",
		"Read":   "read",
		"Update": "update",
		"Delete": "delete",
		"Import": "import",
	}

	for funcName, funcCalls := range funcActions {
		for opSuffix, opKey := range operationMap {
			if strings.HasSuffix(funcName, opSuffix) {
				actions[opKey] = append(actions[opKey], funcCalls...)
				break
			}
		}
	}

	// Phase 3: Follow function returns for implicit reads.
	// When Create returns resourceXxxRead, include Read permissions in Create.
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if !strings.HasPrefix(name, "resource") || !strings.HasSuffix(name, "Create") {
			continue
		}

		calledFuncs := findReturnedResourceCalls(fd)
		for _, calledName := range calledFuncs {
			if calledActions, ok := funcActions[calledName]; ok {
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
// calls, distinguishing unconditional calls from those inside conditional
// blocks (e.g., if d.GetOk("attribute") or d.Get(...)).
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
	condDepth  int    // how many conditional if-blocks deep we are
	condReason string // attribute name from the innermost conditional guard
}

// walkWithConditionals recursively walks an AST node, tracking conditional
// context from if-statements that gate on d.GetOk() or d.Get().
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

		// Check if this if-statement is conditional on d.GetOk() or d.Get()
		condAttr := extractConditionAttribute(n)
		if condAttr != "" {
			// Enter conditional context
			state.condDepth++
			if state.condReason == "" {
				state.condReason = condAttr
			}

			// Walk body inside conditional context
			walkWithConditionals(n.Body, state)

			// Also walk else if present (also conditional, could be different attribute)
			walkWithConditionals(n.Else, state)

			// Leave conditional context
			state.condDepth--
			if state.condDepth == 0 {
				state.condReason = ""
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
				Action:      action,
				Conditional: state.condDepth > 0,
				Condition:   state.condReason,
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

// extractConditionAttribute checks if an if-statement's condition involves
// d.GetOk("attribute") or d.Get("attribute") and returns the attribute name.
func extractConditionAttribute(ifStmt *ast.IfStmt) string {
	// Check Init statement: if v, ok := d.GetOk("attr"); ok { ...
	if ifStmt.Init != nil {
		if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok {
			for _, rhs := range assign.Rhs {
				if attr := extractGetOkAttribute(rhs); attr != "" {
					return attr
				}
			}
		}
	}

	// Check condition expression: d.Get("attr").(bool)
	// The condition may be wrapped in a TypeAssertExpr
	cond := ifStmt.Cond
	if ta, ok := cond.(*ast.TypeAssertExpr); ok {
		cond = ta.X
	}
	if attr := extractGetOkAttribute(cond); attr != "" {
		return attr
	}

	return ""
}

// extractGetOkAttribute checks if an expression is d.GetOk("attr") or
// d.Get("attr") and returns the attribute name.
func extractGetOkAttribute(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}

	// Must be a method call on something named "d"
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "d" {
		return ""
	}

	// Method must be GetOk or Get
	method := sel.Sel.Name
	if method != "GetOk" && method != "Get" {
		return ""
	}

	// First argument must be a string literal
	if len(call.Args) < 1 {
		return ""
	}

	bl, ok := call.Args[0].(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return ""
	}

	// Return the attribute name without quotes
	return strings.Trim(bl.Value, "\"")
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
func sdKMethodToIAMAction(method string, service string) string {
	return service + ":" + method
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
				if out[i].Action == ea.Action && ea.Conditional == false {
					out[i].Conditional = false
					out[i].Condition = ""
				}
			}
		}
	}
	return out
}
