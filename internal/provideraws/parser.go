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

// ParseResourceFile parses a Go source file from the terraform-provider-aws
// and extracts the IAM permissions (actions) required by each CRUD function.
//
// It handles:
// - Direct conn.Method() calls in CRUD function bodies
// - Helper function calls: retryCreateRole(ctx, conn, ...) → conn.CreateRole
// - Recursive helper chains: findRoleByName → findRole → conn.GetRole
// - Anonymous function bodies (via tfresource.RetryWhen)
// - Function return following (Create returns Read → include Read permissions)
//
// src: the full Go source code of the resource file
// tfType: terraform resource type, e.g. "aws_backup_vault"
// resourceName: the CamelCase name used in function names, e.g. "Vault"
func ParseResourceFile(src string, tfType string, resourceName string) (map[string][]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, tfType+".go", src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse Go source: %w", err)
	}

	// Phase 1: Extract direct SDK calls from ALL functions in the file
	allSdkCalls := make(map[string][]string) // funcName -> actions
	funcConnVar := make(map[string]string)   // funcName -> connVar
	funcService := make(map[string]string)   // funcName -> service

	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		calls, connVar, service := extractSDKCallsWithConnInfo(fd)
		if len(calls) > 0 {
			allSdkCalls[name] = dedup(calls)
		}
		if connVar != "" {
			funcConnVar[name] = connVar
		}
		if service != "" {
			funcService[name] = service
		}
	}

	// Phase 1b: Build a call graph — for each function, track which helpers it calls
	callGraph := make(map[string][]string) // funcName -> helper names
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

	// Phase 1c: Resolve transitive SDK calls for each function
	resolvedCalls := make(map[string][]string) // funcName -> resolved actions
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if !strings.HasPrefix(name, "resource") || !containsIgnoreCase(name, resourceName) {
			continue
		}
		resolved := resolveTransitive(name, allSdkCalls, callGraph, make(map[string]bool), 0)
		if len(resolved) > 0 {
			resolvedCalls[name] = dedup(resolved)
		}
	}

	// Phase 2: Map to CRUD operations
	actions := make(map[string][]string)
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
		actions[k] = dedup(v)
	}

	return actions, nil
}

// extractSDKCallsWithConnInfo walks the body of a function and extracts all AWS SDK
// API calls as IAM action strings, along with the service and connection variable name.
// Returns (actions, connVar, service).
func extractSDKCallsWithConnInfo(fd *ast.FuncDecl) ([]string, string, string) {
	if fd.Body == nil {
		return nil, "", ""
	}

	var actions []string
	service := ""
	connVar := ""

	// Also detect conn from function parameters (helpers take conn as param)
	findConnParam(fd, &connVar, &service)

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if svc, conn := findClientAssignment(node); svc != "" {
				service = svc
				connVar = conn
			}
		case *ast.CallExpr:
			if action := extractCallAction(node, connVar, service); action != "" {
				actions = append(actions, action)
			}
		}
		return true
	})

	return actions, connVar, service
}

// findConnParam checks function parameters for a conn variable with a typed
// SDK client (e.g., conn *iam.Client). Sets connVar and service if found.
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
// like *iam.Client, *backup.Client, *dynamodb.Client, etc.
func paramTypeToService(expr ast.Expr) string {
	// Unwrap star expressions: *iam.Client
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	// Look for: pkg.Client
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if sel.Sel.Name != "Client" {
		return ""
	}
	// Get the package: iam, backup, dynamodb, etc.
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return pkgIdent.Name
}

// extractSDKCalls walks the body of a function and extracts all AWS SDK API
// calls as IAM action strings (e.g., "backup:CreateBackupVault").
// Deprecated: use extractSDKCallsWithConnInfo for new code.
func extractSDKCalls(fd *ast.FuncDecl) []string {
	actions, _, _ := extractSDKCallsWithConnInfo(fd)
	return actions
}

// maxHelperDepth limits how deep we follow helper call chains to prevent
// infinite recursion from mutually recursive helpers.
const maxHelperDepth = 5

// resolveTransitive recursively collects all SDK calls reachable from a
// function, following helper calls (call graph edges).
func resolveTransitive(funcName string, sdkCalls map[string][]string, callGraph map[string][]string, visited map[string]bool, depth int) []string {
	if depth > maxHelperDepth {
		return nil
	}
	if visited[funcName] {
		return nil
	}
	visited[funcName] = true

	var all []string

	// Direct SDK calls
	if actions, ok := sdkCalls[funcName]; ok {
		all = append(all, actions...)
	}

	// Follow helpers
	if helpers, ok := callGraph[funcName]; ok {
		for _, helperName := range helpers {
			all = append(all, resolveTransitive(helperName, sdkCalls, callGraph, visited, depth+1)...)
		}
	}

	return all
}

// findHelperCalls finds function calls within fd's body where the first
// argument matches connVar and the function exists in the AST file f.
// Returns the names of called helper functions.
func findHelperCalls(fd *ast.FuncDecl, connVar string, f *ast.File) []string {
	var helpers []string

	// Build a set of function names defined in this file
	funcNames := make(map[string]bool)
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok {
			funcNames[fd.Name.Name] = true
		}
	}

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Get the function name being called
		var calledName string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			calledName = fn.Name
		case *ast.SelectorExpr:
			calledName = fn.Sel.Name
		default:
			return true
		}

		// Skip resource functions (handled separately by return following)
		if isResourceFunc(calledName) {
			return true
		}

		// Check if it's defined in this file
		if !funcNames[calledName] {
			return true
		}

		// Check if connVar appears as any argument (usually second after ctx)
		for _, arg := range call.Args {
			if ident, ok := arg.(*ast.Ident); ok {
				if ident.Name == connVar {
					helpers = append(helpers, calledName)
					break
				}
			}
		}

		return true
	})

	return helpers
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
