package provideraws

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// sdkCallObserver collects the AWS SDK calls the traversal reaches, each tagged
// with the conditional context it was reached under.
type sdkCallObserver struct {
	reqs []iam.Requirement
}

func (o *sdkCallObserver) onCall(call *ast.CallExpr, ctx *walkContext) bool {
	// SDK API call: conn.MethodName(ctx, ...), or a paginator over one.
	action := extractCallAction(call, ctx.conns)
	if action == "" {
		return false
	}
	// An SDK client method always returns an error last, so a statement
	// that drops the last result drops the error.
	discarded := ctx.discardOf(call) != discardNone && isClientMethodCall(call, ctx.conns)
	o.reqs = append(o.reqs, requirements(action, ctx.gates(ctx.bestEffort || discarded))...)
	return true
}

// isClientMethodCall reports whether a call is a method of an SDK client,
// such as conn.DeleteRole(ctx, input), which returns an error last.
func isClientMethodCall(call *ast.CallExpr, conns map[string]string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && clientService(sel.X, conns) != ""
}

// findClientAssignment detects a client connection assignment like:
//
//	conn := meta.(*conns.AWSClient).BackupClient(ctx)
//
// Returns (service, connVar) where service is "backup" and connVar is "conn".
func findClientAssignment(stmt *ast.AssignStmt) (string, string) {
	if len(stmt.Lhs) != 1 || len(stmt.Rhs) != 1 || stmt.Tok != token.DEFINE {
		return "", ""
	}
	lhsIdent, ok := stmt.Lhs[0].(*ast.Ident)
	if !ok {
		return "", ""
	}
	service := clientAccessorService(stmt.Rhs[0])
	if service == "" {
		return "", ""
	}
	return service, lhsIdent.Name
}

// clientAccessorService returns the service of a client accessor call such as
// meta.(*conns.AWSClient).S3Client(ctx) or awsClient.EC2Client(ctx), or "" when
// the expression is not one.
func clientAccessorService(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if !isClientAccessor(sel.Sel.Name) {
		return ""
	}
	return clientMethodToService(sel.Sel.Name)
}

// isClientAccessor reports whether a method name reads like an AWSClient
// accessor for one service's SDK client, e.g. "BackupClient".
func isClientAccessor(name string) bool {
	if !strings.HasSuffix(name, "Client") || len(name) == len("Client") {
		return false
	}
	if name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	// A constructor such as s3.NewPresignClient builds a client from
	// another rather than reading one off the AWSClient.
	if strings.HasPrefix(name, "New") || name == "HTTPClient" {
		return false
	}
	return true
}

// clientService returns the service an expression's client talks to: a
// client variable in scope, or an inline client accessor call.
func clientService(expr ast.Expr, conns map[string]string) string {
	if ident, ok := expr.(*ast.Ident); ok {
		return conns[ident.Name]
	}
	return clientAccessorService(expr)
}

// extractCallAction checks if a call expression is an AWS SDK API call on a
// client, e.g., conn.CreateBackupVault(ctx, input), or builds a paginator over
// one, e.g., cloudwatchlogs.NewDescribeLogGroupsPaginator(conn, input).
// Returns the IAM action string (e.g., "backup:CreateBackupVault") or "".
func extractCallAction(call *ast.CallExpr, conns map[string]string) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}

	method := sel.Sel.Name // e.g., "CreateBackupVault"
	if service := clientService(sel.X, conns); service != "" {
		if isAWSMethod(method) {
			return sdKMethodToIAMAction(method, service)
		}
		return ""
	}

	// A paginator calls the operation it is named after on every page.
	if op := paginatorOperation(method); op != "" && len(call.Args) > 0 {
		if service := clientService(call.Args[0], conns); service != "" {
			return sdKMethodToIAMAction(op, service)
		}
	}

	// The S3 feature manager makes S3 calls with the client it is handed.
	if op, ok := s3ManagerCalls[method]; ok {
		for _, arg := range call.Args {
			if clientService(arg, conns) == "s3" {
				return sdKMethodToIAMAction(op, "s3")
			}
		}
	}
	return ""
}

// s3ManagerCalls maps the S3 feature manager functions
// (github.com/aws/aws-sdk-go-v2/feature/s3/manager) to the S3 operation they
// make. An upload needs s3:PutObject whether it goes in one part or many.
var s3ManagerCalls = map[string]string{
	"NewUploader":     "PutObject",
	"NewDownloader":   "GetObject",
	"GetBucketRegion": "HeadBucket",
}

// paginatorOperation returns the operation a paginator constructor pages
// through, "DescribeLogGroups" for "NewDescribeLogGroupsPaginator", or "".
func paginatorOperation(name string) string {
	if !strings.HasPrefix(name, "New") || !strings.HasSuffix(name, "Paginator") {
		return ""
	}
	op := strings.TrimSuffix(strings.TrimPrefix(name, "New"), "Paginator")
	if !isAWSMethod(op) {
		return ""
	}
	return op
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
	// Options returns the client's configuration; it calls no API.
	return name != "Options"
}

// sdKMethodToIAMAction converts an AWS SDK method name and service to an IAM
// action string. Convention: backup + CreateBackupVault -> backup:CreateBackupVault.
// A method that IAM does not know as an action is renamed to the action the
// AWS service reference says it needs, e.g. s3 HeadObject -> s3:GetObject.
//
// A service can be a client key that is not an IAM prefix, such as
// apigatewayv2. Its own rows come first, then the rows of the prefix it folds
// to, and the action takes that prefix: API Gateway v2 TagResource is
// apigateway:POST, while v1 TagResource is apigateway:PUT.
func sdKMethodToIAMAction(method string, service string) string {
	prefix := service
	if p, ok := sdkClientKeyPrefixes[service]; ok {
		prefix = p
	}
	if canonical := normalizeSDKMethod(service, method); canonical != "" {
		return prefix + ":" + canonical
	}
	if canonical := normalizeSDKMethod(prefix, method); canonical != "" {
		return prefix + ":" + canonical
	}
	return prefix + ":" + method
}

// normalizeSDKMethod returns the IAM action an SDK method needs when IAM spells
// it differently, or "" when the method name is the action.
func normalizeSDKMethod(service, method string) string {
	return sdkOperationActions[service][method]
}

// clientMethodToService returns the IAM service prefix of the client an
// AWSClient accessor returns ("ELBV2Client" -> "elasticloadbalancing"). An
// accessor the provider does not declare falls back to its name less Client,
// read as an SDK package name.
func clientMethodToService(clientMethod string) string {
	if svc, ok := clientAccessorIAMPrefixes[clientMethod]; ok {
		return svc
	}
	base := strings.TrimSuffix(clientMethod, "Client")
	base = strings.TrimSuffix(base, "Regional")
	base = strings.TrimSuffix(base, "Global")
	base = strings.ToLower(base)
	if svc := sdkPackageToIAMService(base); svc != "" {
		return svc
	}
	return base
}

// extractSDKCallsWithConnInfo walks the body of a function and extracts all AWS
// SDK API calls. Clients come from client assignments
// (conn := meta.(*conns.AWSClient).XxxClient(ctx)), from typed parameters
// (func helper(ctx, conn *iam.Client)), and from inline accessor calls.
func extractSDKCallsWithConnInfo(fd *ast.FuncDecl) []iam.Requirement {
	return extractSDKCalls(fd, nil)
}

// extractSDKCalls is extractSDKCallsWithConnInfo with the package's model
// types, so the guards of framework resources gate the calls they guard.
func extractSDKCalls(fd *ast.FuncDecl, models modelTable) []iam.Requirement {
	if fd.Body == nil {
		return nil
	}
	ctx := newWalkContext(fd, models)
	obs := &sdkCallObserver{}
	walkBody(fd.Body, ctx, obs)
	return mergeRequirements(obs.reqs)
}

// paramTypeToService returns the IAM service prefix of a parameter typed as an
// SDK client: *iam.Client -> "iam", *cloudwatchlogs.Client -> "logs". Any type
// other than a pointer to a package's Client yields "".
func paramTypeToService(expr ast.Expr) string {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return ""
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Client" {
		return ""
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	// ident.Name is the package, or the name the file imports it under.
	if svc := sdkPackageToIAMService(ident.Name); svc != "" {
		return svc
	}
	return ident.Name
}

// sdkPackageToIAMService maps an AWS SDK Go package name, or an alias the
// provider imports one under, to its IAM service prefix
// ("elasticloadbalancingv2" -> "elasticloadbalancing"). It returns "" for a
// package the generated table does not know.
func sdkPackageToIAMService(pkg string) string {
	return sdkPackageIAMPrefixes[pkg]
}
