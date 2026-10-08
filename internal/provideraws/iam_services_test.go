package provideraws

import (
	"bufio"
	"go/parser"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// iamPrefixesGolden lists every IAM service prefix of the AWS service
// reference. gen_iam_services.go writes it next to the tables it generates.
const iamPrefixesGolden = "testdata/iam_prefixes.txt"

func knownIAMPrefixes(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open(iamPrefixesGolden)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	known := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			known[line] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(known) < 300 {
		t.Fatalf("%s lists only %d prefixes", iamPrefixesGolden, len(known))
	}
	return known
}

// A finding under a prefix IAM does not know can never be satisfied, so every
// prefix the tables produce must be one the service reference lists.
func TestIAMPrefixTables_ProduceKnownPrefixes(t *testing.T) {
	known := knownIAMPrefixes(t)
	check := func(table, key, prefix string) {
		// A client key folds to its IAM prefix in sdKMethodToIAMAction.
		if p, ok := sdkClientKeyPrefixes[prefix]; ok {
			prefix = p
		}
		if !known[prefix] && !retiredIAMPrefixes[prefix] {
			t.Errorf("%s[%q] = %q, which is not an IAM service prefix", table, key, prefix)
		}
	}
	for pkg, prefix := range sdkPackageIAMPrefixes {
		check("sdkPackageIAMPrefixes", pkg, prefix)
	}
	for acc, prefix := range clientAccessorIAMPrefixes {
		check("clientAccessorIAMPrefixes", acc, prefix)
	}
	for prefix := range sdkOperationActions {
		check("sdkOperationActions", prefix, prefix)
	}
}

func TestParamTypeToService_SDKPackagesWhoseNameIsNotThePrefix(t *testing.T) {
	tests := []struct{ pkg, want string }{
		{"elasticloadbalancingv2", "elasticloadbalancing"},
		{"emr", "elasticmapreduce"},
		{"costexplorer", "ce"},
		{"databasemigrationservice", "dms"},
		{"dms", "dms"}, // the provider's import alias
		{"elasticsearch", "es"},
		{"cognitoidentity", "cognito-identity"},
		{"cognitoidentityprovider", "cognito-idp"},
		{"sfn", "states"},
		{"configservice", "config"},
		{"efs", "elasticfilesystem"},
		{"eventbridge", "events"},
		{"opensearch", "es"},
		{"cloudwatchlogs", "logs"},
		{"cloudcontrol", "cloudformation"},
		{"resourcegroupstaggingapi", "tag"},
		// API Gateway v2 keeps a client key of its own, folded to the
		// apigateway prefix when its actions are named.
		{"apigatewayv2", "apigatewayv2"},
		{"s3control", "s3"},
		{"s3", "s3"},
		{"iam", "iam"},
	}
	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			expr, err := parser.ParseExpr("*" + tt.pkg + ".Client")
			if err != nil {
				t.Fatal(err)
			}
			if got := paramTypeToService(expr); got != tt.want {
				t.Errorf("paramTypeToService(*%s.Client) = %q, want %q", tt.pkg, got, tt.want)
			}
		})
	}
}

func TestClientMethodToService_ProviderAccessors(t *testing.T) {
	tests := []struct{ accessor, want string }{
		{"ELBV2Client", "elasticloadbalancing"},
		{"EMRClient", "elasticmapreduce"},
		{"CEClient", "ce"},
		{"DMSClient", "dms"},
		{"LogsClient", "logs"},
		{"SFNClient", "states"},
		{"ConfigServiceClient", "config"},
		{"OpenSearchClient", "es"},
		{"S3ExpressClient", "s3express"},
	}
	for _, tt := range tests {
		t.Run(tt.accessor, func(t *testing.T) {
			if got := clientMethodToService(tt.accessor); got != tt.want {
				t.Errorf("clientMethodToService(%q) = %q, want %q", tt.accessor, got, tt.want)
			}
		})
	}
}

// The service reference lists the IAM actions each S3 operation needs. These
// are the ones whose SDK method name is not an IAM action.
func TestSDKMethodToIAMAction_S3OperationsTheReferenceRenames(t *testing.T) {
	tests := []struct{ method, want string }{
		{"PutBucketLifecycleConfiguration", "s3:PutLifecycleConfiguration"},
		{"GetBucketLifecycleConfiguration", "s3:GetLifecycleConfiguration"},
		{"DeleteBucketLifecycle", "s3:PutLifecycleConfiguration"},
		{"DeleteObjects", "s3:DeleteObject"},
		{"HeadObject", "s3:GetObject"},
		{"HeadBucket", "s3:ListBucket"},
		{"ListObjects", "s3:ListBucket"},
		{"ListObjectsV2", "s3:ListBucket"},
		{"ListObjectVersions", "s3:ListBucketVersions"},
		{"DeleteBucketEncryption", "s3:PutEncryptionConfiguration"},
		{"DeletePublicAccessBlock", "s3:PutBucketPublicAccessBlock"},
		{"DeleteBucketCors", "s3:PutBucketCORS"},
		{"PutBucketCors", "s3:PutBucketCORS"},
		{"CreateMultipartUpload", "s3:PutObject"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if got := sdKMethodToIAMAction(tt.method, "s3"); got != tt.want {
				t.Errorf("sdKMethodToIAMAction(%q, s3) = %q, want %q", tt.method, got, tt.want)
			}
		})
	}
}

func TestSDKMethodToIAMAction_OtherServices(t *testing.T) {
	tests := []struct{ method, service, want string }{
		{"Invoke", "lambda", "lambda:InvokeFunction"},
		{"SendMessageBatch", "sqs", "sqs:SendMessage"},
		{"CreateRestApi", "apigateway", "apigateway:POST"},
		{"UpdateStage", "apigateway", "apigateway:PATCH"},
		{"CreateBudget", "budgets", "budgets:ModifyBudget"},
		// A method that is an IAM action keeps its name.
		{"CreateLogGroup", "logs", "logs:CreateLogGroup"},
	}
	for _, tt := range tests {
		t.Run(tt.service+"/"+tt.method, func(t *testing.T) {
			if got := sdKMethodToIAMAction(tt.method, tt.service); got != tt.want {
				t.Errorf("sdKMethodToIAMAction(%q, %q) = %q, want %q", tt.method, tt.service, got, tt.want)
			}
		})
	}
}

var (
	sdkImportRE = regexp.MustCompile(`"github.com/aws/aws-sdk-go(?:-v2)?/service/([a-z0-9]+)"`)
	accessorRE  = regexp.MustCompile(`func \(c \*AWSClient\) ([A-Za-z0-9]+Client)\(ctx context\.Context\) \*[a-z0-9]+\.Client`)
)

// Every SDK package the provider imports, and every AWSClient accessor it
// declares, must have a row: a missing row falls back to the package name,
// which is wrong whenever IAM spells the service differently.
func TestIAMPrefixTables_CoverTheProviderCheckout(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the provider checkout")
	}
	dir := defaultCacheDir()
	if _, err := os.Stat(filepath.Join(dir, "internal", "conns")); err != nil {
		t.Skipf("provider checkout not found at %s", dir)
	}

	missing := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(dir, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range sdkImportRE.FindAllSubmatch(src, -1) {
			if _, ok := sdkPackageIAMPrefixes[string(m[1])]; !ok {
				missing[string(m[1])] = true
			}
		}
		if filepath.Base(filepath.Dir(path)) == "conns" {
			for _, m := range accessorRE.FindAllSubmatch(src, -1) {
				if _, ok := clientAccessorIAMPrefixes[string(m[1])]; !ok {
					missing[string(m[1])] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name := range missing {
		t.Errorf("%s has no IAM prefix; rerun gen_iam_services.go against %s", name, DefaultProviderRef)
	}
}

// The tables come from one provider checkout. A bump of DefaultProviderRef
// must regenerate them too.
func TestIAMServices_GeneratedFromDefaultRef(t *testing.T) {
	if iamServicesProviderRef != DefaultProviderRef {
		t.Errorf("iam_services_gen.go was generated from %s, but DefaultProviderRef is %s; rerun gen_iam_services.go", iamServicesProviderRef, DefaultProviderRef)
	}
}
