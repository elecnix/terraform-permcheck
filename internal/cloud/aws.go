package cloud

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// cfnSchema is the subset of a CloudFormation resource schema we need.
type cfnSchema struct {
	TypeName string `json:"typeName"`
	Handlers struct {
		Create struct {
			Permissions []string `json:"permissions"`
		} `json:"create"`
		Read struct {
			Permissions []string `json:"permissions"`
		} `json:"read"`
		Update struct {
			Permissions []string `json:"permissions"`
		} `json:"update"`
		Delete struct {
			Permissions []string `json:"permissions"`
		} `json:"delete"`
		List struct {
			Permissions []string `json:"permissions"`
		} `json:"list"`
	} `json:"handlers"`
}

// AWSProvider resolves AWS resource types via the CloudFormation schema registry.
type AWSProvider struct {
	client  *http.Client
	baseURL string // e.g. "https://schema.cloudformation.us-east-1.amazonaws.com"
}

// registryTimeout bounds one registry request, so a stalled registry fails
// the lookup instead of hanging the run.
const registryTimeout = 30 * time.Second

// NewAWSProvider creates a new AWSProvider.
func NewAWSProvider() *AWSProvider {
	return &AWSProvider{
		client:  &http.Client{Timeout: registryTimeout},
		baseURL: "https://schema.cloudformation.us-east-1.amazonaws.com",
	}
}

// Resolve maps a terraform resource type to its CloudFormation schema and
// returns the required IAM permissions. The error is marked
// iam.ErrUnknownType when the registry holds none of the candidate keys, and
// iam.ErrLookupFailed when any request failed for another reason, since that
// key may exist.
func (p *AWSProvider) Resolve(tfType string) (*iam.Schema, error) {
	keys := cfnKeys(tfType)
	if len(keys) == 0 {
		return nil, fmt.Errorf("%q: cannot derive CFN registry key: %w", tfType, iam.ErrUnknownType)
	}
	var lastErr, failed error
	for _, key := range keys {
		schema, err := p.fetch(key)
		if err == nil {
			return toSchema(schema), nil
		}
		lastErr = err
		if errors.Is(err, iam.ErrLookupFailed) {
			failed = err
		}
	}
	if failed != nil {
		lastErr = failed
	}
	return nil, fmt.Errorf("resolve %s (tried %v): %w", tfType, keys, lastErr)
}

// cfnKeys returns candidate CloudFormation registry keys for a terraform type.
//
// A registry key is the CloudFormation type name in lower case with "::"
// written as "-": AWS::ApiGatewayV2::DomainName is aws-apigatewayv2-domainname.
// The resource name never holds a hyphen, so the words of the Terraform
// resource name are joined without one. Some resource names also carry the
// service prefix (BackupVault rather than Vault), so that form comes second.
//
//	aws_backup_vault             → ["aws-backup-vault", "aws-backup-backupvault"]
//	aws_apigatewayv2_domain_name → ["aws-apigatewayv2-domainname", "aws-apigatewayv2-apigatewayv2domainname"]
//	aws_cloudwatch_log_group     → ["aws-logs-loggroup"]
//
// Types whose Terraform name does not follow the CloudFormation one come from
// cfnTypeOverrides and cfnServicePrefixes. Both are consulted below, and they
// are disjoint, so no entry of either can shadow the other.
//
// cfnKeys returns the candidate CloudFormation registry keys for a terraform
// type, in the order Resolve should try them.
//
// Three tables supply the candidates and a type is covered by exactly one:
// cfnTypeOverrides holds the exact types whose Terraform name does not follow
// the CloudFormation one, cfnServicePrefixes holds the families whose
// CloudFormation namespace differs, and cfnGenericKeys derives the rest from
// the name. The tables are disjoint — an override key is a bare type name and
// a prefix row ends in "_" — so neither can make an entry of the other dead;
// TestCfnKeys_EveryTableEntryIsReachable checks that.
func cfnKeys(tfType string) []string {
	if !strings.HasPrefix(tfType, "aws_") {
		return nil
	}
	var keys []string
	if key, ok := cfnTypeOverrides[tfType]; ok {
		keys = append(keys, key)
	}
	keys = append(keys, cfnPrefixKeys(tfType)...)
	if len(keys) == 0 {
		keys = cfnGenericKeys(tfType)
	}
	return keys
}

// cfnPrefixKeys returns the keys of the service-prefix row that covers tfType,
// or nothing when no row does. A row ends in "_", so it covers a family
// (aws_lb_listener) and never a bare type (aws_lb, which has an override entry
// instead). No row is a prefix of another, so the first match is the only
// match.
func cfnPrefixKeys(tfType string) []string {
	for _, sp := range cfnServicePrefixes {
		if !strings.HasPrefix(tfType, sp.prefix) {
			continue
		}
		resource := strings.ReplaceAll(strings.TrimPrefix(tfType, sp.prefix), "_", "")
		if sp.word == "" {
			return []string{"aws-" + sp.service + "-" + resource}
		}
		return []string{
			"aws-" + sp.service + "-" + sp.word + resource,
			"aws-" + sp.service + "-" + resource,
		}
	}
	return nil
}

// cfnGenericKeys derives the candidates from the Terraform name itself: the
// resource words joined (backup-vault, apigatewayv2-domainname) first, then
// the service prefix repeated (backup-backupvault) for the resource names that
// carry it.
func cfnGenericKeys(tfType string) []string {
	parts := strings.Split(strings.TrimPrefix(tfType, "aws_"), "_")
	if len(parts) < 2 {
		return nil
	}
	service := parts[0]

	// Form 1: the resource words joined (backup-vault, apigatewayv2-domainname).
	k1 := "aws-" + service + "-" + strings.Join(parts[1:], "")

	// Form 2: service prefix + resource (backup-backupvault).
	k2 := "aws-" + service + "-" + strings.Join(parts, "")

	if k1 == k2 {
		return []string{k1}
	}
	return []string{k1, k2}
}

// cfnServicePrefixes maps Terraform type prefixes to the CloudFormation
// namespace their resources live in, when the two differ. A row's prefix ends
// in "_" and covers a family of types; the bare type of that family, if its
// registry key differs too, is an exact entry in cfnTypeOverrides instead. The
// rest of the type name, joined, is the resource name, tried first with word
// in front when the prefix swallowed a word some resource names keep: LogGroup,
// but also EventBus next to Rule.
var cfnServicePrefixes = []struct{ prefix, service, word string }{
	{"aws_cloudwatch_event_", "events", "event"},
	{"aws_cloudwatch_log_", "logs", "log"},
	{"aws_api_gateway_", "apigateway", ""},
	{"aws_alb_", "elasticloadbalancingv2", ""},
	{"aws_lb_", "elasticloadbalancingv2", ""},
	{"aws_sfn_", "stepfunctions", ""},
}

// cfnTypeOverrides maps Terraform types whose resource name differs from the
// CloudFormation one to their registry key, and each key was checked against
// the registry. A key here is an exact type name, never a prefix: the types
// without an entry of their own are derived, and the families whose namespace
// differs are in cfnServicePrefixes.
var cfnTypeOverrides = map[string]string{
	"aws_alb":                     "aws-elasticloadbalancingv2-loadbalancer",
	"aws_lb":                      "aws-elasticloadbalancingv2-loadbalancer",
	"aws_cloudwatch_metric_alarm": "aws-cloudwatch-alarm",
	"aws_db_instance":             "aws-rds-dbinstance",
	"aws_db_parameter_group":      "aws-rds-dbparametergroup",
	"aws_db_subnet_group":         "aws-rds-dbsubnetgroup",
	"aws_rds_cluster":             "aws-rds-dbcluster",
	"aws_ebs_volume":              "aws-ec2-volume",
	"aws_eip":                     "aws-ec2-eip",
	"aws_elasticache_cluster":     "aws-elasticache-cachecluster",
	"aws_flow_log":                "aws-ec2-flowlog",
	"aws_iam_policy":              "aws-iam-managedpolicy",
	"aws_instance":                "aws-ec2-instance",
	"aws_internet_gateway":        "aws-ec2-internetgateway",
	"aws_key_pair":                "aws-ec2-keypair",
	"aws_launch_template":         "aws-ec2-launchtemplate",
	"aws_nat_gateway":             "aws-ec2-natgateway",
	"aws_network_interface":       "aws-ec2-networkinterface",
	"aws_route":                   "aws-ec2-route",
	"aws_route53_record":          "aws-route53-recordset",
	"aws_route53_zone":            "aws-route53-hostedzone",
	"aws_route_table":             "aws-ec2-routetable",
	"aws_security_group":          "aws-ec2-securitygroup",
	"aws_sns_topic_subscription":  "aws-sns-subscription",
	"aws_subnet":                  "aws-ec2-subnet",
	"aws_vpc":                     "aws-ec2-vpc",
	"aws_vpc_endpoint":            "aws-ec2-vpcendpoint",
	"aws_vpc_peering_connection":  "aws-ec2-vpcpeeringconnection",
}

// fetch downloads the CloudFormation schema for a registry key. The registry
// is served from S3, which answers 403 rather than 404 for a key it does not
// hold, so both mark iam.ErrUnknownType. A network error, a timeout, any
// other status and a body that does not parse mark iam.ErrLookupFailed.
func (p *AWSProvider) fetch(key string) (*cfnSchema, error) {
	url := p.baseURL + "/" + key + ".json"
	resp, err := p.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w: %w", url, iam.ErrLookupFailed, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusNotFound:
		return nil, fmt.Errorf("fetch %s: HTTP %d: %w", url, resp.StatusCode, iam.ErrUnknownType)
	default:
		return nil, fmt.Errorf("fetch %s: HTTP %d: %w", url, resp.StatusCode, iam.ErrLookupFailed)
	}
	var s cfnSchema
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("parse %s: %w: %w", url, iam.ErrLookupFailed, err)
	}
	return &s, nil
}

// toSchema converts a CloudFormation schema to an iam.Schema. The
// registry lists handler permissions without gates, so every requirement is
// ungated. Every handler is a known operation, even one with no permissions.
func toSchema(cfn *cfnSchema) *iam.Schema {
	return &iam.Schema{
		TypeName: cfn.TypeName,
		Ops: map[string][]iam.Requirement{
			"create": iam.Unconditional(cfn.Handlers.Create.Permissions...),
			"read":   iam.Unconditional(cfn.Handlers.Read.Permissions...),
			"update": iam.Unconditional(cfn.Handlers.Update.Permissions...),
			"delete": iam.Unconditional(cfn.Handlers.Delete.Permissions...),
			"list":   iam.Unconditional(cfn.Handlers.List.Permissions...),
		},
	}
}
