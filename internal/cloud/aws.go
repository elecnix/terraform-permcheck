package cloud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

// NewAWSProvider creates a new AWSProvider.
func NewAWSProvider() *AWSProvider {
	return &AWSProvider{
		client:  http.DefaultClient,
		baseURL: "https://schema.cloudformation.us-east-1.amazonaws.com",
	}
}

// Name returns "aws".
func (p *AWSProvider) Name() string { return "aws" }

// Resolve maps a terraform resource type to its CloudFormation schema and
// returns the required IAM permissions.
func (p *AWSProvider) Resolve(tfType string) (*Schema, error) {
	keys := cfnKeys(tfType)
	if len(keys) == 0 {
		return nil, fmt.Errorf("%q: cannot derive CFN registry key", tfType)
	}
	var lastErr error
	for _, key := range keys {
		schema, err := p.fetch(key)
		if err == nil {
			return toSchema(schema), nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("resolve %s (tried %v): %w", tfType, keys, lastErr)
}

// cfnKeys returns candidate CloudFormation registry keys for a terraform type.
//
// Terraform types like aws_backup_vault map to CFN types where the resource
// name may include the service prefix (BackupVault) or not (Table).
// We generate both forms and try them in order.
//
//	aws_backup_vault       → ["aws-backup-vault", "aws-backup-backupvault"]
//	aws_dynamodb_table     → ["aws-dynamodb-table", "aws-dynamodb-dynamodbtable"]
//	aws_iam_role           → ["aws-iam-role", "aws-iam-iamrole"]
func cfnKeys(tfType string) []string {
	if !strings.HasPrefix(tfType, "aws_") {
		return nil
	}
	rest := strings.TrimPrefix(tfType, "aws_")
	parts := strings.Split(rest, "_")
	if len(parts) < 2 {
		return nil
	}
	service := parts[0]
	resourceParts := parts[1:]

	// Form 1: hyphenated (matches dynamodb-table, iam-role, s3-bucket)
	k1 := "aws-" + service + "-" + strings.Join(resourceParts, "-")

	// Form 2: service prefix + resource, no separators
	// (matches backup-backupvault, backup-backupplan)
	allNoSep := strings.Join(parts, "")
	k2 := "aws-" + service + "-" + allNoSep

	// Deduplicate
	if k1 == k2 {
		return []string{k1}
	}
	return []string{k1, k2}
}

// fetch downloads the CloudFormation schema for a registry key.
func (p *AWSProvider) fetch(key string) (*cfnSchema, error) {
	url := p.baseURL + "/" + key + ".json"
	resp, err := p.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	var s cfnSchema
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", url, err)
	}
	return &s, nil
}

// toSchema converts a CloudFormation schema to our agnostic Schema type.
func toSchema(cfn *cfnSchema) *Schema {
	return &Schema{
		TypeName: cfn.TypeName,
		Permissions: map[string][]string{
			"create": cfn.Handlers.Create.Permissions,
			"read":   cfn.Handlers.Read.Permissions,
			"update": cfn.Handlers.Update.Permissions,
			"delete": cfn.Handlers.Delete.Permissions,
			"list":   cfn.Handlers.List.Permissions,
		},
	}
}
