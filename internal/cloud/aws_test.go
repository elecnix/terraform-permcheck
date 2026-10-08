package cloud

import (
	"testing"
)

func TestCfnKeys(t *testing.T) {
	tests := []struct {
		tfType string
		want0  string // first key
		want1  string // second key (if different from first)
	}{
		{"aws_backup_vault", "aws-backup-vault", "aws-backup-backupvault"},
		{"aws_dynamodb_table", "aws-dynamodb-table", "aws-dynamodb-dynamodbtable"},
		{"aws_iam_role", "aws-iam-role", "aws-iam-iamrole"},
		{"aws_s3_bucket", "aws-s3-bucket", "aws-s3-s3bucket"},
		{"aws_lambda_function", "aws-lambda-function", "aws-lambda-lambdafunction"},
		{"aws_secretsmanager_secret", "aws-secretsmanager-secret", "aws-secretsmanager-secretsmanagersecret"},
	}

	for _, tt := range tests {
		t.Run(tt.tfType, func(t *testing.T) {
			keys := cfnKeys(tt.tfType)
			if len(keys) < 1 {
				t.Fatalf("expected at least 1 key, got 0")
			}
			if keys[0] != tt.want0 {
				t.Errorf("key[0] = %q, want %q", keys[0], tt.want0)
			}
			if tt.want1 != "" && tt.want1 != tt.want0 {
				if len(keys) < 2 || keys[1] != tt.want1 {
					t.Errorf("key[1] = %v, want %q", keys, tt.want1)
				}
			}
		})
	}
}

func TestCfnKeysNonAWS(t *testing.T) {
	keys := cfnKeys("google_storage_bucket")
	if len(keys) != 0 {
		t.Errorf("expected empty keys for non-AWS type, got %v", keys)
	}
}

func TestNewAWSProvider(t *testing.T) {
	p := NewAWSProvider()
	if p.Name() != "aws" {
		t.Errorf("expected name 'aws', got %q", p.Name())
	}
	if p.baseURL == "" {
		t.Error("expected non-empty baseURL")
	}
}

// TestAWSProviderResolveReal checks the live CFN registry for known resource types.
func TestAWSProviderResolveReal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in short mode")
	}
	p := NewAWSProvider()

	tests := []struct {
		tfType       string
		wantAction   string // must appear in create permissions
		wantKmsGrant bool   // kms:CreateGrant should appear in create permissions
	}{
		{"aws_backup_vault", "backup:CreateBackupVault", true},
		{"aws_dynamodb_table", "dynamodb:CreateTable", false},
		{"aws_iam_role", "iam:CreateRole", false},
		{"aws_cloudwatch_log_group", "logs:CreateLogGroup", false},
		{"aws_apigatewayv2_domain_name", "apigateway:POST", false},
	}

	for _, tt := range tests {
		t.Run(tt.tfType, func(t *testing.T) {
			schema, err := p.Resolve(tt.tfType)
			if err != nil {
				t.Fatalf("resolve %s: %v", tt.tfType, err)
			}
			createPerms := schema.GetPermissions()["create"]
			if len(createPerms) == 0 {
				t.Fatal("expected non-empty create permissions")
			}

			found := false
			for _, a := range createPerms {
				if a == tt.wantAction {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %q in create permissions, got %v", tt.wantAction, createPerms)
			}

			if tt.wantKmsGrant {
				foundKms := false
				for _, a := range createPerms {
					if a == "kms:CreateGrant" {
						foundKms = true
						break
					}
				}
				if !foundKms {
					t.Errorf("expected kms:CreateGrant in create permissions, got %v", createPerms)
				}
			}
		})
	}
}

// TestCfnKeys_IncludeTheRegistryKey checks that the candidates hold the
// registry key for types whose resource name has several words or whose
// Terraform service differs from the CloudFormation namespace. Each expected
// key was checked against the live registry.
func TestCfnKeys_IncludeTheRegistryKey(t *testing.T) {
	tests := map[string]string{
		"aws_apigatewayv2_domain_name": "aws-apigatewayv2-domainname",
		"aws_backup_vault":             "aws-backup-vault",
		"aws_cloudwatch_log_group":     "aws-logs-loggroup",
		"aws_cloudwatch_log_stream":    "aws-logs-logstream",
		"aws_cloudwatch_metric_alarm":  "aws-cloudwatch-alarm",
		"aws_cloudwatch_event_rule":    "aws-events-rule",
		"aws_cloudwatch_event_bus":     "aws-events-eventbus",
		"aws_lb":                       "aws-elasticloadbalancingv2-loadbalancer",
		"aws_alb":                      "aws-elasticloadbalancingv2-loadbalancer",
		"aws_lb_listener":              "aws-elasticloadbalancingv2-listener",
		"aws_lb_target_group":          "aws-elasticloadbalancingv2-targetgroup",
		"aws_lb_listener_rule":         "aws-elasticloadbalancingv2-listenerrule",
		"aws_sfn_state_machine":        "aws-stepfunctions-statemachine",
		"aws_api_gateway_rest_api":     "aws-apigateway-restapi",
		"aws_vpc":                      "aws-ec2-vpc",
		"aws_subnet":                   "aws-ec2-subnet",
		"aws_security_group":           "aws-ec2-securitygroup",
		"aws_instance":                 "aws-ec2-instance",
		"aws_route_table":              "aws-ec2-routetable",
		"aws_route":                    "aws-ec2-route",
		"aws_eip":                      "aws-ec2-eip",
		"aws_ebs_volume":               "aws-ec2-volume",
		"aws_flow_log":                 "aws-ec2-flowlog",
		"aws_vpc_peering_connection":   "aws-ec2-vpcpeeringconnection",
		"aws_db_instance":              "aws-rds-dbinstance",
		"aws_rds_cluster":              "aws-rds-dbcluster",
		"aws_db_subnet_group":          "aws-rds-dbsubnetgroup",
		"aws_route53_zone":             "aws-route53-hostedzone",
		"aws_route53_record":           "aws-route53-recordset",
		"aws_iam_policy":               "aws-iam-managedpolicy",
		"aws_elasticache_cluster":      "aws-elasticache-cachecluster",
		"aws_sns_topic_subscription":   "aws-sns-subscription",
		"aws_autoscaling_group":        "aws-autoscaling-autoscalinggroup",
		"aws_secretsmanager_secret":    "aws-secretsmanager-secret",
		"aws_s3_bucket_policy":         "aws-s3-bucketpolicy",
	}
	for tfType, want := range tests {
		keys := cfnKeys(tfType)
		found := false
		for _, k := range keys {
			found = found || k == want
		}
		if !found {
			t.Errorf("cfnKeys(%q) = %v, want %q among them", tfType, keys, want)
		}
	}
}
