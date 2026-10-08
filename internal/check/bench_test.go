package check

import (
	"fmt"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// BenchmarkRun_SecretVersions measures a plan check of 2000 secrets, each
// with a version whose secret_id references it. Each version resolves its
// reference among every change, so this measures reference resolution.
func BenchmarkRun_SecretVersions(b *testing.B) {
	const n = 2000
	var changes []*plan.ResourceChange
	for i := 0; i < n; i++ {
		secret := fmt.Sprintf("s%d", i)
		changes = append(changes,
			&plan.ResourceChange{Address: "aws_secretsmanager_secret." + secret, Type: "aws_secretsmanager_secret", Name: secret, Change: "create",
				AttributeValues: map[string]string{"name": "app-" + secret}},
			&plan.ResourceChange{Address: "aws_secretsmanager_secret_version." + secret, Type: "aws_secretsmanager_secret_version", Name: secret, Change: "create",
				References: map[string][]string{"secret_id": {"aws_secretsmanager_secret." + secret + ".id", "aws_secretsmanager_secret." + secret}}})
	}
	resolver := fakeResolver{
		"aws_secretsmanager_secret": &cloud.Schema{TypeName: "aws_secretsmanager_secret",
			Ops: map[string][]iam.Requirement{"create": iam.Unconditional("secretsmanager:CreateSecret")}},
		"aws_secretsmanager_secret_version": &cloud.Schema{TypeName: "aws_secretsmanager_secret_version",
			Ops: map[string][]iam.Requirement{"create": iam.Unconditional("secretsmanager:PutSecretValue")}},
	}
	load := func() ([]byte, error) {
		return []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:*","Resource":"arn:aws:secretsmanager:*:*:secret:app-*"}]}`), nil
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Run(FromPlan(changes), load, Options{Resolver: resolver}); err != nil {
			b.Fatal(err)
		}
	}
}
