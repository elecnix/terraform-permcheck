package plan

import (
	"fmt"
	"strings"
	"testing"
)

// secretsPlan builds a plan of n secrets in each of two modules, each with a
// version that references its secret, plus the configuration section that
// carries those references.
func secretsPlan(n int) []byte {
	var changes, resources []string
	for i := 0; i < n; i++ {
		for _, mod := range []string{"a", "b"} {
			changes = append(changes,
				fmt.Sprintf(`{"address":"module.%[1]s.aws_secretsmanager_secret.s%[2]d","module_address":"module.%[1]s","mode":"managed","type":"aws_secretsmanager_secret","name":"s%[2]d","change":{"actions":["create"],"before":null,"after":{"name":"%[1]s-%[2]d","tags":null},"after_unknown":{"arn":true,"id":true,"tags_all":true}}}`, mod, i),
				fmt.Sprintf(`{"address":"module.%[1]s.aws_secretsmanager_secret_version.v%[2]d","module_address":"module.%[1]s","mode":"managed","type":"aws_secretsmanager_secret_version","name":"v%[2]d","change":{"actions":["create"],"before":null,"after":{"secret_string":"x","secret_id":null},"after_unknown":{"secret_id":true,"version_id":true,"version_stages":[true]}}}`, mod, i))
		}
	}
	for i := 0; i < n; i++ {
		resources = append(resources,
			fmt.Sprintf(`{"address":"aws_secretsmanager_secret.s%[1]d","mode":"managed","type":"aws_secretsmanager_secret","name":"s%[1]d","expressions":{"name":{"constant_value":"x"}}}`, i),
			fmt.Sprintf(`{"address":"aws_secretsmanager_secret_version.v%[1]d","mode":"managed","type":"aws_secretsmanager_secret_version","name":"v%[1]d","expressions":{"secret_id":{"references":["aws_secretsmanager_secret.s%[1]d.id","aws_secretsmanager_secret.s%[1]d"]},"secret_string":{"constant_value":"x"}}}`, i))
	}
	mod := `{"module":{"resources":[` + strings.Join(resources, ",") + `]}}`
	return []byte(`{"resource_changes":[` + strings.Join(changes, ",") + `],"configuration":{"root_module":{"module_calls":{"a":` + mod + `,"b":` + mod + `}}}}`)
}

// BenchmarkParse measures Parse on a plan of 4000 secrets and 4000 versions
// across two modules.
func BenchmarkParse(b *testing.B) {
	raw := secretsPlan(2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(raw, "aws_"); err != nil {
			b.Fatal(err)
		}
	}
}
