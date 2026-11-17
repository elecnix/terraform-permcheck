package plan

import (
	"strings"
	"testing"
)

// kmsKeyChange is an existing aws_kms_key whose arn and key_id the plan
// knows. configured lists the attributes that its configuration writes.
func kmsKeyChange(policy string, configured ...string) string {
	expressions := make([]string, len(configured))
	for i, a := range configured {
		expressions[i] = `"` + a + `": {}`
	}
	return `{"address": "aws_kms_key.data", "type": "aws_kms_key", "name": "data",
		"change": {"actions": ["no-op"], "after": {"key_id": "1234abcd-12ab-34cd-56ef-1234567890ab",
			"arn": "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab", "policy": ` + policy + `}, "after_unknown": {}}}`
}

// kmsPlan returns a plan with the resource changes, whose configuration
// section lists the resources with the expressions given by address.
func kmsPlan(t *testing.T, changes []string, expressions map[string]string) []*ResourceChange {
	t.Helper()
	var resources []string
	for addr, expr := range expressions {
		typ, name, _ := strings.Cut(addr, ".")
		resources = append(resources, `{"address": "`+addr+`", "mode": "managed", "type": "`+typ+`", "name": "`+name+`", "expressions": {`+expr+`}}`)
	}
	return parseRaw(t, `{"resource_changes": [`+strings.Join(changes, ",")+`],
		"configuration": {"root_module": {"resources": [`+strings.Join(resources, ",")+`]}}}`)
}

const kmsKeyPolicyChange = `{"address": "aws_kms_key_policy.data", "type": "aws_kms_key_policy", "name": "data",
	"change": {"actions": ["create"], "after": {"key_id": "1234abcd-12ab-34cd-56ef-1234567890ab", "policy": "{}"}, "after_unknown": {}}}`

const kmsKeyPolicyRefs = `"policy": {}, "key_id": {"references": ["aws_kms_key.data.key_id", "aws_kms_key.data"]}`

// A key whose configuration leaves the policy out, and that no
// aws_kms_key_policy sets, gets the default key policy. Its current policy
// in the plan isn't a source.
func TestPolicySources_KMSDefaultKeyPolicy(t *testing.T) {
	changes := kmsPlan(t, []string{kmsKeyChange(`"{\"Statement\": []}"`)}, map[string]string{"aws_kms_key.data": `"description": {}`})
	sources := PolicySources(changes, nil)
	if len(sources) != 1 || !sources[0].DefaultKeyPolicy || sources[0].Unknown || sources[0].Text != "" || sources[0].PolicyMaybe {
		t.Fatalf("sources = %+v, want the default key policy", sources)
	}
	if got := sources[0].Resources; len(got) != 1 || got[0].Change != changes[0] || got[0].Match != LinkYes {
		t.Errorf("resources = %+v, want the key", got)
	}
}

// An aws_kms_key_policy that sets the key's policy replaces the default key
// policy.
func TestPolicySources_KMSKeyPolicyResource(t *testing.T) {
	changes := kmsPlan(t, []string{kmsKeyChange(`"{}"`), kmsKeyPolicyChange},
		map[string]string{"aws_kms_key.data": `"description": {}`, "aws_kms_key_policy.data": kmsKeyPolicyRefs})
	sources := PolicySources(changes, nil)
	if len(sources) != 1 || sources[0].Address != "aws_kms_key_policy.data" || sources[0].Text != "{}" || sources[0].PolicyMaybe {
		t.Fatalf("sources = %+v, want the aws_kms_key_policy alone", sources)
	}
	if got := sources[0].Resources; len(got) != 1 || got[0].Value != "1234abcd-12ab-34cd-56ef-1234567890ab" {
		t.Errorf("resources = %+v, want the key by its id", got)
	}
}

// When the key writes its policy attribute and an aws_kms_key_policy sets
// it too, the key's policy is one of the two, so each may not apply.
func TestPolicySources_KMSBothPolicies(t *testing.T) {
	changes := kmsPlan(t, []string{kmsKeyChange(`"{}"`), kmsKeyPolicyChange},
		map[string]string{"aws_kms_key.data": `"policy": {}`, "aws_kms_key_policy.data": kmsKeyPolicyRefs})
	sources := PolicySources(changes, nil)
	if len(sources) != 2 {
		t.Fatalf("sources = %+v, want two", sources)
	}
	for _, s := range sources {
		if !s.PolicyMaybe || s.DefaultKeyPolicy {
			t.Errorf("%s: PolicyMaybe = %v, DefaultKeyPolicy = %v; want a maybe with its own text", s.Address, s.PolicyMaybe, s.DefaultKeyPolicy)
		}
	}
}

// A key policy whose key_id terraform computes from a variable may set the
// policy of any key, so the default key policy may not apply.
func TestPolicySources_KMSKeyPolicyMayApply(t *testing.T) {
	policy := `{"address": "aws_kms_key_policy.data", "type": "aws_kms_key_policy", "name": "data",
		"change": {"actions": ["create"], "after": {"policy": "{}"}, "after_unknown": {"key_id": true}}}`
	changes := kmsPlan(t, []string{kmsKeyChange(`"{}"`), policy},
		map[string]string{"aws_kms_key.data": `"description": {}`, "aws_kms_key_policy.data": `"policy": {}, "key_id": {"references": ["var.key_id"]}`})
	sources := sourcesAt(PolicySources(changes, nil), "aws_kms_key.data")
	if len(sources) != 1 || !sources[0].DefaultKeyPolicy || !sources[0].PolicyMaybe {
		t.Errorf("sources = %+v, want the default key policy as a maybe", sources)
	}
}

// A grant gives a policy text: an Allow of its operations to its grantee.
// Operations and a grantee that terraform computes give every KMS action
// and no Principal.
func TestPolicySources_KMSGrant(t *testing.T) {
	grant := func(after, unknown string) string {
		return `{"address": "aws_kms_grant.g", "type": "aws_kms_grant", "name": "g",
			"change": {"actions": ["create"], "after": {"key_id": "1234abcd-12ab-34cd-56ef-1234567890ab"` + after + `}, "after_unknown": {` + unknown + `}}}`
	}
	for _, c := range []struct {
		name, after, unknown, want string
	}{
		{"known", `, "grantee_principal": "arn:aws:iam::123456789012:role/app-task", "operations": ["Decrypt", "Encrypt"]`, ``,
			`{"Statement":[{"Action":["kms:Decrypt","kms:Encrypt"],"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/app-task"},"Resource":"*"}],"Version":"2012-10-17"}`},
		{"computed", ``, `"grantee_principal": true, "operations": true`,
			`{"Statement":[{"Action":["kms:*"],"Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}`},
	} {
		sources := PolicySources(parseRaw(t, `{"resource_changes": [`+grant(c.after, c.unknown)+`]}`), nil)
		if len(sources) != 1 || !sources[0].Grant || sources[0].Service != "kms" {
			t.Fatalf("%s: sources = %+v, want one grant", c.name, sources)
		}
		if sources[0].Text != c.want {
			t.Errorf("%s: text = %s, want %s", c.name, sources[0].Text, c.want)
		}
	}
}

// An alias whose target_key_id names the key gives the key an alias. An
// alias whose target terraform computes from a variable may name it.
func TestPolicySources_KMSAliases(t *testing.T) {
	alias := func(name, target string) string {
		after := `"name": "` + name + `"`
		unknown := `{}`
		if target != "" {
			after += `, "target_key_id": "` + target + `"`
		} else {
			unknown = `{"target_key_id": true}`
		}
		return `{"address": "aws_kms_alias.` + strings.TrimPrefix(name, "alias/") + `", "type": "aws_kms_alias", "name": "` + strings.TrimPrefix(name, "alias/") + `",
			"change": {"actions": ["create"], "after": {` + after + `}, "after_unknown": ` + unknown + `}}`
	}
	changes := kmsPlan(t, []string{
		kmsKeyChange(`"{}"`),
		alias("alias/app-data", "1234abcd-12ab-34cd-56ef-1234567890ab"),
		alias("alias/app-any", ""),
		alias("alias/app-other", "arn:aws:kms:us-east-1:123456789012:key/0987dcba-09fe-87dc-65ba-ab0987654321"),
	}, map[string]string{
		"aws_kms_key.data":      `"description": {}`,
		"aws_kms_alias.app-any": `"target_key_id": {"references": ["var.key_id"]}`,
	})
	sources := sourcesAt(PolicySources(changes, nil), "aws_kms_key.data")
	if len(sources) != 1 || len(sources[0].Resources) != 1 {
		t.Fatalf("sources = %+v, want the key's default policy", sources)
	}
	a := sources[0].Resources[0]
	for arn, want := range map[string]LinkMatch{
		"arn:aws:kms:us-east-1:123456789012:alias/app-data":                           LinkYes,
		"arn:aws:kms:us-east-1:123456789012:alias/app-any":                            LinkMaybe,
		"arn:aws:kms:us-east-1:123456789012:alias/app-other":                          LinkNo,
		"arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab": LinkNo,
	} {
		if got := a.AliasMatch(arn); got != want {
			t.Errorf("AliasMatch(%s) = %v, want %v", arn, got, want)
		}
	}
}
