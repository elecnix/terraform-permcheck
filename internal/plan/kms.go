package plan

import (
	"encoding/json"
	"strings"
)

// KMS key policies, grants and aliases.
//
// Every KMS key has exactly one key policy
// (https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html).
// The plan sets it in the policy attribute of the aws_kms_key, or with an
// aws_kms_key_policy whose key_id names the key. When neither sets it, AWS
// gives the key its default key policy.

// The resource types of KMS keys, their policies and their aliases.
const (
	kmsKeyType       = "aws_kms_key"
	kmsKeyPolicyType = "aws_kms_key_policy"
	kmsAliasType     = "aws_kms_alias"
)

// kmsKeyLink links an aws_kms_key_policy or an aws_kms_grant to its key
// through key_id, which holds a key id or a key ARN.
var kmsKeyLink = attributeLink("key_id", kmsKeyType)

// keyPolicyOfKey reads the policy of an aws_kms_key.
//
// A key whose configuration writes its policy attribute gives that text.
// When an aws_kms_key_policy of the plan may also set the policy, each apply
// sets one of the two, so the source gets PolicyMaybe, and so does the
// aws_kms_key_policy (see keyPolicyText).
//
// A key whose configuration leaves the policy out, and whose policy no
// aws_kms_key_policy provably sets, gets AWS's default key policy: "If you
// do not provide a key policy, AWS KMS attaches a default key policy to the
// KMS key"
// (https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html#KMS-CreateKey-request-Policy).
// The plan doesn't show its text, and it doesn't need to: the default key
// policy "gives the AWS account that owns the KMS key permission to use IAM
// policies to allow access to all AWS KMS operations on the KMS key"
// (https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html).
// The source has DefaultKeyPolicy set, and PolicyMaybe when an
// aws_kms_key_policy may set the policy instead.
//
// The check assumes that the plan lists every policy of a key, as it does
// for other resources, so a key that no source of the plan gives a policy
// has the default one, even when its current policy is another.
func keyPolicyOfKey(rc *ResourceChange, ctx sourceContext) []policyText {
	set := keyPolicySetBy(rc, ctx)
	if maySet(rc, "policy") {
		t := readText(rc, "policy")
		t.maybe = set != LinkNo
		return []policyText{t}
	}
	if set == LinkYes {
		return nil
	}
	return []policyText{{path: "policy", defaultKey: true, maybe: set == LinkMaybe}}
}

// keyPolicySetBy reports whether an aws_kms_key_policy of the plan sets the
// policy of the key: LinkYes when one provably does, LinkMaybe when one may,
// and LinkNo when none does.
func keyPolicySetBy(key *ResourceChange, ctx sourceContext) LinkMatch {
	out := LinkNo
	for _, c := range ctx.changes {
		if c.Type != kmsKeyPolicyType || c.Change == "delete" {
			continue
		}
		switch keyLinkMatch(kmsKeyLink(c), key) {
		case LinkYes:
			return LinkYes
		case LinkMaybe:
			out = LinkMaybe
		}
	}
	return out
}

// keyPolicyText reads the policy of an aws_kms_key_policy. The source gets
// PolicyMaybe when a key it may attach to writes its own policy attribute
// too (see keyPolicyOfKey).
func keyPolicyText(rc *ResourceChange, ctx sourceContext) []policyText {
	t := readText(rc, "policy")
	link := kmsKeyLink(rc)
	for _, c := range ctx.changes {
		if c.Type == kmsKeyType && c.Change != "delete" && maySet(c, "policy") && keyLinkMatch(link, c) != LinkNo {
			t.maybe = true
		}
	}
	return []policyText{t}
}

// keyLinkMatch reports whether a link through key_id or target_key_id
// points to the key in the plan. The references of the attribute decide
// first. Then its known value, a key id or a key ARN, must equal the key's
// known key_id or arn.
func keyLinkMatch(l PolicyLink, key *ResourceChange) LinkMatch {
	if key.Type != kmsKeyType {
		return LinkNo
	}
	if m, decided := l.matchReferences(key); decided {
		return m
	}
	known := key.AttributeValues["key_id"]
	if known == "" {
		known = key.AttributeValues["arn"]
	}
	return sameKey(l.Value, known)
}

// sameKey compares two names of a key, each a key id or a key ARN. It is
// LinkMaybe when either is unknown.
func sameKey(a, b string) LinkMatch {
	switch {
	case a == "" || b == "":
		return LinkMaybe
	case keyID(a) == keyID(b):
		return LinkYes
	}
	return LinkNo
}

// keyID returns the key id that a key ARN ends with, or the value itself
// when it isn't an ARN.
func keyID(v string) string {
	if strings.HasPrefix(v, "arn:") {
		if i := strings.LastIndex(v, ":key/"); i >= 0 {
			return v[i+len(":key/"):]
		}
	}
	return v
}

// keyAliases returns the names of the aws_kms_alias resources of the plan
// that may point to the attached key, through their target_key_id. An
// alias whose name terraform computes at apply time is left out: a need
// can't name it. It returns nil when no alias may point to the key.
func keyAliases(a AttachedResource, ctx sourceContext) map[string]LinkMatch {
	var out map[string]LinkMatch
	for _, c := range ctx.changes {
		name := c.AttributeValues["name"]
		if c.Type != kmsAliasType || c.Change == "delete" || name == "" {
			continue
		}
		link := attributeLink("target_key_id", kmsKeyType)(c)
		var m LinkMatch
		switch {
		case a.Change != nil:
			m = keyLinkMatch(link, a.Change)
		case a.ARN != "":
			m = sameKey(link.Value, a.ARN)
		default:
			m = sameKey(link.Value, a.Value)
		}
		if m == LinkNo {
			continue
		}
		if out == nil {
			out = map[string]LinkMatch{}
		}
		if out[name] != LinkYes {
			out[name] = m
		}
	}
	return out
}

// grantText builds the policy text of an aws_kms_grant: one Allow of the
// grant's operations to its grantee principal. A grant "allows the grantee
// principal to call the specified grant operations on the KMS key provided
// that all conditions specified in the grant are met"
// (https://docs.aws.amazon.com/kms/latest/developerguide/grants.html). A
// grantee that terraform computes at apply time leaves the Principal out,
// so the statement may apply to any principal. Operations that terraform
// computes at apply time allow every KMS action. The check counts the
// grant's Allow as a grant it can't check (see package principal).
func grantText(rc *ResourceChange, _ sourceContext) []policyText {
	actions := []string{"kms:*"}
	if ops := knownStrings(rc, "operations"); ops != nil {
		actions = make([]string, len(ops))
		for i, op := range ops {
			actions[i] = "kms:" + op
		}
	}
	statement := map[string]any{"Effect": "Allow", "Action": actions, "Resource": "*"}
	if grantee := rc.AttributeValues["grantee_principal"]; grantee != "" {
		statement["Principal"] = map[string]any{"AWS": grantee}
	}
	text, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{statement}})
	if err != nil {
		return []policyText{{path: "operations", unknown: true}}
	}
	return []policyText{{path: "operations", text: string(text)}}
}
