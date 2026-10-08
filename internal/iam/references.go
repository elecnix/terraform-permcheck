package iam

import (
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// Reference resolution.
//
// A target rule often finds its target through a reference: a secret version
// names its secret in secret_id, and a Lambda function names its role in
// role. The configuration section lists each reference as an address relative
// to the module the expression lives in, such as aws_iam_role.r.arn or
// aws_iam_role.r[1]. The target is the planned instance with that address in
// the same module instance.

// referencedChanges returns the planned resource changes of type resType that
// attribute attr of rc references.
//
// A reference with an instance key, such as aws_iam_role.r[1], selects that
// instance. Terraform also lists the bare address aws_iam_role.r beside it, so
// a bare address selects every instance only when no reference to the same
// resource carries a key. That is the case for r[count.index] and for a
// resource with no count or for_each.
func referencedChanges(rc *plan.ResourceChange, all []*plan.ResourceChange, attr, resType string) []*plan.ResourceChange {
	keys := map[string]map[string]bool{} // resource name → instance keys
	var names []string
	for _, ref := range rc.References[attr] {
		name, key, ok := parseResourceReference(ref, resType)
		if !ok {
			continue
		}
		if _, seen := keys[name]; !seen {
			keys[name] = map[string]bool{}
			names = append(names, name)
		}
		if key != "" {
			keys[name][key] = true
		}
	}
	var out []*plan.ResourceChange
	for _, name := range names {
		for _, c := range all {
			if c.Type != resType || c.ModuleAddress != rc.ModuleAddress {
				continue
			}
			cName, cKey := instanceOf(c)
			if cName != name {
				continue
			}
			if len(keys[name]) > 0 && !keys[name][cKey] {
				continue
			}
			out = append(out, c)
		}
	}
	return out
}

// parseResourceReference splits a reference to a managed resource of type
// resType into the resource name and its instance key, such as "[0]" or
// `["a"]`. The key is empty when the reference has none. It reports false
// for a reference to anything else.
func parseResourceReference(ref, resType string) (name, key string, ok bool) {
	rest, found := strings.CutPrefix(ref, resType+".")
	if !found {
		return "", "", false
	}
	end := strings.IndexAny(rest, ".[")
	if end < 0 {
		return rest, "", rest != ""
	}
	name = rest[:end]
	if rest[end] == '[' {
		if j := strings.IndexByte(rest[end:], ']'); j > 0 {
			key = rest[end : end+j+1]
		}
	}
	return name, key, name != ""
}

// instanceOf returns the resource name and instance key of a change, read
// from its address. A change without an address, as tests build them, may
// carry the key in its name.
func instanceOf(c *plan.ResourceChange) (name, key string) {
	if c.Address == "" {
		name = stripResourceIndex(c.Name)
		return name, c.Name[len(name):]
	}
	local := c.Address
	if c.ModuleAddress != "" {
		local = strings.TrimPrefix(local, c.ModuleAddress+".")
	}
	return c.Name, strings.TrimPrefix(local, c.Type+"."+c.Name)
}

// worstVerdict checks action against each target and returns the worst
// verdict. Each target is the list of ARN forms of one resource the change
// acts on, and every one of them must be covered. With no targets, the
// action alone decides.
func (d *PolicyDocument) worstVerdict(action string, targets [][]string, strict bool) Verdict {
	if len(targets) == 0 {
		return d.Coverage(action, nil, strict)
	}
	worst := Covered
	for _, forms := range targets {
		switch d.Coverage(action, forms, strict) {
		case Missing:
			return Missing
		case Unverified:
			worst = Unverified
		}
	}
	return worst
}
