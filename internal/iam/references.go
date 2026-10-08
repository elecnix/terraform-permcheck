package iam

import (
	"regexp"
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
func referencedChanges(rc *plan.ResourceChange, set *changeSet, attr, resType string) []*plan.ResourceChange {
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
		for _, c := range set.named(rc.ModuleAddress, resType, name) {
			if _, cKey := instanceOf(c); len(keys[name]) > 0 && !keys[name][cKey] {
				continue
			}
			out = append(out, c)
		}
	}
	return out
}

// attributeTargets returns the resources that attribute attr of rc names,
// one list of ARN patterns per resource. A literal ARN in attr is the one
// target. Otherwise each planned resource of type resType that attr
// references is a target, with the patterns arnPatterns builds from it. A
// referenced resource whose patterns are unknown is left out, so the caller
// checks only what the plan shows.
func attributeTargets(rc *plan.ResourceChange, set *changeSet, attr, resType string, arnPatterns func(*plan.ResourceChange) []string) [][]string {
	if v := rc.AttributeValues[attr]; isARN(v) {
		return [][]string{{v}}
	}
	var targets [][]string
	for _, c := range referencedChanges(rc, set, attr, resType) {
		if forms := arnPatterns(c); forms != nil {
			targets = append(targets, forms)
		}
	}
	return targets
}

// changeSet indexes the plan's changes by module, type and resource name, so
// a reference resolves without a scan over every change. A plan with
// thousands of references would otherwise take time quadratic in its size.
type changeSet struct {
	byName map[changeKey][]*plan.ResourceChange
}

type changeKey struct {
	module, typ, name string
}

// newChangeSet indexes changes, keeping plan order within each resource.
func newChangeSet(changes []*plan.ResourceChange) *changeSet {
	s := &changeSet{byName: make(map[changeKey][]*plan.ResourceChange, len(changes))}
	for _, c := range changes {
		name, _ := instanceOf(c)
		k := changeKey{c.ModuleAddress, c.Type, name}
		s.byName[k] = append(s.byName[k], c)
	}
	return s
}

// named returns the changes of the resource with the given module, type
// and name, every instance included. A nil set has none.
func (s *changeSet) named(module, typ, name string) []*plan.ResourceChange {
	if s == nil {
		return nil
	}
	return s.byName[changeKey{module, typ, name}]
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

// instanceOf returns the resource name and instance key of a change. A
// change without an address, as tests build them, may carry the key in its
// name.
func instanceOf(c *plan.ResourceChange) (name, key string) {
	instance := c.InstanceName()
	name = stripResourceIndex(instance)
	return name, instance[len(name):]
}

// stripResourceIndex removes a count or for_each index suffix from a
// terraform resource name.
//
//	cloudtrail[0]       → cloudtrail
//	config["us-east-1"]  → config
func stripResourceIndex(name string) string {
	return resourceIndexRE.ReplaceAllString(name, "")
}

// resourceIndexRE matches a trailing bracket-index suffix like [0] or ["key"].
var resourceIndexRE = regexp.MustCompile(`\[[^\]]*\]$`)
