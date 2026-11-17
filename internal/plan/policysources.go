package plan

import (
	"strconv"
	"strings"
)

// PolicyKind says how AWS evaluates a policy source.
type PolicyKind string

const (
	// KindIdentity is an inline or managed policy of a principal.
	KindIdentity PolicyKind = "identity"
	// KindBoundary is the permissions boundary of a principal.
	KindBoundary PolicyKind = "boundary"
	// KindResource is a policy attached to a resource, such as a secret.
	KindResource PolicyKind = "resource"
)

// PolicySource is one policy document that the plan attaches to a principal
// or to a resource.
type PolicySource struct {
	// Address is the terraform address of the resource that sets the
	// policy, such as aws_iam_role_policy.task_logs.
	Address string
	// Path is the attribute path of the policy text in that resource, such
	// as policy or inline_policy.0.policy.
	Path string
	// Kind says how AWS evaluates the policy.
	Kind PolicyKind
	// Text is the policy JSON. It is empty when Unknown is true.
	Text string
	// Unknown is true when the plan lacks the policy text, such as a value
	// that terraform computes at apply time.
	Unknown bool
	// Link ties the source to the principal or resource it attaches to.
	Link PolicyLink
}

// PolicyLink ties a policy source to the principal or resource it attaches
// to. It keeps the data that decides the link, and Match decides it.
type PolicyLink struct {
	// Type is the resource type the link points to, such as aws_iam_role.
	Type string
	// Self is the address of the source resource when the policy belongs to
	// that resource itself, such as the inline_policy of an aws_iam_role.
	// It is empty when the link goes through an attribute.
	Self string
	// Module is the module address of the source resource. References are
	// relative to it.
	Module string
	// Attribute is the link attribute, such as role. It is empty when Self
	// is set.
	Attribute string
	// References are the references of the link attribute, from the plan's
	// configuration section.
	References []string
	// Value is the known value of the link attribute. It is empty when
	// terraform computes the value at apply time.
	Value string
}

// LinkMatch is the answer to whether a policy source attaches to a
// principal.
type LinkMatch int

const (
	// LinkNo means the source provably doesn't attach to the principal.
	LinkNo LinkMatch = iota
	// LinkYes means the source attaches to the principal.
	LinkYes
	// LinkMaybe means the plan can't decide the link, so the source may
	// attach to the principal.
	LinkMaybe
)

// String returns no, yes or maybe.
func (m LinkMatch) String() string {
	switch m {
	case LinkYes:
		return "yes"
	case LinkMaybe:
		return "maybe"
	default:
		return "no"
	}
}

// Match reports whether the link points to the principal p. It tries the
// references of the link attribute first, then its known value against the
// principal's known name or arn. When neither decides, the answer is
// LinkMaybe.
//
// A reference without an instance key, such as aws_iam_role.task for a role
// with count or for_each, names every instance. For an instance it matches
// only when the known values agree, and it is undecidable when a value is
// unknown.
func (l PolicyLink) Match(p *ResourceChange) LinkMatch {
	if p == nil || p.Type != l.Type {
		return LinkNo
	}
	if l.Self != "" {
		if p.Address == l.Self {
			return LinkYes
		}
		return LinkNo
	}
	if m, decided := l.matchReferences(p); decided {
		return m
	}
	return l.matchValue(p)
}

// matchReferences decides the link from the references of the link
// attribute. It reports false when the references don't decide it: the
// attribute references no resource of the principal's type, or it also
// references a value that could name any principal, such as a variable.
func (l PolicyLink) matchReferences(p *ResourceChange) (LinkMatch, bool) {
	pKey := strings.TrimPrefix(p.InstanceName(), p.Name)
	var named, keyed, keyMatch, other, opaque bool
	for _, ref := range l.References {
		typ, name, key, ok := parseResourceRef(ref)
		switch {
		case !ok:
			// count.index and each.key select an instance. Any other
			// reference that isn't a resource may carry any value.
			if !strings.HasPrefix(ref, "count.index") && !strings.HasPrefix(ref, "each.key") {
				opaque = true
			}
		case typ != p.Type:
			// Another resource's attribute may hold any principal's name.
			opaque = true
		case name == p.Name && l.Module == p.ModuleAddress:
			named = true
			if key != "" {
				keyed = true
				keyMatch = keyMatch || key == pKey
			}
		default:
			other = true
		}
	}
	switch {
	case opaque || (named && other) || (!named && !other):
		// The attribute may name the principal or another one, or it
		// references no resource of the principal's type.
		return LinkNo, false
	case !named:
		// The attribute references other resources of the principal's
		// type only.
		return LinkNo, true
	case keyed:
		// Terraform lists aws_iam_role.r[0] and aws_iam_role.r for one
		// reference to an instance, so a keyed reference decides alone.
		if keyMatch {
			return LinkYes, true
		}
		return LinkNo, true
	case pKey == "":
		return LinkYes, true
	default:
		// The reference names every instance of the principal. Only the
		// known values can tell which one.
		return l.matchValue(p), true
	}
}

// matchValue decides the link from the known value of the link attribute.
// An ARN compares with the principal's arn, and any other value with its
// name.
func (l PolicyLink) matchValue(p *ResourceChange) LinkMatch {
	if l.Value == "" {
		return LinkMaybe
	}
	attr := "name"
	if strings.HasPrefix(l.Value, "arn:") {
		attr = "arn"
	}
	known := p.AttributeValues[attr]
	switch {
	case known == "":
		return LinkMaybe
	case known == l.Value:
		return LinkYes
	default:
		return LinkNo
	}
}

// parseResourceRef splits a reference to a managed resource, such as
// aws_iam_role.task["a"].id, into its type, name and instance key. The key
// keeps its brackets and terraform's quoting. It reports false for any other
// reference, such as var.name, data.x.y or module.m.out.
func parseResourceRef(ref string) (typ, name, key string, ok bool) {
	typ, rest, found := strings.Cut(ref, ".")
	if !found || !strings.Contains(typ, "_") {
		return "", "", "", false
	}
	end := strings.IndexAny(rest, ".[")
	if end < 0 {
		return typ, rest, "", rest != ""
	}
	name = rest[:end]
	if name == "" {
		return "", "", "", false
	}
	if rest[end] == '[' {
		close := closingBracket(rest[end:])
		if close < 0 {
			return "", "", "", false
		}
		key = rest[end : end+close+1]
	}
	return typ, name, key, true
}

// closingBracket returns the index of the bracket that closes the one at
// s[0], skipping brackets inside a quoted key. It returns -1 when none does.
func closingBracket(s string) int {
	quoted := false
	for i := 1; i < len(s); i++ {
		switch {
		case quoted && s[i] == '\\':
			i++
		case s[i] == '"':
			quoted = !quoted
		case !quoted && s[i] == ']':
			return i
		}
	}
	return -1
}

// policyText is one policy text a resource sets, at an attribute path.
type policyText struct {
	path    string
	text    string
	unknown bool
}

// sourceSpec says how one resource type sets a policy source: its kind,
// where the policy text is, and how the source links to its principal or
// resource.
type sourceSpec struct {
	kind  PolicyKind
	texts func(rc *ResourceChange) []policyText
	link  func(rc *ResourceChange) PolicyLink
}

// sourceSpecs lists the policy sources of each resource type that
// PolicySources reads.
var sourceSpecs = map[string][]sourceSpec{
	"aws_iam_role_policy": {{KindIdentity, attributeText("policy"), attributeLink("role", "aws_iam_role")}},
	"aws_iam_role":        {{KindIdentity, blockTexts("inline_policy", "policy"), selfLink}},
}

// PolicySources returns the policy sources that the changes set, in plan
// order. A create or update reads the planned value, and a no-op reads the
// current value. A delete adds no source, since the policy goes away, so a
// replace adds one source, from its create.
func PolicySources(changes []*ResourceChange) []PolicySource {
	var out []PolicySource
	for _, rc := range changes {
		if rc.Change == "delete" {
			continue
		}
		for _, spec := range sourceSpecs[rc.Type] {
			link := spec.link(rc)
			for _, t := range spec.texts(rc) {
				out = append(out, PolicySource{
					Address: rc.Address,
					Path:    t.path,
					Kind:    spec.kind,
					Text:    t.text,
					Unknown: t.unknown,
					Link:    link,
				})
			}
		}
	}
	return out
}

// attributeText reads the policy text from a top-level attribute. A value
// that terraform computes at apply time, or that the plan leaves null, is
// unknown.
func attributeText(attr string) func(rc *ResourceChange) []policyText {
	return func(rc *ResourceChange) []policyText {
		return []policyText{readText(rc, attr)}
	}
}

// blockTexts reads one policy text from the attribute attr of each nested
// block, such as inline_policy.N.policy. A block list that terraform
// computes at apply time is one unknown source. The blocks are a source only
// when the configuration writes them, since a computed block that the
// configuration omits holds policies that other resources set.
func blockTexts(block, attr string) func(rc *ResourceChange) []policyText {
	return func(rc *ResourceChange) []policyText {
		if rc.Configured != nil && !rc.Configured[block] {
			return nil
		}
		if rc.paths == nil {
			return []policyText{{path: block, unknown: true}}
		}
		if unknownAlong(rc.paths.unknown, block) {
			return []policyText{{path: block, unknown: true}}
		}
		list, _ := walk(rc.paths.state, block)
		blocks, _ := list.([]any)
		var out []policyText
		for i := range blocks {
			path := block + "." + strconv.Itoa(i) + "." + attr
			t := readText(rc, path)
			if !t.unknown || unknownAlong(rc.paths.unknown, path) {
				out = append(out, t)
			}
		}
		return out
	}
}

// readText reads the policy text at a path. A value that terraform computes
// at apply time, or that the plan doesn't hold as a string, is unknown.
func readText(rc *ResourceChange, path string) policyText {
	if rc.paths == nil || unknownAlong(rc.paths.unknown, path) {
		return policyText{path: path, unknown: true}
	}
	v, _ := walk(rc.paths.state, path)
	if s, ok := v.(string); ok && s != "" {
		return policyText{path: path, text: s}
	}
	return policyText{path: path, unknown: true}
}

// attributeLink links a source to a principal or resource of type target
// through the attribute attr.
func attributeLink(attr, target string) func(rc *ResourceChange) PolicyLink {
	return func(rc *ResourceChange) PolicyLink {
		return PolicyLink{
			Type:       target,
			Module:     rc.ModuleAddress,
			Attribute:  attr,
			References: rc.References[attr],
			Value:      rc.AttributeValues[attr],
		}
	}
}

// selfLink links a source to the resource that sets it.
func selfLink(rc *ResourceChange) PolicyLink {
	return PolicyLink{Type: rc.Type, Self: rc.Address, Module: rc.ModuleAddress}
}
