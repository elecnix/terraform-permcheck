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
	// Service is the service prefix of the actions a resource policy can
	// grant, such as secretsmanager. It is empty for an identity or
	// boundary source.
	Service string
	// Text is the policy JSON. It is empty when Unknown is true.
	Text string
	// Unknown is true when the plan lacks the policy text, such as a value
	// that terraform computes at apply time, and when this version doesn't
	// read the source's type yet.
	Unknown bool
	// Unread is true when this version knows the source's type but doesn't
	// read its policy text yet. Unknown is true too.
	Unread bool
	// PolicyARN is the known ARN of the managed policy that the source
	// attaches, such as the policy_arn of an aws_iam_role_policy_attachment.
	// It is empty when the source holds its text itself, or when terraform
	// computes the ARN at apply time.
	PolicyARN string
	// OutsidePlan is true when PolicyARN names a managed policy that the
	// plan doesn't create, such as an AWS managed policy. The plan can't
	// show its text.
	OutsidePlan bool
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
	// Values are the known values of a link attribute that holds a list,
	// such as the roles of an aws_iam_policy_attachment. It is nil when the
	// attribute isn't a list, or when terraform computes it at apply time.
	Values []string
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
//
// A list, such as the roles of an aws_iam_policy_attachment, matches when
// one of its values matches. It doesn't match when no value may match.
func (l PolicyLink) matchValue(p *ResourceChange) LinkMatch {
	if l.Values != nil {
		out := LinkNo
		for _, v := range l.Values {
			switch matchOneValue(v, p) {
			case LinkYes:
				return LinkYes
			case LinkMaybe:
				out = LinkMaybe
			}
		}
		return out
	}
	return matchOneValue(l.Value, p)
}

// matchOneValue compares one known value of a link attribute with the
// principal's known name or arn. An empty value is unknown.
func matchOneValue(value string, p *ResourceChange) LinkMatch {
	if value == "" {
		return LinkMaybe
	}
	attr := "name"
	if strings.HasPrefix(value, "arn:") {
		attr = "arn"
	}
	known := p.AttributeValues[attr]
	switch {
	case known == "":
		return LinkMaybe
	case known == value:
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
	kind PolicyKind
	// unread marks a source type that this version knows but doesn't read
	// yet. Its sources are unknown, whatever text the plan holds. A later
	// version reads the type by dropping the marker and giving the spec a
	// texts function that reads the text.
	unread bool
	// service is the service prefix of the actions a resource policy can
	// grant, such as secretsmanager. It is empty for an identity or
	// boundary source.
	service string
	// arn is the attribute that holds the ARN of the managed policy the
	// source attaches, such as policy_arn. It is empty when the source
	// holds its policy text itself.
	arn   string
	texts func(rc *ResourceChange) []policyText
	link  func(rc *ResourceChange) PolicyLink
}

// sourceSpecs lists the policy sources of each resource type that the
// design of issue #175 names. PolicySources reads the policy text of the
// specs without the unread marker. A spec with the marker still gives a
// source, with unknown text, so that a grant the plan shows is never absent
// from the check.
//
// The membership resources aws_iam_user_group_membership and
// aws_iam_group_membership set no policy, so they have no spec. An
// aws_iam_policy holds the text of a managed policy, but it attaches to no
// principal by itself, so it has no spec either.
var sourceSpecs = map[string][]sourceSpec{
	// Identity policies of a role.
	"aws_iam_role_policy": {{kind: KindIdentity, texts: attributeText("policy"), link: attributeLink("role", "aws_iam_role")}},
	"aws_iam_role": {
		{kind: KindIdentity, texts: blockTexts("inline_policy", "policy"), link: selfLink},
		{kind: KindIdentity, unread: true, texts: unreadText("managed_policy_arns"), link: selfLink},
		{kind: KindBoundary, unread: true, arn: "permissions_boundary", texts: unreadText("permissions_boundary"), link: selfLink},
	},
	"aws_iam_role_policy_attachment":            {{kind: KindIdentity, unread: true, arn: "policy_arn", texts: unreadText("policy_arn"), link: attributeLink("role", "aws_iam_role")}},
	"aws_iam_role_policy_attachments_exclusive": {{kind: KindIdentity, unread: true, texts: unreadText("policy_arns"), link: attributeLink("role_name", "aws_iam_role")}},
	"aws_iam_policy_attachment": {
		{kind: KindIdentity, unread: true, arn: "policy_arn", texts: unreadTextWhen("policy_arn", "roles"), link: attributeLink("roles", "aws_iam_role")},
		{kind: KindIdentity, unread: true, arn: "policy_arn", texts: unreadTextWhen("policy_arn", "users"), link: attributeLink("users", "aws_iam_user")},
		{kind: KindIdentity, unread: true, arn: "policy_arn", texts: unreadTextWhen("policy_arn", "groups"), link: attributeLink("groups", "aws_iam_group")},
	},

	// Identity policies and the boundary of a user, and the policies of a
	// group.
	"aws_iam_user":                    {{kind: KindBoundary, unread: true, arn: "permissions_boundary", texts: unreadText("permissions_boundary"), link: selfLink}},
	"aws_iam_user_policy":             {{kind: KindIdentity, unread: true, texts: unreadText("policy"), link: attributeLink("user", "aws_iam_user")}},
	"aws_iam_user_policy_attachment":  {{kind: KindIdentity, unread: true, arn: "policy_arn", texts: unreadText("policy_arn"), link: attributeLink("user", "aws_iam_user")}},
	"aws_iam_group_policy":            {{kind: KindIdentity, unread: true, texts: unreadText("policy"), link: attributeLink("group", "aws_iam_group")}},
	"aws_iam_group_policy_attachment": {{kind: KindIdentity, unread: true, arn: "policy_arn", texts: unreadText("policy_arn"), link: attributeLink("group", "aws_iam_group")}},

	// Resource policies.
	"aws_secretsmanager_secret_policy": {{kind: KindResource, unread: true, service: "secretsmanager", texts: unreadText("policy"), link: attributeLink("secret_arn", "aws_secretsmanager_secret")}},
	"aws_secretsmanager_secret":        {{kind: KindResource, unread: true, service: "secretsmanager", texts: unreadText("policy"), link: selfLink}},
	"aws_s3_bucket_policy":             {{kind: KindResource, unread: true, service: "s3", texts: unreadText("policy"), link: attributeLink("bucket", "aws_s3_bucket")}},
	"aws_sqs_queue_policy":             {{kind: KindResource, unread: true, service: "sqs", texts: unreadText("policy"), link: attributeLink("queue_url", "aws_sqs_queue")}},
	"aws_sqs_queue":                    {{kind: KindResource, unread: true, service: "sqs", texts: unreadText("policy"), link: selfLink}},
	"aws_sns_topic_policy":             {{kind: KindResource, unread: true, service: "sns", texts: unreadText("policy"), link: attributeLink("arn", "aws_sns_topic")}},
	"aws_sns_topic":                    {{kind: KindResource, unread: true, service: "sns", texts: unreadText("policy"), link: selfLink}},
	"aws_ecr_repository_policy":        {{kind: KindResource, unread: true, service: "ecr", texts: unreadText("policy"), link: attributeLink("repository", "aws_ecr_repository")}},
	"aws_kms_key":                      {{kind: KindResource, unread: true, service: "kms", texts: unreadText("policy"), link: selfLink}},
	"aws_kms_key_policy":               {{kind: KindResource, unread: true, service: "kms", texts: unreadText("policy"), link: attributeLink("key_id", "aws_kms_key")}},
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
				s := PolicySource{
					Address: rc.Address,
					Path:    t.path,
					Kind:    spec.kind,
					Service: spec.service,
					Text:    t.text,
					Unknown: t.unknown || spec.unread,
					Unread:  spec.unread,
					Link:    link,
				}
				if spec.unread {
					s.Text = ""
				}
				if spec.arn != "" {
					s.PolicyARN = rc.AttributeValues[spec.arn]
					s.OutsidePlan = outsidePlan(rc, spec.arn, changes)
				}
				out = append(out, s)
			}
		}
	}
	return out
}

// awsManagedPolicyPrefix starts the ARN of every AWS managed policy. AWS
// owns these policies, so no plan creates one.
const awsManagedPolicyPrefix = "arn:aws:iam::aws:policy/"

// outsidePlan reports whether the attribute attr of rc holds the known ARN
// of a managed policy that no aws_iam_policy in the plan can be. That is
// true for an AWS managed policy. For any other ARN, it is true when the
// attribute references no aws_iam_policy, and every aws_iam_policy in the
// plan has a known ARN or name that differs from it. A policy whose ARN and
// name are both unknown, such as one with name_prefix, may be any ARN.
func outsidePlan(rc *ResourceChange, attr string, changes []*ResourceChange) bool {
	arn := rc.AttributeValues[attr]
	if arn == "" {
		return false
	}
	if strings.HasPrefix(arn, awsManagedPolicyPrefix) {
		return true
	}
	for _, ref := range rc.References[attr] {
		if typ, _, _, ok := parseResourceRef(ref); !ok || typ == "aws_iam_policy" {
			return false
		}
	}
	name := arn[strings.LastIndex(arn, "/")+1:]
	for _, p := range changes {
		if p.Type != "aws_iam_policy" || p.Change == "delete" {
			continue
		}
		if known := p.AttributeValues["arn"]; known != "" {
			if known == arn {
				return false
			}
			continue
		}
		if known := p.AttributeValues["name"]; known == "" || known == name {
			return false
		}
	}
	return true
}

// unreadText gives one source with unknown text at the attribute attr, when
// the resource may set that attribute.
func unreadText(attr string) func(rc *ResourceChange) []policyText {
	return unreadTextWhen(attr, attr)
}

// unreadTextWhen gives one source with unknown text at the attribute attr,
// when the resource may set the attribute when. An aws_iam_policy_attachment
// that names only users, say, gives no source for roles.
func unreadTextWhen(attr, when string) func(rc *ResourceChange) []policyText {
	return func(rc *ResourceChange) []policyText {
		if !maySet(rc, when) {
			return nil
		}
		return []policyText{{path: attr, unknown: true}}
	}
}

// maySet reports whether the resource may set the attribute attr. An
// attribute the configuration doesn't write holds no policy that this
// resource sets, even when the provider computes a value for it, such as the
// policy AWS gives a new SNS topic or the managed_policy_arns that other
// resources attach to a role. An attribute that the plan holds as null or
// empty sets nothing. Without a configuration section or a state, the
// attribute may be set.
func maySet(rc *ResourceChange, attr string) bool {
	if rc.Configured != nil && !rc.Configured[attr] {
		return false
	}
	if rc.Attributes == nil {
		return true
	}
	return rc.Attributes[attr]
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
			Values:     knownStrings(rc, attr),
		}
	}
}

// knownStrings returns the values of a top-level attribute that holds a
// list of strings. It returns nil when the attribute isn't such a list, or
// when terraform computes any part of it at apply time.
func knownStrings(rc *ResourceChange, attr string) []string {
	if rc.paths == nil || unknownAlong(rc.paths.unknown, attr) {
		return nil
	}
	v, _ := walk(rc.paths.state, attr)
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok || s == "" {
			return nil
		}
		out = append(out, s)
	}
	return out
}

// selfLink links a source to the resource that sets it.
func selfLink(rc *ResourceChange) PolicyLink {
	return PolicyLink{Type: rc.Type, Self: rc.Address, Module: rc.ModuleAddress}
}

// AddressType returns the resource type of a terraform instance address of a
// managed resource, such as aws_iam_role for
// module.app["eu"].aws_iam_role.task[0]. It reports false for an address of
// any other form, such as a data source or a module alone.
func AddressType(addr string) (string, bool) {
	rest := addr
	for strings.HasPrefix(rest, "module.") {
		rest = rest[len("module."):]
		end := strings.IndexAny(rest, ".[")
		if end <= 0 {
			return "", false
		}
		rest = rest[end:]
		if rest[0] == '[' {
			close := closingBracket(rest)
			if close < 0 {
				return "", false
			}
			rest = rest[close+1:]
		}
		if !strings.HasPrefix(rest, ".") {
			return "", false
		}
		rest = rest[1:]
	}
	typ, name, key, ok := parseResourceRef(rest)
	if !ok || typ == "data" || rest != typ+"."+name+key {
		return "", false
	}
	return typ, true
}
