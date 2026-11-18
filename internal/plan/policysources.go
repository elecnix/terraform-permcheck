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
	// Policy is the address of the aws_iam_policy resource, or of the
	// data "aws_iam_policy" source, that holds the text of the managed
	// policy the source attaches. It is empty when the source holds its
	// text itself, and when the attached ARN names no policy of the plan.
	Policy string
	// PolicyMaybe is true when the source may not apply. For a source that
	// attaches a managed policy, the plan can't decide whether the attached
	// ARN names Policy or, for a source with OutsidePlan, a managed policy
	// outside the plan. For a KMS key policy, another source of the plan may
	// set the key's policy instead (see keyPolicyOfKey).
	PolicyMaybe bool
	// OutsidePlan is true when the attached ARN names a managed policy that
	// the plan doesn't create and no data source of the plan reads, such as
	// an AWS managed policy. The plan can't show its text.
	OutsidePlan bool
	// PolicyName is the known name of an inline policy: the name of an
	// aws_iam_role_policy, an aws_iam_user_policy or an
	// aws_iam_group_policy, or of an inline_policy block of an aws_iam_role.
	// It is empty for any other source, and when terraform computes the
	// name at apply time.
	PolicyName string
	// Managed is true when the source attaches a managed policy, such as an
	// aws_iam_role_policy_attachment, and false when it holds an inline
	// policy or a resource policy.
	Managed bool
	// Link ties the source to the principal or resource it attaches to.
	Link PolicyLink
	// Resources are the resources that a resource policy source may attach
	// to, from its link (see attachedResources). They are set for a source
	// type that this version reads, and nil for an identity or boundary
	// source and for an unread type.
	Resources []AttachedResource
	// ResourceUnknown is true when the plan can't tell which resource a
	// resource policy source attaches to, such as a link attribute that a
	// variable sets. The source may then attach to any resource of its
	// type, in the plan or outside it.
	ResourceUnknown bool
	// Grant is true for an aws_kms_grant. Its text is a policy that the
	// check builds from the grant: an Allow of the grant's operations to its
	// grantee principal (see grantText).
	Grant bool
	// DefaultKeyPolicy is true for the default key policy that AWS gives a
	// KMS key created without a policy (see keyPolicyOfKey). The source has
	// no text: AWS documents the policy, which allows every action to the
	// key's account and so lets its identity policies grant access.
	DefaultKeyPolicy bool
}

// AttachedResource is a resource that a resource policy source may attach
// to.
type AttachedResource struct {
	// Change is the resource in the plan. It is nil when the link
	// attribute holds a known ARN, which decides the resource without it.
	Change *ResourceChange
	// ARN is the known ARN that the link attribute holds, such as the
	// secret_arn of an aws_secretsmanager_secret_policy. It is empty when
	// terraform computes the value at apply time.
	ARN string
	// Value is the known value of the link attribute when it isn't an ARN
	// but still names the resource, such as the bucket name of an
	// aws_s3_bucket_policy or the queue URL of an aws_sqs_queue_policy. Like
	// ARN, it decides the resource without Change. It is empty when ARN or
	// Change is set.
	Value string
	// Match is LinkYes when the source attaches to the resource, and
	// LinkMaybe when the plan can't decide which of several resources it
	// attaches to.
	Match LinkMatch
	// Aliases are the names of the aws_kms_alias resources of the plan that
	// may point to a KMS key, such as alias/app-data, with LinkYes when the
	// alias provably points to the key and LinkMaybe when it may. It is nil
	// for a resource of any other type (see keyAliases).
	Aliases map[string]LinkMatch
}

// AliasMatch reports whether an ARN names the attached KMS key by one of
// its aliases, such as arn:aws:kms:us-east-1:123456789012:alias/app-data. It
// is LinkNo for an ARN without an alias, and for an alias that the plan
// doesn't point to the key.
func (a AttachedResource) AliasMatch(arn string) LinkMatch {
	i := strings.Index(arn, ":alias/")
	if i < 0 {
		return LinkNo
	}
	return a.Aliases[arn[i+1:]]
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
// principal's known name or arn. A list whose values are all known tries
// its values first. When neither decides, the answer is LinkMaybe.
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
	if l.Values != nil {
		// A list whose values are all known, such as the groups of an
		// aws_iam_user_group_membership, may mix references with constants,
		// so its references don't list every principal it names. Its known
		// values decide when the principal's name or arn is known.
		if m := l.matchValue(p); m != LinkMaybe {
			return m
		}
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

// policyText is one policy text a resource sets, at an attribute path. For a
// source that attaches a managed policy, it also says which policy.
type policyText struct {
	path    string
	text    string
	unknown bool
	// policyARN, policy, maybe and outside fill the PolicySource fields of
	// the same names (PolicyARN, Policy, PolicyMaybe, OutsidePlan).
	policyARN string
	policy    string
	maybe     bool
	outside   bool
	// defaultKey fills PolicySource.DefaultKeyPolicy.
	defaultKey bool
}

// sourceContext is what a source reads besides its own resource: every
// change and every data source of the plan.
type sourceContext struct {
	changes []*ResourceChange
	data    []DataSource
}

// sourceSpec says how one resource type sets a policy source: its kind,
// where the policy text is, and how the source links to its principal or
// resource.
type sourceSpec struct {
	kind PolicyKind
	// unread marks a source type that this version knows but doesn't read
	// yet. Its sources are unknown, whatever text the plan holds. A later
	// version reads the type by dropping the marker and giving the spec a
	// texts function that reads the text. Since the IAM users and groups
	// stage of issue #175, every type of the design is read, and no spec has
	// the marker.
	unread bool
	// service is the service prefix of the actions a resource policy can
	// grant, such as secretsmanager. It is empty for an identity or
	// boundary source.
	service string
	// managed marks a source that attaches a managed policy.
	managed bool
	// grant marks an aws_kms_grant (see PolicySource.Grant).
	grant bool
	// arn is the attribute of an unread source that holds the ARN of the
	// managed policy it attaches, such as policy_arn. It sets PolicyARN and
	// OutsidePlan. A read source sets them through its texts function.
	arn   string
	texts func(rc *ResourceChange, ctx sourceContext) []policyText
	link  func(rc *ResourceChange) PolicyLink
}

// sourceSpecs lists the policy sources of each resource type that the
// design of issue #175 names. PolicySources reads the policy text of the
// specs without the unread marker. A spec with the marker still gives a
// source, with unknown text, so that a grant the plan shows is never absent
// from the check.
//
// The membership resources aws_iam_user_group_membership and
// aws_iam_group_membership set no policy, so they have no spec: Groups reads
// them. An
// aws_iam_policy holds the text of a managed policy, but it attaches to no
// principal by itself, so it has no spec either. A source that attaches it
// reads its text (see resolvePolicyARN).
var sourceSpecs = map[string][]sourceSpec{
	// Identity policies of a role.
	"aws_iam_role_policy": {{kind: KindIdentity, texts: attributeText("policy"), link: attributeLink("role", "aws_iam_role")}},
	"aws_iam_role": {
		{kind: KindIdentity, texts: blockTexts("inline_policy", "policy"), link: selfLink},
		{kind: KindIdentity, managed: true, texts: managedPolicyList("managed_policy_arns"), link: selfLink},
		// The permissions boundary is a managed policy ARN. It resolves to
		// its text as an attached managed policy does (see
		// resolvePolicyARN).
		{kind: KindBoundary, texts: managedPolicy("permissions_boundary", "permissions_boundary"), link: selfLink},
	},
	"aws_iam_role_policy_attachment": {{kind: KindIdentity, managed: true, texts: managedPolicy("policy_arn", "policy_arn"), link: attributeLink("role", "aws_iam_role")}},
	// An aws_iam_role_policy_attachments_exclusive attaches each ARN of its
	// list. Its other effect, removing what the list omits, is an Exclusive
	// (see Exclusives). An aws_iam_role_policies_exclusive holds no policy
	// text, so it has no spec: the inline policies it lists come from
	// aws_iam_role_policy resources, or from outside the plan.
	"aws_iam_role_policy_attachments_exclusive": {{kind: KindIdentity, managed: true, texts: managedPolicyList("policy_arns"), link: attributeLink("role_name", "aws_iam_role")}},
	"aws_iam_policy_attachment": {
		{kind: KindIdentity, managed: true, texts: managedPolicy("policy_arn", "roles"), link: attributeLink("roles", roleType)},
		{kind: KindIdentity, managed: true, texts: managedPolicy("policy_arn", "users"), link: attributeLink("users", userType)},
		{kind: KindIdentity, managed: true, texts: managedPolicy("policy_arn", "groups"), link: attributeLink("groups", groupType)},
	},

	// Identity policies and the boundary of a user. A user also gets the
	// policies of each group it belongs to (see Groups).
	"aws_iam_user":                              {{kind: KindBoundary, texts: managedPolicy("permissions_boundary", "permissions_boundary"), link: selfLink}},
	"aws_iam_user_policy":                       {{kind: KindIdentity, texts: attributeText("policy"), link: attributeLink("user", userType)}},
	"aws_iam_user_policy_attachment":            {{kind: KindIdentity, managed: true, texts: managedPolicy("policy_arn", "policy_arn"), link: attributeLink("user", userType)}},
	"aws_iam_user_policy_attachments_exclusive": {{kind: KindIdentity, managed: true, texts: managedPolicyList("policy_arns"), link: attributeLink("user_name", userType)}},

	// Identity policies of a group. Their link points to the group, and the
	// memberships of the plan take them on to its users (see Groups).
	"aws_iam_group_policy":                       {{kind: KindIdentity, texts: attributeText("policy"), link: attributeLink("group", groupType)}},
	"aws_iam_group_policy_attachment":            {{kind: KindIdentity, managed: true, texts: managedPolicy("policy_arn", "policy_arn"), link: attributeLink("group", groupType)}},
	"aws_iam_group_policy_attachments_exclusive": {{kind: KindIdentity, managed: true, texts: managedPolicyList("policy_arns"), link: attributeLink("group_name", groupType)}},

	// Resource policies.
	// A resource policy source links to the resource it is attached to: the
	// resource type and the link attribute, or the resource itself. A read
	// type also needs a row in iam's ownARNPatterns, which builds the
	// resource's ARN pattern when the plan doesn't know its arn.
	//
	// A read type's service must combine its resource policy with the
	// identity policies of a principal in the same account as IAM's general
	// rule does: an Allow in either grants, and an explicit Deny in either
	// overrides it. IAM's evaluation page says that services other than IAM
	// and KMS "may also require an explicit Allow statement within the same
	// account", so each row cites its service's documentation.

	// Secrets Manager: see principal's resourcePolicy
	// (https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html).
	"aws_secretsmanager_secret_policy": {{kind: KindResource, service: "secretsmanager", texts: attributeText("policy"), link: attributeLink("secret_arn", "aws_secretsmanager_secret")}},
	"aws_secretsmanager_secret":        {{kind: KindResource, service: "secretsmanager", texts: configuredText("policy"), link: selfLink}},
	// "If the parent AWS account owns the resource (bucket or object), it
	// can grant resource permissions to its IAM principal by using either
	// the user policy or the resource policy."
	// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-auth-workflow-object-operation.html).
	// The same page says that an object another account owns needs a grant
	// from its owner, through the object ACL. The check assumes that the
	// bucket's account owns its objects, which the bucket owner enforced
	// setting of Object Ownership guarantees. The deprecated policy
	// attribute of aws_s3_bucket is a source when the configuration writes
	// it, at both provider major versions.
	"aws_s3_bucket_policy": {{kind: KindResource, service: "s3", texts: attributeText("policy"), link: attributeLink("bucket", "aws_s3_bucket")}},
	"aws_s3_bucket":        {{kind: KindResource, service: "s3", texts: configuredText("policy"), link: selfLink}},
	// "There are two ways to give your users permissions to your Amazon SQS
	// resources: using the Amazon SQS policy system (resource-based
	// policies) and using the IAM policy system (identity-based policies).
	// You can use one or both methods, with the exception of the ListQueues
	// action, which is a regional permission that can only be set in an IAM
	// policy." ListQueues acts on "*", which no resource policy grants
	// (https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-using-identity-based-policies.html).
	"aws_sqs_queue_policy": {{kind: KindResource, service: "sqs", texts: attributeText("policy"), link: attributeLink("queue_url", "aws_sqs_queue")}},
	"aws_sqs_queue":        {{kind: KindResource, service: "sqs", texts: configuredText("policy"), link: selfLink}},
	// "To grant your users permissions for your Amazon SNS topics, you can
	// use IAM policies, Amazon SNS policies, or both." An explicit deny in
	// either "always overrides an allow"
	// (https://docs.aws.amazon.com/sns/latest/dg/sns-using-identity-based-policies.html).
	// AWS gives a new topic a default policy when the configuration leaves
	// the policy attribute out. That policy is no source (see maySet).
	"aws_sns_topic_policy": {{kind: KindResource, service: "sns", texts: attributeText("policy"), link: attributeLink("arn", "aws_sns_topic")}},
	"aws_sns_topic":        {{kind: KindResource, service: "sns", texts: configuredText("policy"), link: selfLink}},
	// "A user or role only needs to be allowed permission for an action
	// through either a repository policy or an IAM policy but not both for
	// the action to be allowed." A Deny in either denies the action
	// (https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html).
	"aws_ecr_repository_policy": {{kind: KindResource, service: "ecr", texts: attributeText("policy"), link: attributeLink("repository", "aws_ecr_repository")}},
	// A KMS key policy must allow the principal, or the account, before an
	// identity policy has any effect, so the union rule doesn't apply.
	// Package principal evaluates the key policy and the identity policies
	// apart (see its requiredResourcePolicy). A grant is a third way to
	// allow access to a key
	// (https://docs.aws.amazon.com/kms/latest/developerguide/grants.html).
	"aws_kms_key":        {{kind: KindResource, service: "kms", texts: keyPolicyOfKey, link: selfLink}},
	"aws_kms_key_policy": {{kind: KindResource, service: "kms", texts: keyPolicyText, link: kmsKeyLink}},
	"aws_kms_grant":      {{kind: KindResource, service: "kms", grant: true, texts: grantText, link: kmsKeyLink}},
}

// PolicySources returns the policy sources that the changes set, in plan
// order. A create or update reads the planned value, and a no-op reads the
// current value. A delete adds no source, since the policy goes away, so a
// replace adds one source, from its create.
//
// data are the data sources of the plan (see ParseDataSources). A
// data "aws_iam_policy" source gives the text of a managed policy that the
// plan attaches but doesn't create.
func PolicySources(changes []*ResourceChange, data []DataSource) []PolicySource {
	ctx := sourceContext{changes: changes, data: data}
	var out []PolicySource
	for _, rc := range changes {
		if rc.Change == "delete" {
			continue
		}
		for _, spec := range sourceSpecs[rc.Type] {
			link := spec.link(rc)
			for _, t := range spec.texts(rc, ctx) {
				s := PolicySource{
					Address:          rc.Address,
					Path:             t.path,
					Kind:             spec.kind,
					Service:          spec.service,
					Text:             t.text,
					Unknown:          t.unknown || spec.unread,
					Unread:           spec.unread,
					PolicyARN:        t.policyARN,
					Policy:           t.policy,
					PolicyMaybe:      t.maybe,
					OutsidePlan:      t.outside,
					PolicyName:       inlinePolicyName(rc, t.path),
					Managed:          spec.managed,
					Link:             link,
					Grant:            spec.grant,
					DefaultKeyPolicy: t.defaultKey,
				}
				if spec.unread {
					s.Text = ""
					s.Policy = ""
				}
				if spec.arn != "" {
					s.PolicyARN = rc.AttributeValues[spec.arn]
					s.OutsidePlan = outsidePlan(rc, spec.arn, ctx)
				}
				if spec.kind == KindResource && !spec.unread {
					s.Resources, s.ResourceUnknown = attachedResources(link, rc, ctx)
				}
				if spec.service == "kms" {
					for i := range s.Resources {
						s.Resources[i].Aliases = keyAliases(s.Resources[i], ctx)
					}
				}
				out = append(out, s)
			}
		}
	}
	return out
}

// inlinePolicyName returns the known name of the inline policy whose text is
// at path in rc: the name of an aws_iam_role_policy, aws_iam_user_policy or
// aws_iam_group_policy, or the name of an inline_policy block of an
// aws_iam_role. It is empty for any other source.
func inlinePolicyName(rc *ResourceChange, path string) string {
	switch {
	case (rc.Type == rolePolicyType || rc.Type == userPolicyType || rc.Type == groupPolicyType) && path == "policy":
		return rc.AttributeValues["name"]
	case rc.Type == roleType && strings.HasPrefix(path, "inline_policy.") && strings.HasSuffix(path, ".policy"):
		namePath := strings.TrimSuffix(path, ".policy") + ".name"
		if rc.paths == nil || unknownAlong(rc.paths.unknown, namePath) {
			return ""
		}
		v, _ := walk(rc.paths.state, namePath)
		name, _ := v.(string)
		return name
	}
	return ""
}

// policyType is the resource type of a customer managed policy.
const policyType = "aws_iam_policy"

// awsManagedPolicyPrefix starts the ARN of every AWS managed policy. AWS
// owns these policies, so no plan creates one.
const awsManagedPolicyPrefix = "arn:aws:iam::aws:policy/"

// outsidePlan reports whether the attribute attr of rc holds the known ARN
// of a managed policy that the plan provably doesn't contain: no
// aws_iam_policy of the plan may have it, and no data source of the plan
// reads it.
func outsidePlan(rc *ResourceChange, attr string, ctx sourceContext) bool {
	arn := rc.AttributeValues[attr]
	if arn == "" {
		return false
	}
	targets := resolvePolicyARN(rc, attr, arn, rc.References[attr], ctx)
	return len(targets) == 1 && targets[0].outside && !targets[0].maybe
}

// managedPolicy reads the text of the managed policy that the attribute attr
// attaches, such as the policy_arn of an aws_iam_role_policy_attachment. It
// gives a source only when the resource may set the attribute when. An
// aws_iam_policy_attachment that names only users, say, gives no source for
// roles. See resolvePolicyARN for how the ARN names a policy.
func managedPolicy(attr, when string) func(rc *ResourceChange, ctx sourceContext) []policyText {
	return func(rc *ResourceChange, ctx sourceContext) []policyText {
		if !maySet(rc, when) {
			return nil
		}
		arn := rc.AttributeValues[attr]
		return resolvePolicyARN(rc, attr, arn, rc.References[attr], ctx).texts(attr, arn)
	}
}

// managedPolicyList reads the text of each managed policy that a list of
// ARNs attaches, such as the managed_policy_arns of an aws_iam_role. It
// gives a source only when the configuration writes the list, since a
// computed list that the configuration omits holds what other resources
// attach.
//
// A known ARN in the list names its policy by value: the references of the
// attribute belong to the whole list, not to one ARN. An ARN that terraform
// computes at apply time comes from a reference, so it names one of the
// referenced aws_iam_policy resources whose ARN is unknown. When the list
// has one such ARN and its references name one such policy, it names that
// policy. Otherwise each referenced policy may be one of them. A list that
// terraform computes whole, or whose computed ARNs the references don't
// name, is one source with unknown text.
func managedPolicyList(attr string) func(rc *ResourceChange, ctx sourceContext) []policyText {
	return func(rc *ResourceChange, ctx sourceContext) []policyText {
		if !maySet(rc, attr) {
			return nil
		}
		if rc.paths == nil || unknownAlong(rc.paths.unknown, attr) {
			return []policyText{{path: attr, unknown: true}}
		}
		list, _ := walk(rc.paths.state, attr)
		items, _ := list.([]any)
		var out []policyText
		computed := 0
		for i, item := range items {
			path := attr + "." + strconv.Itoa(i)
			arn, _ := item.(string)
			if unknownAlong(rc.paths.unknown, path) || arn == "" {
				computed++
				continue
			}
			out = append(out, resolvePolicyARN(rc, attr, arn, nil, ctx).texts(path, arn)...)
		}
		if computed == 0 {
			return out
		}
		policies, ok := referencedPolicies(rc, rc.References[attr], ctx)
		var targets policyTargets
		for _, p := range policies {
			// A reference to a policy whose ARN is known gives a known ARN.
			if p.AttributeValues["arn"] == "" {
				targets = append(targets, policyTarget(p, computed > 1))
			}
		}
		if !ok || len(targets) == 0 {
			return append(out, policyText{path: attr, unknown: true})
		}
		if len(targets) > 1 {
			for i := range targets {
				targets[i].maybe = true
			}
		}
		return append(out, targets.texts(attr, "")...)
	}
}

// referencedPolicies returns the aws_iam_policy changes that the references
// of a list attribute of rc name, in plan order. A reference with an
// instance key names that instance, and a reference without one names each
// instance. It reports false when a reference may carry another value, such
// as a variable or an attribute of another resource type.
func referencedPolicies(rc *ResourceChange, refs []string, ctx sourceContext) ([]*ResourceChange, bool) {
	named := map[string]bool{}
	keys := map[string]map[string]bool{}
	for _, ref := range refs {
		typ, name, key, ok := parseResourceRef(ref)
		switch {
		case !ok && (strings.HasPrefix(ref, "count.index") || strings.HasPrefix(ref, "each.key")):
			continue
		case !ok || typ != policyType:
			return nil, false
		}
		named[name] = true
		if key != "" {
			if keys[name] == nil {
				keys[name] = map[string]bool{}
			}
			keys[name][key] = true
		}
	}
	var out []*ResourceChange
	for _, p := range ctx.changes {
		if p.Type != policyType || p.Change == "delete" || p.ModuleAddress != rc.ModuleAddress || !named[p.Name] {
			continue
		}
		// Terraform lists aws_iam_policy.p[0] and aws_iam_policy.p for one
		// reference to an instance, so a keyed reference decides alone.
		if k := keys[p.Name]; k != nil && !k[strings.TrimPrefix(p.InstanceName(), p.Name)] {
			continue
		}
		out = append(out, p)
	}
	return out, true
}

// policyTargets are the policies that one attached ARN may name, as
// policyText values without their path and ARN.
type policyTargets []policyText

// texts returns the targets with the attribute path and the known ARN set.
func (ts policyTargets) texts(path, arn string) []policyText {
	out := make([]policyText, len(ts))
	for i, t := range ts {
		t.path = path
		t.policyARN = arn
		out[i] = t
	}
	return out
}

// resolvePolicyARN returns the policies that a managed policy ARN may name.
// The attribute attr of rc holds the ARN, refs are its references, and arn
// is its known value, or empty when terraform computes it at apply time.
// The ARN names a policy in the order a principal link does (see
// PolicyLink.Match):
//
//  1. The references of the attribute. policy_arn = aws_iam_policy.x.arn
//     names aws_iam_policy.x. A reference without an instance key to a
//     policy with count or for_each names one of its instances, decided by
//     known ARNs or undecidable.
//  2. The known ARN against the known arn of each aws_iam_policy of the
//     plan, then of each data "aws_iam_policy" source. A data source that
//     terraform read during the plan gives the text of a policy that the
//     plan doesn't create, such as an AWS managed policy.
//  3. Otherwise a known ARN may name an aws_iam_policy whose ARN is
//     unknown, unless its known name differs. Each such policy is a target
//     that may apply, and so is a policy outside the plan.
//
// A computed ARN that the references don't decide gives one target with
// unknown text. A known ARN that names no policy of the plan gives one
// target outside the plan. A policy whose text terraform computes at apply
// time gives a target with unknown text.
func resolvePolicyARN(rc *ResourceChange, attr, arn string, refs []string, ctx sourceContext) policyTargets {
	link := PolicyLink{Type: policyType, Module: rc.ModuleAddress, Attribute: attr, References: refs, Value: arn}
	var out policyTargets
	for _, p := range ctx.changes {
		if p.Type != policyType || p.Change == "delete" {
			continue
		}
		m, decided := link.matchReferences(p)
		if !decided {
			// The references decide for every policy or for none.
			break
		}
		if m != LinkNo {
			out = append(out, policyTarget(p, m == LinkMaybe))
		}
	}
	if len(out) > 0 {
		return out
	}
	if arn == "" {
		return policyTargets{{unknown: true}}
	}

	for _, p := range ctx.changes {
		if p.Type == policyType && p.Change != "delete" && p.AttributeValues["arn"] == arn {
			return policyTargets{policyTarget(p, false)}
		}
	}
	for _, d := range ctx.data {
		if d.Type == policyType && d.Values["arn"] == arn {
			text := d.Values["policy"]
			return policyTargets{{policy: d.Address, text: text, unknown: d.Deferred || text == ""}}
		}
	}
	if strings.HasPrefix(arn, awsManagedPolicyPrefix) {
		return policyTargets{{unknown: true, outside: true}}
	}
	name := arn[strings.LastIndex(arn, "/")+1:]
	for _, p := range ctx.changes {
		if p.Type != policyType || p.Change == "delete" || p.AttributeValues["arn"] != "" {
			continue
		}
		if known := p.AttributeValues["name"]; known == "" || known == name {
			out = append(out, policyTarget(p, true))
		}
	}
	return append(out, policyText{unknown: true, outside: true, maybe: len(out) > 0})
}

// policyTarget returns the aws_iam_policy p as a target, with the text of
// its policy attribute. A text that terraform computes at apply time is
// unknown.
func policyTarget(p *ResourceChange, maybe bool) policyText {
	t := readText(p, "policy")
	return policyText{policy: p.Address, text: t.text, unknown: t.unknown, maybe: maybe}
}

// attachedResources returns the resources that a resource policy source of
// rc may attach to, through its link:
//
//   - A source that belongs to the resource itself, such as the policy of an
//     aws_secretsmanager_secret, attaches to rc.
//   - A link attribute with a known ARN attaches to the resource with that
//     ARN, whether the plan contains it or not.
//   - A link attribute with another known value, such as a bucket name or a
//     queue URL, attaches to the resource that the value names, whether the
//     plan contains it or not. AttachedResource.Value keeps the value.
//   - Otherwise the references of the link attribute name the resources of
//     the plan it may attach to, as PolicyLink.Match decides for a principal.
//
// It reports true when the plan can't tell the resource: the references
// name no resource of the link's type, or they may carry another value, such
// as a variable or a data source.
func attachedResources(link PolicyLink, rc *ResourceChange, ctx sourceContext) ([]AttachedResource, bool) {
	if link.Self != "" {
		return []AttachedResource{{Change: rc, Match: LinkYes}}, false
	}
	if strings.HasPrefix(link.Value, "arn:") {
		return []AttachedResource{{ARN: link.Value, Match: LinkYes}}, false
	}
	if link.Value != "" {
		return []AttachedResource{{Value: link.Value, Match: LinkYes}}, false
	}
	var out []AttachedResource
	for _, c := range ctx.changes {
		if c.Type != link.Type || c.Change == "delete" {
			continue
		}
		m, decided := link.matchReferences(c)
		if !decided {
			return nil, true
		}
		if m != LinkNo {
			out = append(out, AttachedResource{Change: c, Match: m})
		}
	}
	return out, len(out) == 0
}

// configuredText reads the policy text from a top-level attribute, when the
// resource may set that attribute (see maySet). The policy attribute of an
// aws_secretsmanager_secret is one: the provider computes it when the
// configuration leaves it out, and it then holds the policy that an
// aws_secretsmanager_secret_policy sets.
func configuredText(attr string) func(rc *ResourceChange, ctx sourceContext) []policyText {
	return func(rc *ResourceChange, _ sourceContext) []policyText {
		if !maySet(rc, attr) {
			return nil
		}
		return []policyText{readText(rc, attr)}
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
func attributeText(attr string) func(rc *ResourceChange, ctx sourceContext) []policyText {
	return func(rc *ResourceChange, _ sourceContext) []policyText {
		return []policyText{readText(rc, attr)}
	}
}

// blockTexts reads one policy text from the attribute attr of each nested
// block, such as inline_policy.N.policy. A block list that terraform
// computes at apply time is one unknown source. The blocks are a source only
// when the configuration writes them, since a computed block that the
// configuration omits holds policies that other resources set.
func blockTexts(block, attr string) func(rc *ResourceChange, ctx sourceContext) []policyText {
	return func(rc *ResourceChange, _ sourceContext) []policyText {
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
