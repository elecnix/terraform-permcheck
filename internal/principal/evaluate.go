package principal

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// Principal is a role that the config's principals map gives a label, as
// the plan shows it. Exactly one of Role and Outside is set.
type Principal struct {
	// Label is the key of the principals map, which the needs of the role
	// use as their principal.
	Label string
	// Role is the change of the role in the plan (see Find). It is nil for
	// a role outside the plan.
	Role *plan.ResourceChange
	// Outside is the role outside the plan that a name or arn entry gives.
	// It is nil for a role in the plan.
	Outside *plan.OutsideRole
}

// link reports whether a policy link points to the principal's role.
func (p Principal) link(l plan.PolicyLink) plan.LinkMatch {
	if p.Outside != nil {
		return l.MatchOutside(*p.Outside)
	}
	return l.Match(p.Role)
}

// Identity returns what the plan shows of the principal's role, for matching
// the Principal and NotPrincipal elements of a resource policy. A role in
// the plan gives its known arn and name, and whether it sets a permissions
// boundary. A role outside the plan gives the name or ARN of its entry.
func (p Principal) Identity() policy.Principal {
	if p.Outside != nil {
		return policy.Principal{Kind: policy.KindRole, ARN: p.Outside.ARN, Name: p.Outside.Name}
	}
	out := policy.Principal{Kind: policy.KindRole}
	if p.Role == nil {
		return out
	}
	out.ARN = p.Role.AttributeValues["arn"]
	out.Name = p.Role.AttributeValues["name"]
	out.PermissionsBoundary = p.Role.AttributeValues["permissions_boundary"] != "" || p.Role.Attributes["permissions_boundary"]
	return out
}

// The kinds of policy that the plan may not show completely for a role
// outside the plan, as Applied.Unlisted names them.
const (
	UnlistedInline  = "inline"
	UnlistedManaged = "managed"
)

// Applied is a policy source that may apply to a checked need of a
// principal.
type Applied struct {
	plan.PolicySource
	// Match says whether the source attaches to the principal. A source
	// whose attached ARN may name another policy (see
	// plan.PolicySource.PolicyMaybe) is LinkMaybe, and so is a source that
	// an exclusive resource of the role may remove (see Check). A resource
	// policy is LinkYes when its resource is the resource of a checked need,
	// and LinkMaybe when it may be (see resourcePolicy). A resource policy of
	// a type this version doesn't read yet is LinkMaybe.
	Match plan.LinkMatch
	// Unlisted is set on the implicit source of a role outside the plan:
	// the policies that other stacks attach to the role. It names the kinds
	// of policy that the plan may not show, UnlistedInline and
	// UnlistedManaged. This source has no address and unknown text.
	Unlisted []string
	// ResourceOutside is set on the implicit source of a resource whose
	// resource policy must allow a need and that the plan doesn't show, such
	// as a KMS key outside the plan (see requiredResourcePolicy). This source
	// has no address and unknown text.
	ResourceOutside bool
	// Resource is the need's resource of a source with ResourceOutside. It
	// is empty for a need without resources, which may act on any resource
	// of the service.
	Resource string
}

// Result is the outcome of Check.
type Result struct {
	// Missing are the need actions that the policies don't grant, or that
	// they grant only where the tool can't check the grant. Each one
	// carries the principal's label.
	Missing []iam.MissingAction
	// Sources are the policy sources that may apply to at least one checked
	// action: the sources of the plan in plan order, then the inline
	// policies that an exclusive resource lists and the plan doesn't define,
	// then the implicit source of a role outside the plan.
	Sources []Applied
	// Complete is true when the plan shows every policy of the role. The
	// check assumes it for a role in the plan. A role outside the plan has
	// it when the plan has both exclusive resources for the role.
	Complete bool
}

// Check checks the needs of the principal against the policy sources of the
// plan. It is the one entry point for the evaluation of a principal's
// policies: for each action and resource of a need, it builds the
// principal's policy set (see Set) and runs the action through
// iam.CheckNeedsWith, the path the needs of a --policy-* document take.
//
// exclusives are the exclusive resources of the plan (see plan.Exclusives).
// For a role in the plan, the check assumes that the plan shows every policy
// of the role, with or without them. A role outside the plan may have
// policies that other stacks attach, so it gets an implicit unknown source,
// unless the plan has an aws_iam_role_policies_exclusive and an
// aws_iam_role_policy_attachments_exclusive for the role. With one of them,
// the implicit source covers the other kind only.
//
// For either role, an exclusive resource changes the sources in two ways.
// An inline policy that its list names and that the plan doesn't define is
// an unknown source. A source of the kind it lists, which its list may omit,
// gets LinkMaybe: the provider removes it after the apply, unless terraform
// attaches it again afterwards, so it may not apply. Its Allows count as
// grants the tool can't check, and its Denies don't. Dropping the source
// would turn its grants into a gap that the apply may disprove.
//
// The permissions boundary of a role in the plan is a policy source of the
// kind plan.KindBoundary (see Set). The plan doesn't show whether a role
// outside the plan has a boundary, or what it allows. The check treats it as
// it treats a service control policy or a session policy: as allowing. A
// boundary can only remove permissions, so a missing verdict stays provable,
// and a covered verdict means covered by the policies the plan shows.
//
// It returns an error when the plan shows a policy text that doesn't parse.
func Check(p Principal, needs []iam.Need, sources []plan.PolicySource, exclusives []plan.Exclusive, strict bool) (Result, error) {
	docs := make([]*policy.Document, len(sources))
	for i, s := range sources {
		if s.Unknown || s.DefaultKeyPolicy {
			continue
		}
		doc, err := policy.Parse([]byte(s.Text))
		if err != nil {
			return Result{}, fmt.Errorf("principals[%q]: parse the policy of %s (%s): %w", p.Label, s.Address, s.Path, err)
		}
		docs[i] = doc
	}

	// The link of an identity or boundary source is the same for every
	// action.
	links := make([]plan.LinkMatch, len(sources))
	for i, s := range sources {
		if s.Kind != plan.KindResource {
			links[i] = p.identityLink(s)
		}
	}
	extra, complete := applyExclusives(p, sources, links, exclusives)

	identity := p.Identity()
	applied := make([]plan.LinkMatch, len(sources))
	var outside []Applied
	outsideSeen := map[string]bool{}
	grantsFor := func(action, resource string) iam.Grants {
		var set Set
		var merged, resourceSide, beyond, boundaries []*policy.Document
		var boundaryNames []string
		service, _, _ := strings.Cut(action, ":")
		service = strings.ToLower(service)
		required := requiredResourcePolicy[service] && resource != "*"
		found := false
		for i, s := range sources {
			m := links[i]
			var resourceDoc *policy.Document
			if s.Kind == plan.KindResource {
				r := resourcePolicy(s, docs[i], identity, action, resource, required)
				m, resourceDoc = r.match, r.principalSide
				resourceSide = append(resourceSide, r.resourceSide)
				beyond = append(beyond, r.beyondBoundary)
				found = found || r.on
			}
			if m == plan.LinkNo {
				continue
			}
			if applied[i] == plan.LinkNo || m == plan.LinkYes {
				applied[i] = m
			}
			switch {
			case s.Kind == plan.KindBoundary:
				boundaries = append(boundaries, boundaryDoc(s, docs[i], m))
				if name := boundaryName(s); !slices.Contains(boundaryNames, name) {
					boundaryNames = append(boundaryNames, name)
				}
			case s.Kind == plan.KindResource:
				merged = append(merged, resourceDoc)
			case s.Unknown:
				merged = append(merged, policy.UnknownSource())
			case m == plan.LinkMaybe:
				// The source may not apply to the principal. Its Allows count
				// as grants the tool can't check, with the reason condition,
				// and its Denies don't (design of issue #175, "Undecidable
				// overlaps in the new cases").
				merged = append(merged, docs[i].MayGrant(policy.ReasonCondition))
			default:
				merged = append(merged, docs[i])
			}
		}
		// Each extra source is an identity source with unknown text.
		for range extra {
			merged = append(merged, policy.UnknownSource())
		}
		if required && !found {
			// The plan doesn't show the resource's policy, which may grant
			// the principal itself (see requiredResourcePolicy).
			merged = append(merged, policy.UnknownSource())
			resourceSide = append(resourceSide, policy.UnknownSource())
			beyond = append(beyond, policy.UnknownSource())
			if !outsideSeen[resource] {
				outsideSeen[resource] = true
				match := plan.LinkYes
				if resource == "" {
					match = plan.LinkMaybe
				}
				outside = append(outside, Applied{
					PolicySource:    plan.PolicySource{Kind: plan.KindResource, Service: service, Unknown: true, OutsidePlan: true},
					Match:           match,
					ResourceOutside: true,
					Resource:        resource,
				})
			}
		}
		set.Policies = policy.Merge(merged...)
		if required {
			set.ResourceSide = policy.Merge(resourceSide...)
		}
		if len(boundaries) > 0 {
			set.Boundary = policy.Merge(boundaries...)
			set.BoundaryName = strings.Join(boundaryNames, " or ")
			set.BeyondBoundary = policy.Merge(beyond...)
		}
		return set
	}

	missing := iam.CheckNeedsWith(needs, grantsFor, strict)
	for i := range missing {
		missing[i].Principal = p.Label
	}
	res := Result{Missing: missing, Complete: complete}
	for i, m := range applied {
		if m != plan.LinkNo {
			res.Sources = append(res.Sources, Applied{PolicySource: sources[i], Match: m})
		}
	}
	if len(needs) > 0 {
		res.Sources = append(res.Sources, extra...)
	}
	res.Sources = append(res.Sources, outside...)
	return res, nil
}

// requiredResourcePolicy lists the services whose resource policy must allow
// a request before an identity policy has any effect. For most resources an
// Allow in an identity policy or in a resource policy is enough, and "KMS
// key policies are exceptions to this logic, because they must explicitly
// allow access for principals"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).
// Check evaluates a need of such a service on two sides, and the need is
// covered only when both allow it (see Set.ResourceSide):
//
//   - The principal side merges the identity policies with the statements
//     of the resource policies that allow the principal itself, and with
//     the KMS grants of the plan.
//   - The resource side merges the resource policies, where a statement
//     for the principal's account grants too (see policy.ResourceSide), and
//     the grants.
//
// A definite Deny in either side makes the need missing. The two sides give
// AWS's rule for a key: a key policy statement for the principal grants by
// itself, and a statement for the account grants only the actions it
// allows, and only when an identity policy allows them too. "Unless the key
// policy explicitly allows it, you cannot use IAM policies to allow access
// to a KMS key"
// (https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html),
// and an account statement lets the account "use IAM policies to delegate
// the permissions specified in the key policy"
// (https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html#key-policy-elements).
//
// A grant allows access "along with key policies and IAM policies"
// (https://docs.aws.amazon.com/kms/latest/developerguide/grants.html), so
// it joins both sides. The check can't tell whether a grant is still in
// place when the need runs, since its retiring principal may retire it, so
// a grant's Allow is a grant the tool can't check, with the reason
// condition.
//
// Every key has a key policy, so the closed-world assumption of the other
// services, "no policy in the plan means no resource policy", doesn't hold
// for a key. When the need's resource is no key of the plan, or the need has
// no resources, the key policy is an unknown source on both sides: it may
// allow the principal itself. Such a need is covered by default unless a
// definite Deny applies, and unverified with the reason policy_unknown under
// --strict-resources, even when an identity policy allows it. A need on "*"
// acts on no particular key, such as kms:CreateKey, which a key policy can't
// control
// (https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies.html),
// so the identity policies decide it.
var requiredResourcePolicy = map[string]bool{"kms": true}

// identityLink reports whether an identity or boundary source applies to
// the principal: its link matches the role.
func (p Principal) identityLink(s plan.PolicySource) plan.LinkMatch {
	m := p.link(s.Link)
	if m == plan.LinkYes && s.PolicyMaybe {
		// The role attaches the ARN, and the ARN may name another policy.
		return plan.LinkMaybe
	}
	return m
}

// appliedResourcePolicy is what a resource policy source adds to the
// check of one action and one resource of a need (see resourcePolicy).
type appliedResourcePolicy struct {
	// match says whether the source applies to the need.
	match plan.LinkMatch
	// principalSide holds the statements that join the principal's
	// policies.
	principalSide *policy.Document
	// resourceSide holds the statements of the resource side of a service
	// whose resource policy is required (see requiredResourcePolicy). It is
	// nil for any other service.
	resourceSide *policy.Document
	// beyondBoundary holds the Allow statements of principalSide whose grant
	// a permissions boundary of the principal doesn't limit (see
	// policy.BeyondBoundary).
	beyondBoundary *policy.Document
	// on is true when the need's resource is provably the resource that
	// the source attaches to, and the source is a policy of that resource,
	// not a grant.
	on bool
}

// resourcePolicy returns whether a resource policy source applies to a need
// of the principal, for one action and one resource of the need, and the
// statements it adds to the check. It applies the same-account rule of the
// design of issue #175: an Allow in an identity policy or in a resource
// policy grants, and an explicit Deny in either overrides it
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-rdp).
// Secrets Manager applies the same rule to a secret's resource policy
// (https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html).
// The table of source types in package plan cites the page of each other
// service it reads. When required is set, the service's resource policy
// must allow the need too, and the source also gives the statements of the
// resource side (see requiredResourcePolicy).
//
// A source of another service doesn't apply. A source of a type this version
// doesn't read yet applies to every action of its service, as an unknown
// source. For a read type:
//
//  1. The need's resource selects the resources of the source, and the
//     patterns of each resource that it may share an ARN with (see
//     resourceMatch). A bucket has a pattern for itself and one for its
//     objects, so a need on objects keeps the statements on objects only,
//     and a need on the bucket keeps the statements on the bucket only. A
//     statement on the bucket ARN doesn't grant its objects. A need on "*"
//     needs a grant on every resource, which
//     the policy of one resource can't give, and a Deny on one resource
//     doesn't deny every resource. So no resource policy applies to it, and
//     the identity policies decide it. A need may name a KMS key by an
//     alias that the plan points to the key (see
//     plan.AttachedResource.AliasMatch).
//  2. A source whose text the plan doesn't show is an unknown source.
//  3. Otherwise the statements whose Principal or NotPrincipal may match the
//     principal are kept (see policy.Document.ForPrincipal), and each one is
//     rewritten to apply to the attached resource only (see
//     policy.Document.OnResource).
//  4. When the attached resource may not be the need's resource, its Allows
//     are grants the tool can't check, with the reason resource_scope, and
//     its Denies are dropped (see policy.Document.MayGrant). For a need
//     without resources, the target is unknown, and Coverage applies a Deny
//     only when it denies every resource, which a rewritten Deny never does.
//  5. A source that may not be the resource's policy (see
//     plan.PolicySource.PolicyMaybe), and a KMS grant, give grants the tool
//     can't check, with the reason condition. The default key policy of a
//     KMS key gives the resource side an Allow of every action, and the
//     principal side nothing (see plan's keyPolicyOfKey).
//
// The plan is taken to list every policy, of principals and of resources. A
// resource that the plan doesn't contain, or whose policy no source of the
// plan sets, has no resource policy that the check can see, so the identity
// policies decide its needs. A required resource policy is the exception
// (see requiredResourcePolicy).
func resourcePolicy(s plan.PolicySource, doc *policy.Document, identity policy.Principal, action, resource string, required bool) appliedResourcePolicy {
	service, _, _ := strings.Cut(action, ":")
	switch {
	case !strings.EqualFold(service, s.Service):
		return appliedResourcePolicy{}
	case s.Unread:
		return appliedResourcePolicy{match: plan.LinkMaybe, principalSide: policy.UnknownSource(), beyondBoundary: policy.UnknownSource(), resourceSide: sideOf(required, policy.UnknownSource())}
	case resource == "*":
		return appliedResourcePolicy{}
	}
	attached := s.Resources
	if s.ResourceUnknown {
		attached = []plan.AttachedResource{{Match: plan.LinkMaybe}}
	}
	out := appliedResourcePolicy{}
	var principalSide, resourceSide, beyond []*policy.Document
	for _, a := range attached {
		patterns := attachedPatterns(s.Link.Type, a)
		m := a.Match
		as := patterns
		on := false
		switch {
		case resource == "":
			// The need acts on an unknown resource.
			m = plan.LinkMaybe
		case a.AliasMatch(resource) != plan.LinkNo:
			// The need names the key by an alias that the plan points to
			// the key.
			if a.AliasMatch(resource) == plan.LinkMaybe {
				m = plan.LinkMaybe
			}
			patterns, as = []string{resource}, []string{resource}
			on = m == plan.LinkYes
		case patterns == nil:
			// The resource's ARN and pattern are both unknown.
			m = plan.LinkMaybe
		default:
			var rm plan.LinkMatch
			patterns, rm = resourceMatch(resource, patterns)
			if rm == plan.LinkNo {
				continue
			}
			if rm == plan.LinkMaybe {
				m = plan.LinkMaybe
			}
			if m == plan.LinkYes {
				// The need's resource is the attached resource, so a
				// statement on the whole resource is a statement on the
				// need's resource.
				as = []string{resource}
				on = true
			}
		}
		if out.match == plan.LinkNo || m == plan.LinkYes {
			out.match = m
		}
		out.on = out.on || (on && !s.Grant)
		if s.Unknown {
			continue
		}
		shape := func(d *policy.Document) *policy.Document {
			switch {
			case patterns == nil:
				d = d.MayGrant(policy.ReasonResourceScope)
			case resource != "" && m == plan.LinkMaybe:
				d = d.OnResource(patterns, nil).MayGrant(policy.ReasonResourceScope)
			default:
				d = d.OnResource(patterns, as)
			}
			if s.PolicyMaybe || s.Grant {
				d = d.MayGrant(policy.ReasonCondition)
			}
			return d
		}
		switch {
		case s.DefaultKeyPolicy:
			resourceSide = append(resourceSide, shape(defaultKeyPolicy))
		case s.Grant:
			// A grant's grantee may be an account, which a grant
			// allows as a key policy statement does.
			d := shape(doc.ForPrincipal(identity, policy.ResourceSide()))
			principalSide = append(principalSide, d)
			resourceSide = append(resourceSide, d)
			beyond = append(beyond, shape(doc.ForPrincipal(identity, policy.BeyondBoundary())))
		default:
			principalSide = append(principalSide, shape(doc.ForPrincipal(identity)))
			beyond = append(beyond, shape(doc.ForPrincipal(identity, policy.BeyondBoundary())))
			if required {
				resourceSide = append(resourceSide, shape(doc.ForPrincipal(identity, policy.ResourceSide())))
			}
		}
	}
	switch {
	case out.match == plan.LinkNo:
		return appliedResourcePolicy{}
	case s.Unknown:
		out.principalSide = policy.UnknownSource()
		out.beyondBoundary = policy.UnknownSource()
		out.resourceSide = sideOf(required, policy.UnknownSource())
	default:
		out.principalSide = policy.Merge(principalSide...)
		out.beyondBoundary = policy.Merge(beyond...)
		out.resourceSide = sideOf(required, policy.Merge(resourceSide...))
	}
	return out
}

// sideOf returns the document of the resource side when the resource policy
// is required, and nil otherwise.
func sideOf(required bool, d *policy.Document) *policy.Document {
	if !required {
		return nil
	}
	return d
}

// defaultKeyPolicy is the resource side of AWS's default key policy, which
// "gives the AWS account that owns the KMS key permission to use IAM
// policies to allow access to all AWS KMS operations on the KMS key"
// (https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html).
// Its one statement allows the account every action, and the check assumes
// that the key is in the principal's account, as the same-account rule
// does. It allows the principal nothing by itself.
var defaultKeyPolicy = mustParse(`{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "kms:*", "Resource": "*"}]}`)

// mustParse parses a policy text of this package.
func mustParse(text string) *policy.Document {
	d, err := policy.Parse([]byte(text))
	if err != nil {
		panic(err)
	}
	return d
}

// attachedPatterns returns the ARN patterns of a resource of type typ that a
// resource policy attaches to: the known ARN of the link attribute, the
// patterns that another known value of the link attribute gives (see
// iam.LinkValueARNPatterns), or the ARN or target pattern of the resource in
// the plan (see iam.ResourceARNPatterns). It returns nil when none is known.
func attachedPatterns(typ string, a plan.AttachedResource) []string {
	switch {
	case a.ARN != "":
		return []string{a.ARN}
	case a.Value != "":
		return iam.LinkValueARNPatterns(typ, a.Value)
	case a.Change != nil:
		return iam.ResourceARNPatterns(a.Change)
	}
	return nil
}

// resourceMatch compares a resource of a need with the ARN patterns of the
// resource a policy is attached to. It is LinkYes when they provably share
// an ARN, LinkNo when they provably share none, and LinkMaybe when the
// overlap is undecidable (see policy.ARNOverlap). It also returns the
// patterns that decide the answer: those that provably share an ARN with the
// need's resource, or for LinkMaybe those that may.
func resourceMatch(resource string, patterns []string) ([]string, plan.LinkMatch) {
	var yes, maybe []string
	for _, p := range patterns {
		overlap, decidable := policy.ARNOverlap(resource, p)
		switch {
		case overlap && decidable:
			yes = append(yes, p)
		case overlap:
			maybe = append(maybe, p)
		}
	}
	switch {
	case yes != nil:
		return yes, plan.LinkYes
	case maybe != nil:
		return maybe, plan.LinkMaybe
	}
	return nil, plan.LinkNo
}

// applyExclusives applies the exclusive resources of the principal's role
// to the links of its sources (see Check). It returns the extra sources: the
// inline policies that a list names and the plan doesn't define, and the
// implicit source of a role outside the plan. It also reports whether the
// plan shows every policy of the role.
func applyExclusives(p Principal, sources []plan.PolicySource, links []plan.LinkMatch, exclusives []plan.Exclusive) ([]Applied, bool) {
	var extra []Applied
	inline, managed := false, false
	for _, ex := range exclusives {
		m := p.link(ex.Link)
		if m == plan.LinkNo {
			continue
		}
		if ex.Kind == plan.ExclusiveInline {
			extra = append(extra, undefinedInline(ex, m, sources, links)...)
		}
		if m != plan.LinkYes {
			// The resource may list the policies of another role.
			continue
		}
		listed := listedPolicies(ex, sources)
		for i, s := range sources {
			if links[i] != plan.LinkYes || s.Kind != plan.KindIdentity || s.Address == ex.Address {
				continue
			}
			switch {
			case ex.Kind == plan.ExclusiveInline && !s.Managed && !ex.ListsInline(s):
				links[i] = plan.LinkMaybe
			case ex.Kind == plan.ExclusiveManaged && s.Managed && !listed[s.PolicyARN] && !listed[s.Policy]:
				links[i] = plan.LinkMaybe
			}
		}
		if ex.Kind == plan.ExclusiveInline {
			inline = true
		} else {
			managed = true
		}
	}
	if p.Outside == nil {
		return extra, true
	}
	var unlisted []string
	if !inline {
		unlisted = append(unlisted, UnlistedInline)
	}
	if !managed {
		unlisted = append(unlisted, UnlistedManaged)
	}
	if len(unlisted) == 0 {
		return extra, true
	}
	implicit := Applied{
		PolicySource: plan.PolicySource{Kind: plan.KindIdentity, Unknown: true},
		Match:        plan.LinkYes,
		Unlisted:     unlisted,
	}
	return append(extra, implicit), false
}

// listedPolicies returns the managed policies that the list of an
// aws_iam_role_policy_attachments_exclusive provably names: its known ARNs,
// and the address of each aws_iam_policy or data source whose text a source
// of the list reads. It is empty for the list of inline policies.
func listedPolicies(ex plan.Exclusive, sources []plan.PolicySource) map[string]bool {
	out := map[string]bool{}
	if ex.Kind != plan.ExclusiveManaged {
		return out
	}
	for _, arn := range ex.Entries {
		if arn != "" {
			out[arn] = true
		}
	}
	for _, s := range sources {
		if s.Address == ex.Address && s.Policy != "" && !s.PolicyMaybe {
			out[s.Policy] = true
		}
	}
	delete(out, "")
	return out
}

// undefinedInline returns an unknown source for each inline policy that the
// list of an aws_iam_role_policies_exclusive names and the plan doesn't
// define for the role: the role keeps that policy, and the plan doesn't show
// its text. An inline policy is defined when a source that attaches to the
// role has its name. An entry that terraform computes at apply time is
// defined when the list references aws_iam_role_policy resources only. The
// sources get the link m of the exclusive resource.
func undefinedInline(ex plan.Exclusive, m plan.LinkMatch, sources []plan.PolicySource, links []plan.LinkMatch) []Applied {
	defined := map[string]bool{}
	for i, s := range sources {
		if links[i] == plan.LinkYes && s.Kind == plan.KindIdentity && !s.Managed && s.PolicyName != "" {
			defined[s.PolicyName] = true
		}
	}
	var out []Applied
	computed := ex.Computed
	for i, name := range ex.Entries {
		switch {
		case name == "":
			computed = true
		case !defined[name]:
			out = append(out, Applied{Match: m, PolicySource: plan.PolicySource{
				Address:     ex.Address,
				Path:        ex.Attribute + "." + strconv.Itoa(i),
				Kind:        plan.KindIdentity,
				Unknown:     true,
				OutsidePlan: true,
				PolicyName:  name,
				Link:        ex.Link,
			}})
		}
	}
	if computed && !ex.EntriesFromPlan("aws_iam_role_policy") {
		out = append(out, Applied{Match: m, PolicySource: plan.PolicySource{
			Address: ex.Address,
			Path:    ex.Attribute,
			Kind:    plan.KindIdentity,
			Unknown: true,
			Link:    ex.Link,
		}})
	}
	return out
}

// boundaryDoc returns the document that a boundary source adds to the
// boundary of the principal. The boundary is one policy, so the documents of
// its sources merge into one: each source is a policy that the boundary's
// ARN may name (see plan.PolicySource.PolicyMaybe). A boundary allows an
// action when one of them may allow it.
//
// A source whose text the plan doesn't show is an unknown source, which may
// allow anything. A source that may not be the boundary gives its Allows as
// grants the tool can't check, with the reason condition, and its Denies
// don't count.
func boundaryDoc(s plan.PolicySource, doc *policy.Document, m plan.LinkMatch) *policy.Document {
	switch {
	case s.Unknown:
		return policy.UnknownSource()
	case m == plan.LinkMaybe:
		return doc.MayGrant(policy.ReasonCondition)
	}
	return doc
}

// boundaryName names a boundary source in a finding: the address of the
// aws_iam_policy or data "aws_iam_policy" that holds its text, or else the
// ARN of the policy.
func boundaryName(s plan.PolicySource) string {
	switch {
	case s.Policy != "":
		return s.Policy
	case s.PolicyARN != "":
		return s.PolicyARN
	}
	return s.Address
}

// Set is the policies that decide one action of a principal in one account.
// Policies merges the identity policies of the principal with the resource
// policies that may apply.
//
// AWS allows a request in one account when an identity or a resource policy
// allows it and none denies it
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-rdp),
// which policy.Merge computes.
//
// Boundary is the permissions boundary of the principal, or nil when it has
// none. The identity policies and the boundary give "the intersection of the
// two categories"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-bound).
// The boundary also limits a resource policy grant to the role's ARN, but not
// a grant to a session of the role or to an IAM user's ARN
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).
// BeyondBoundary holds the grants of the resource policies that the boundary
// doesn't limit (see policy.BeyondBoundary). So the set allows an action in
// two ways, and its verdict is the better of the two:
//
//   - Policies and Boundary both allow it.
//   - BeyondBoundary allows it, and no Deny of Policies or Boundary denies
//     it. "If the enforcement code finds even one explicit deny that
//     applies, the enforcement code returns a final decision of Deny"
//     (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).
//
// A missing verdict that only the boundary causes names the boundary with
// BoundaryName (see policy.Result.Boundary).
//
// ResourceSide holds the resource policies that must allow the action as
// well, apart from the merged policies, such as a KMS key policy (see
// requiredResourcePolicy). It is nil when the action needs no such Allow.
// When it is set, Set's verdict is also no better than its verdict. The KMS
// documentation doesn't say how a boundary combines with a key policy, so the
// check applies the IAM rule above to the principal side: a key policy
// statement for the role's ARN, and an account statement through the
// identity policies, are limited by the boundary, and a statement for a
// session of the role isn't.
type Set struct {
	Policies       *policy.Document
	ResourceSide   *policy.Document
	Boundary       *policy.Document
	BoundaryName   string
	BeyondBoundary *policy.Document
}

// Coverage reports whether the set grants action on a resource matching any
// of the target ARN patterns (see Set).
func (s Set) Coverage(action string, targets []string, conds policy.Conditions, strict bool) policy.Result {
	return s.verdict(func(d *policy.Document) policy.Result {
		return d.Coverage(action, targets, conds, strict)
	})
}

// CoverageOfEveryResource reports whether the set grants action on every
// resource (see Set).
func (s Set) CoverageOfEveryResource(action string, strict bool) policy.Result {
	return s.verdict(func(d *policy.Document) policy.Result {
		return d.CoverageOfEveryResource(action, strict)
	})
}

// verdict combines the verdicts that coverage gives for each document of the
// set, as Set describes.
func (s Set) verdict(coverage func(*policy.Document) policy.Result) policy.Result {
	policies := coverage(s.Policies)
	res := policies
	if s.Boundary != nil {
		bounded := worst(policies, coverage(s.Boundary))
		beyond := coverage(policy.Merge(s.BeyondBoundary, s.Policies.Denies(), s.Boundary.Denies()))
		res = best(bounded, beyond)
		if res.Verdict == policy.Missing && policies.Verdict != policy.Missing {
			res.Boundary = s.BoundaryName
		}
	}
	if s.ResourceSide != nil {
		res = worst(res, coverage(s.ResourceSide))
	}
	return res
}

// GrantedResources lists the resources the merged policies grant action
// on, when they grant it only on some. A boundary grants nothing by itself,
// so it adds none.
func (s Set) GrantedResources(action string) []string {
	return s.Policies.GrantedResources(action)
}

// best returns the result that allows more: Covered before Unverified before
// Missing. Between two unverified results it keeps the first.
func best(a, b policy.Result) policy.Result {
	if rank(b.Verdict) < rank(a.Verdict) {
		return b
	}
	return a
}

// worst returns the result that allows less: Missing before Unverified
// before Covered. Between two unverified results it keeps the first, so the
// reason of the merged policies comes before the boundary's and the resource
// side's.
func worst(a, b policy.Result) policy.Result {
	if rank(b.Verdict) > rank(a.Verdict) {
		return b
	}
	return a
}

// rank orders the verdicts for worst. A higher rank allows less.
func rank(v policy.Verdict) int {
	switch v {
	case policy.Missing:
		return 2
	case policy.Unverified:
		return 1
	default:
		return 0
	}
}
