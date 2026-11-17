package principal

import (
	"fmt"
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
// It returns an error when the plan shows a policy text that doesn't parse.
func Check(p Principal, needs []iam.Need, sources []plan.PolicySource, exclusives []plan.Exclusive, strict bool) (Result, error) {
	docs := make([]*policy.Document, len(sources))
	for i, s := range sources {
		if s.Unknown {
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
	grantsFor := func(action, resource string) iam.Grants {
		var set Set
		var merged []*policy.Document
		for i, s := range sources {
			m := links[i]
			var resourceDoc *policy.Document
			if s.Kind == plan.KindResource {
				m, resourceDoc = resourcePolicy(s, docs[i], identity, action, resource)
			}
			if m == plan.LinkNo {
				continue
			}
			if applied[i] == plan.LinkNo || m == plan.LinkYes {
				applied[i] = m
			}
			switch {
			case s.Kind == plan.KindBoundary:
				// No boundary type is read yet, so every boundary is an
				// unknown source. It can only remove permissions.
				set.Boundaries = append(set.Boundaries, policy.UnknownSource())
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
		set.Policies = policy.Merge(merged...)
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
	return res, nil
}

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

// resourcePolicy returns whether a resource policy source applies to a need
// of the principal, for one action and one resource of the need, and the
// statements it adds to the merged document. It applies the same-account
// rule of the design of issue #175: an Allow in an identity policy or in a
// resource policy grants, and an explicit Deny in either overrides it
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-rdp).
// Secrets Manager applies the same rule to a secret's resource policy
// (https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html).
// The table of source types in package plan cites the page of each other
// service it reads.
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
//     the identity policies decide it.
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
//
// The plan is taken to list every policy, of principals and of resources. A
// resource that the plan doesn't contain, or whose policy no source of the
// plan sets, has no resource policy that the check can see, so the identity
// policies decide its needs.
func resourcePolicy(s plan.PolicySource, doc *policy.Document, identity policy.Principal, action, resource string) (plan.LinkMatch, *policy.Document) {
	service, _, _ := strings.Cut(action, ":")
	switch {
	case !strings.EqualFold(service, s.Service):
		return plan.LinkNo, nil
	case s.Unread:
		return plan.LinkMaybe, policy.UnknownSource()
	case resource == "*":
		return plan.LinkNo, nil
	}
	attached := s.Resources
	if s.ResourceUnknown {
		attached = []plan.AttachedResource{{Match: plan.LinkMaybe}}
	}
	best := plan.LinkNo
	var docs []*policy.Document
	for _, a := range attached {
		patterns := attachedPatterns(s.Link.Type, a)
		m := a.Match
		as := patterns
		switch {
		case resource == "":
			// The need acts on an unknown resource.
			m = plan.LinkMaybe
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
			}
		}
		if best == plan.LinkNo || m == plan.LinkYes {
			best = m
		}
		if s.Unknown {
			continue
		}
		d := doc.ForPrincipal(identity)
		switch {
		case patterns == nil:
			d = d.MayGrant(policy.ReasonResourceScope)
		case resource != "" && m == plan.LinkMaybe:
			d = d.OnResource(patterns, nil).MayGrant(policy.ReasonResourceScope)
		default:
			d = d.OnResource(patterns, as)
		}
		docs = append(docs, d)
	}
	if best == plan.LinkNo {
		return plan.LinkNo, nil
	}
	if s.Unknown {
		return best, policy.UnknownSource()
	}
	return best, policy.Merge(docs...)
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

// Set is the policies that decide one action of a principal in one account.
// Policies merges the identity policies of the principal with the resource
// policies that may apply, and Boundaries are its permissions boundaries.
//
// AWS allows a request in one account when an identity or a resource policy
// allows it and none denies it
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-rdp),
// which policy.Merge computes. A permissions boundary must allow it too:
// the identity policies and the boundary give "the intersection of the two
// categories"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-bound).
// So Set's verdict is the worst of the merged verdict and each boundary's.
type Set struct {
	Policies   *policy.Document
	Boundaries []*policy.Document
}

// Coverage reports whether the set grants action on a resource matching any
// of the target ARN patterns: the worst of the merged policies' verdict and
// each boundary's.
func (s Set) Coverage(action string, targets []string, conds policy.Conditions, strict bool) policy.Result {
	res := s.Policies.Coverage(action, targets, conds, strict)
	for _, b := range s.Boundaries {
		res = worst(res, b.Coverage(action, targets, conds, strict))
	}
	return res
}

// CoverageOfEveryResource reports whether the set grants action on every
// resource: the worst of the merged policies' verdict and each boundary's.
func (s Set) CoverageOfEveryResource(action string, strict bool) policy.Result {
	res := s.Policies.CoverageOfEveryResource(action, strict)
	for _, b := range s.Boundaries {
		res = worst(res, b.CoverageOfEveryResource(action, strict))
	}
	return res
}

// GrantedResources lists the resources the merged policies grant action
// on, when they grant it only on some. A boundary grants nothing by itself,
// so it adds none.
func (s Set) GrantedResources(action string) []string {
	return s.Policies.GrantedResources(action)
}

// worst returns the result that allows less: Missing before Unverified
// before Covered. Between two unverified results it keeps the first, so the
// reason of the merged policies comes before a boundary's.
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
