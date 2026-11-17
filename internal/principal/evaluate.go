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
	// Match says whether the source attaches to the principal. A resource
	// policy is LinkMaybe, since this version doesn't read the Principal
	// element of its statements. So is a source whose attached ARN may name
	// another policy (see plan.PolicySource.PolicyMaybe), and a source that
	// an exclusive resource of the role may remove (see Check).
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
// policies: for each action, it builds the principal's policy set (see Set)
// and runs the action through iam.CheckNeedsWith, the path the needs of a
// --policy-* document take.
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

	applied := make([]plan.LinkMatch, len(sources))
	grantsFor := func(action string) iam.Grants {
		var set Set
		var merged []*policy.Document
		for i, s := range sources {
			m := links[i]
			if s.Kind == plan.KindResource {
				m = resourceLink(s, action)
			}
			if m == plan.LinkNo {
				continue
			}
			applied[i] = m
			switch {
			case s.Kind == plan.KindBoundary:
				// No boundary type is read yet, so every boundary is an
				// unknown source. It can only remove permissions.
				set.Boundaries = append(set.Boundaries, policy.UnknownSource())
			case s.Kind == plan.KindResource:
				// This version doesn't read the Principal element of a
				// resource policy, so it can't tell whom the policy grants.
				// Every resource policy that may apply is an unknown source,
				// whether or not the plan shows its text.
				merged = append(merged, policy.UnknownSource())
			case s.Unknown:
				merged = append(merged, policy.UnknownSource())
			case m == plan.LinkMaybe:
				merged = append(merged, mayGrant(docs[i]))
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

// resourceLink reports whether a resource policy may apply to an action: it
// does when its service is the service of the action. A later version
// narrows that by the resource ARN and by the Principal element of each
// statement.
func resourceLink(s plan.PolicySource, action string) plan.LinkMatch {
	service, _, _ := strings.Cut(action, ":")
	if strings.EqualFold(service, s.Service) {
		return plan.LinkMaybe
	}
	return plan.LinkNo
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

// mayGrant returns the statements of a source whose link to the principal
// is undecidable. Its Allows count, marked as grants the tool can't check,
// and its Denies don't, since the source may not apply to the principal
// (design of issue #175, "Undecidable overlaps in the new cases"). The
// marked Allows make a need they cover unverified under --strict-resources,
// with the reason condition.
func mayGrant(doc *policy.Document) *policy.Document {
	out := &policy.Document{Version: doc.Version}
	for _, s := range doc.Statements {
		if s.Effect == "Allow" {
			out.Statements = append(out.Statements, s.Unverified(policy.ReasonCondition))
		}
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
