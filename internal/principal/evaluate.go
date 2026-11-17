package principal

import (
	"fmt"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// Principal is a role that the config's principals map gives a label, as
// the plan shows it.
type Principal struct {
	// Label is the key of the principals map, which the needs of the role
	// use as their principal.
	Label string
	// Role is the change of the role in the plan (see Find).
	Role *plan.ResourceChange
}

// Applied is a policy source that may apply to a checked need of a
// principal.
type Applied struct {
	plan.PolicySource
	// Match says whether the source attaches to the principal. A resource
	// policy is LinkMaybe, since this version doesn't read the Principal
	// element of its statements. So is a source whose attached ARN may name
	// another policy (see plan.PolicySource.PolicyMaybe).
	Match plan.LinkMatch
}

// Result is the outcome of Check.
type Result struct {
	// Missing are the need actions that the policies don't grant, or that
	// they grant only where the tool can't check the grant. Each one
	// carries the principal's label.
	Missing []iam.MissingAction
	// Sources are the policy sources that may apply to at least one checked
	// action, in plan order.
	Sources []Applied
}

// Check checks the needs of the principal against the policy sources of the
// plan. It is the one entry point for the evaluation of a principal's
// policies: for each action, it builds the principal's policy set (see Set)
// and runs the action through iam.CheckNeedsWith, the path the needs of a
// --policy-* document take.
//
// It returns an error when the plan shows a policy text that doesn't parse.
func Check(p Principal, needs []iam.Need, sources []plan.PolicySource, strict bool) (Result, error) {
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

	applied := make([]plan.LinkMatch, len(sources))
	grantsFor := func(action string) iam.Grants {
		var set Set
		var merged []*policy.Document
		for i, s := range sources {
			m := applies(s, p.Role, action)
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
		set.Policies = policy.Merge(merged...)
		return set
	}

	missing := iam.CheckNeedsWith(needs, grantsFor, strict)
	for i := range missing {
		missing[i].Principal = p.Label
	}
	res := Result{Missing: missing}
	for i, m := range applied {
		if m != plan.LinkNo {
			res.Sources = append(res.Sources, Applied{PolicySource: sources[i], Match: m})
		}
	}
	return res, nil
}

// applies reports whether a policy source may apply to an action of the
// principal role. An identity policy or a boundary applies when its link
// matches the role. A resource policy applies when its service is the
// service of the action. A later version narrows that by the resource ARN
// and by the Principal element of each statement.
func applies(s plan.PolicySource, role *plan.ResourceChange, action string) plan.LinkMatch {
	if s.Kind == plan.KindResource {
		service, _, _ := strings.Cut(action, ":")
		if strings.EqualFold(service, s.Service) {
			return plan.LinkMaybe
		}
		return plan.LinkNo
	}
	m := s.Link.Match(role)
	if m == plan.LinkYes && s.PolicyMaybe {
		// The role attaches the ARN, and the ARN may name another policy.
		return plan.LinkMaybe
	}
	return m
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
