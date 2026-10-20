package iam

import (
	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// Implied requirements.
//
// Some permissions are checked by AWS at apply time though the provider never
// calls them, so no schema lists them: iam:PassRole on the role a resource
// hands to a service, the callback a web ACL association makes into its
// target's service, and the service-linked role a service creates on first
// use. impliedRequirements describes each one as a requirement
// with the resources it acts on. Validate appends them to the schema's
// requirements, and every requirement then goes through the same gates,
// classification, coverage check and filters.

// targeted is a requirement with the resources its action acts on.
type targeted struct {
	Requirement
	// targets lists the resources the action acts on, one list of ARN
	// patterns per resource. Nil means the plan does not show them, and the
	// action alone decides coverage.
	targets [][]string
	// knownTargetsOnly drops a missing verdict when targets is nil. The
	// resource may act on no target at all, so only a grant checked against
	// a known target, or a grant scoped elsewhere under --strict-resources,
	// counts against the policy.
	knownTargetsOnly bool
}

// withTargets pairs each requirement with the same targets.
func withTargets(reqs []Requirement, targets [][]string) []targeted {
	out := make([]targeted, len(reqs))
	for i, r := range reqs {
		out[i] = targeted{Requirement: r, targets: targets}
	}
	return out
}

// impliedRequirements returns the requirements AWS adds to resource change
// rc beyond the calls the provider makes.
func impliedRequirements(rc *plan.ResourceChange, set *changeSet) []targeted {
	reqs := append(passRoleRequirements(rc, set), crossServiceRequirements(rc, set)...)
	reqs = append(reqs, serviceLinkedRoleRequirements(rc)...)
	return append(reqs, instanceProfileDetachRequirements(rc, set)...)
}

// instanceProfileDetachRequirements returns iam:RemoveRoleFromInstanceProfile
// when an aws_iam_role delete has co-deleted aws_iam_instance_profile resources
// in the plan that name this role. The provider calls RemoveRoleFromInstanceProfile
// only when ListInstanceProfilesForRole returns non-empty; a co-deleted profile
// is direct evidence that the role has at least one instance profile to detach.
//
// This handles the common Terraform case where both the role and its profiles
// are managed together. Roles that have profiles outside the plan still need
// the permission, but there is no plan-level signal to detect them from.
func instanceProfileDetachRequirements(rc *plan.ResourceChange, set *changeSet) []targeted {
	if rc.Type != "aws_iam_role" || rc.Change != "delete" {
		return nil
	}
	roleName := rc.AttributeValues["name"]
	for _, profile := range set.allByType("aws_iam_instance_profile") {
		if profile.Change != "delete" {
			continue
		}
		if roleName != "" && profile.AttributeValues["role"] == roleName {
			return []targeted{{Requirement: Requirement{Action: "iam:RemoveRoleFromInstanceProfile"}}}
		}
		for _, ref := range referencedChanges(profile, set, "role", "aws_iam_role") {
			if ref == rc {
				return []targeted{{Requirement: Requirement{Action: "iam:RemoveRoleFromInstanceProfile"}}}
			}
		}
	}
	return nil
}

// verdict returns the policy's verdict on a requirement: whether the policy
// grants its action on each of its targets.
func (t targeted) verdict(doc *policy.Document, strict bool) policy.Verdict {
	v := doc.WorstVerdict(t.Action, t.targets, strict)
	if v == policy.Missing && t.knownTargetsOnly && len(t.targets) == 0 {
		return policy.Covered
	}
	return v
}

// actionPaths is an action with every path that reaches it.
type actionPaths struct {
	action string
	paths  []targeted
}

// pathsByAction groups requirements by action, in the order each action first
// appears.
func pathsByAction(reqs []targeted) []actionPaths {
	var out []actionPaths
	index := make(map[string]int, len(reqs))
	for _, r := range reqs {
		i, ok := index[r.Action]
		if !ok {
			i = len(out)
			index[r.Action] = i
			out = append(out, actionPaths{action: r.Action})
		}
		out[i].paths = append(out[i].paths, r)
	}
	return out
}

// gates returns the gate of each path.
func (a actionPaths) gates() []Gate {
	gates := make([]Gate, len(a.paths))
	for i, p := range a.paths {
		gates[i] = p.Gate
	}
	return gates
}

// verdict returns the worst verdict over the paths that run for rc.
func (a actionPaths) verdict(rc *plan.ResourceChange, doc *policy.Document, strict bool) policy.Verdict {
	worst := policy.Covered
	for _, p := range a.paths {
		if !p.holds(rc) {
			continue
		}
		switch p.verdict(doc, strict) {
		case policy.Missing:
			return policy.Missing
		case policy.Unverified:
			worst = policy.Unverified
		}
	}
	return worst
}
