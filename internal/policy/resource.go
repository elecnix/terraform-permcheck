package policy

import "strings"

// Resource policies.
//
// A resource policy is attached to one resource, such as a secret, and its
// statements apply to that resource only. Secrets Manager says so for the
// Resource element: in a resource policy it can be "*", which means the
// secret the policy is attached to
// (https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html).
// Coverage reads Resource as the identity policies use it, so OnResource
// rewrites each statement to name the attached resource before the merge.
// Without that step, a secret's "Resource": "*" would grant the action on
// every resource.

// OnResource returns the statements of a resource policy as statements on
// the resource the policy is attached to, ready for Merge. attached holds the
// ARN patterns of that resource: its ARN when the plan knows it, or the
// target pattern the tool builds from its known attributes, such as a
// secret's name followed by AWS's random suffix. It must not be empty.
//
// as holds the patterns that a statement on the whole attached resource
// gets. It is attached itself, or the need's resource when the caller has
// decided that the need's resource is the attached resource. The need's
// resource may then be wider than the attached pattern, as
// secret:app-db-* is wider than secret:app-db-??????, and a Deny on the
// whole secret must still cover the need. A nil as means attached.
//
// The rewrite never widens a statement beyond what it grants or denies on
// the attached resource:
//
//   - A Resource pattern that contains the attached resource, such as "*",
//     becomes as.
//   - A Resource pattern inside the attached resource, such as the secret's
//     full ARN under a target pattern, stays as it is.
//   - A Resource pattern that provably shares no ARN with the attached
//     resource names nothing the policy can grant on. A statement left with
//     no pattern is dropped.
//   - A Resource pattern that overlaps the attached resource in another way
//     is narrowed segment by segment (see intersectPattern). When the
//     narrowed pattern may still name more than the overlap, the statement
//     is marked with Statement.Unverified and ReasonResourceScope. Its Allow
//     is then a grant the tool can't check, and its Deny is never definite.
//   - A NotResource statement whose list provably contains the attached
//     resource doesn't apply, so it is dropped. One whose list provably
//     shares no ARN with it applies to the whole resource and becomes a
//     statement on as. Any other one becomes a statement on as, marked as
//     above.
//   - A statement without Resource and NotResource applies to the whole
//     attached resource.
func (d *Document) OnResource(attached, as []string) *Document {
	if as == nil {
		as = attached
	}
	out := &Document{Version: d.Version}
	for _, s := range d.Statements {
		if t, ok := onResource(s, attached, as); ok {
			out.Statements = append(out.Statements, t)
		}
	}
	return out
}

// onResource rewrites one statement for OnResource. It reports false when
// the statement doesn't apply to the attached resource.
func onResource(s Statement, attached, as []string) (Statement, bool) {
	exact := true
	var resources []string
	seen := map[string]bool{}
	add := func(patterns ...string) {
		for _, x := range patterns {
			if !seen[x] {
				seen[x] = true
				resources = append(resources, x)
			}
		}
	}
	if len(s.NotResource) > 0 {
		for _, n := range s.NotResource {
			for _, p := range attached {
				if globContains(n, inPartitionOf(p, n)) {
					return s, false
				}
				if arnIntersect(n, p) {
					exact = false
				}
			}
		}
		add(as...)
	} else {
		own := []string(s.Resource)
		if len(own) == 0 {
			own = []string{"*"}
		}
		for _, r := range own {
			for _, p := range attached {
				x, whole, ex, ok := intersectPattern(r, p)
				switch {
				case !ok:
					continue
				case whole:
					add(as...)
				default:
					add(x)
				}
				exact = exact && ex
			}
		}
		if len(resources) == 0 {
			return s, false
		}
	}
	s.Resource = resources
	s.NotResource = nil
	if !exact {
		s.unverified = firstReason(s.unverified, ReasonResourceScope)
	}
	return s, true
}

// intersectPattern compares a statement's Resource pattern r with the
// attached resource's pattern p. It reports false as its last result when
// the two provably share no ARN. It reports whole when r contains p, so the
// statement applies to the whole attached resource. Otherwise it returns a
// pattern for the ARNs the two share, and whether that pattern is exact.
//
// p takes the partition that r names when its own is unknown (see
// inPartitionOf). When p contains r, r is exact. Otherwise the patterns are
// compared segment by segment, and the narrower segment of each pair is
// kept. A pair where neither segment contains the other keeps p's segment,
// which is wider than the overlap, so the pattern isn't exact.
func intersectPattern(r, p string) (x string, whole, exact, ok bool) {
	if !arnIntersect(r, p) {
		return "", false, false, false
	}
	p = inPartitionOf(p, r)
	switch {
	case globContains(r, p):
		return p, true, true, true
	case globContains(p, r):
		return r, false, true, true
	}
	rs, ps := strings.Split(r, ":"), strings.Split(p, ":")
	if len(rs) != len(ps) {
		return p, true, false, true
	}
	exact = true
	out := make([]string, len(ps))
	for i := range ps {
		switch {
		case globContains(rs[i], ps[i]):
			out[i] = ps[i]
		case globContains(ps[i], rs[i]):
			out[i] = rs[i]
		default:
			out[i] = ps[i]
			exact = false
		}
	}
	return strings.Join(out, ":"), false, exact, true
}

// MayGrant returns the Allow statements of the document, marked with
// Statement.Unverified as grants the tool can't check, and drops its Deny
// statements. A statement that already carries a reason keeps the one
// firstReason picks. It is the document of a policy that may not apply,
// such as a source whose link to the principal is undecidable, or a
// resource policy whose resource may not be the need's resource: its Allows
// count as coverage by default, and its Denies can't be shown to apply.
func (d *Document) MayGrant(reason UnverifiedReason) *Document {
	out := &Document{Version: d.Version}
	for _, s := range d.Statements {
		if s.Effect == "Allow" {
			s.unverified = firstReason(s.unverified, reason)
			out.Statements = append(out.Statements, s)
		}
	}
	return out
}
