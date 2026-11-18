package plan

import "strings"

// Group membership.
//
// "You can attach an identity-based policy to a user group so that all of the
// users in the user group receive the policy's permissions", and "User groups
// can't be nested" (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html).
// So a policy of a group applies to a user through one membership: the policy
// links to the group, and a membership puts the user in the group. Groups
// decides both hops with the link rules of PolicyLink.Match.
//
// The plan is taken to list every group membership of a user in the plan, as
// it is taken to list every policy of a role. The provider has two membership
// resources. An aws_iam_user_group_membership "can be used multiple times
// with the same user for non-overlapping groups", so it doesn't own the
// user's group list. An aws_iam_group_membership owns the user list of its
// group: it "will conflict with itself if used more than once with the same
// group"
// (https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user_group_membership,
// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_membership).
// Neither lists every group of a user, so for a user outside the plan, other
// stacks may add it to groups.

// membershipTypes maps each membership resource type to the attributes that
// link it to its users and to its groups.
var membershipTypes = map[string]struct{ users, groups string }{
	"aws_iam_user_group_membership": {"user", "groups"},
	"aws_iam_group_membership":      {"users", "group"},
}

// Membership is a resource that puts IAM users in IAM groups: an
// aws_iam_user_group_membership puts one user in a list of groups, and an
// aws_iam_group_membership puts a list of users in one group.
type Membership struct {
	// Address is the terraform address of the membership resource.
	Address string
	// Users ties the membership to the users it puts in groups.
	Users PolicyLink
	// Groups ties the membership to its groups.
	Groups PolicyLink
}

// group is a group that a link may point to: a group of the plan, or a group
// outside the plan, known by its name or with no known name.
type group struct {
	change  *ResourceChange
	outside OutsidePrincipal
}

// match reports whether the link l points to the group.
func (g group) match(l PolicyLink) LinkMatch {
	if g.change != nil {
		return l.Match(g.change)
	}
	return l.MatchOutside(g.outside)
}

// id returns the address of a group of the plan, or the name of a group
// outside the plan, which is empty when the plan doesn't know it.
func (g group) id() string {
	if g.change != nil {
		return g.change.Address
	}
	return g.outside.Name
}

// Groups is what the plan shows of IAM groups: their memberships, the
// aws_iam_group resources, and the groups outside the plan that a link may
// point to.
type Groups struct {
	// Memberships are the membership resources of the plan, in plan order.
	Memberships []Membership
	// groups are the aws_iam_group resources of the plan, then a group
	// outside the plan for each known group name that names no group of the
	// plan, then a group outside the plan with no known name.
	groups []group
}

// ParseGroups reads the groups and memberships of the plan. The known group
// names come from the memberships, from the links of the policy sources, and
// from the links of the exclusive resources. A delete adds no group or
// membership.
func ParseGroups(changes []*ResourceChange, sources []PolicySource, exclusives []Exclusive) Groups {
	var out Groups
	var links []PolicyLink
	for _, rc := range changes {
		if rc.Change == "delete" {
			continue
		}
		if rc.Type == groupType {
			out.groups = append(out.groups, group{change: rc})
		}
		if t, ok := membershipTypes[rc.Type]; ok {
			m := Membership{
				Address: rc.Address,
				Users:   attributeLink(t.users, userType)(rc),
				Groups:  attributeLink(t.groups, groupType)(rc),
			}
			out.Memberships = append(out.Memberships, m)
			links = append(links, m.Groups)
		}
	}
	for _, s := range sources {
		links = append(links, s.Link)
	}
	for _, ex := range exclusives {
		links = append(links, ex.Link)
	}
	seen := map[string]bool{}
	for _, l := range links {
		if l.Type != groupType {
			continue
		}
		names := l.Values
		if names == nil && l.Value != "" {
			names = []string{l.Value}
		}
		for _, name := range names {
			if strings.HasPrefix(name, "arn:") {
				name = name[strings.LastIndex(name, "/")+1:]
			}
			key := strings.ToLower(name)
			if seen[key] || out.inPlan(name) {
				continue
			}
			seen[key] = true
			out.groups = append(out.groups, group{outside: OutsidePrincipal{Type: groupType, Name: name}})
		}
	}
	out.groups = append(out.groups, group{outside: OutsidePrincipal{Type: groupType}})
	return out
}

// inPlan reports whether an aws_iam_group of the plan has the known name.
func (g Groups) inPlan(name string) bool {
	for _, c := range g.groups {
		if c.change != nil && strings.EqualFold(c.change.AttributeValues["name"], name) {
			return true
		}
	}
	return false
}

// both is the link of two hops: LinkYes when both are LinkYes, LinkNo when
// either is LinkNo, and LinkMaybe otherwise.
func both(a, b LinkMatch) LinkMatch {
	switch {
	case a == LinkNo || b == LinkNo:
		return LinkNo
	case a == LinkYes && b == LinkYes:
		return LinkYes
	}
	return LinkMaybe
}

// either is the link of two ways: LinkYes when either is LinkYes, LinkNo
// when both are LinkNo, and LinkMaybe otherwise.
func either(a, b LinkMatch) LinkMatch {
	switch {
	case a == LinkYes || b == LinkYes:
		return LinkYes
	case a == LinkMaybe || b == LinkMaybe:
		return LinkMaybe
	}
	return LinkNo
}

// Same reports whether two links to a group point to the same group: LinkYes
// when one group provably matches both, LinkNo when no group may match both,
// and LinkMaybe otherwise.
func (g Groups) Same(a, b PolicyLink) LinkMatch {
	out := LinkNo
	for _, c := range g.groups {
		out = either(out, both(c.match(a), c.match(b)))
	}
	return out
}

// Member reports whether the link l to a group reaches a user through a
// membership of the plan. user reports whether a membership's link to its
// users points to the user. The link is the best of each membership and
// each group: both hops, membership to user and l to the group the
// membership names, as both combines them. It also returns the group of the
// best way: the address of an aws_iam_group, or the name of a group outside
// the plan.
func (g Groups) Member(l PolicyLink, user func(PolicyLink) LinkMatch) (LinkMatch, string) {
	out, id := LinkNo, ""
	for _, m := range g.Memberships {
		u := user(m.Users)
		if u == LinkNo {
			continue
		}
		for _, c := range g.groups {
			hop := both(u, both(c.match(m.Groups), c.match(l)))
			if hop == LinkNo || out == LinkYes || (out == LinkMaybe && hop == LinkMaybe) {
				continue
			}
			out, id = hop, c.id()
		}
	}
	return out, id
}

// OutsideGroup is a group that a membership may put a user in, and whose
// policies the plan may not show.
type OutsideGroup struct {
	// Membership is the membership resource.
	Membership Membership
	// Name is the group's known name. It is empty when the plan doesn't
	// know the group's name.
	Name string
	// Match says whether the membership puts the user in the group.
	Match LinkMatch
}

// OutsideGroups returns the groups whose policies the plan may not show and
// that a membership may put the user in. user reports whether a
// membership's link to its users points to the user.
//
// A group is outside the plan when no aws_iam_group of the plan may be it.
// A group known by its name is still taken to have its policies in the plan
// when a policy source of the plan provably attaches to it, or when the plan
// has an exclusive resource of each kind for it. A group whose name the plan
// doesn't know may always be outside the plan.
func (g Groups) OutsideGroups(user func(PolicyLink) LinkMatch, sources []PolicySource, exclusives []Exclusive) []OutsideGroup {
	var out []OutsideGroup
	for _, m := range g.Memberships {
		u := user(m.Users)
		if u == LinkNo {
			continue
		}
		for _, c := range g.groups {
			if c.change != nil {
				continue
			}
			hop := both(u, c.match(m.Groups))
			if hop == LinkNo || (c.outside.Name != "" && listed(c.outside, sources, exclusives)) {
				continue
			}
			out = append(out, OutsideGroup{Membership: m, Name: c.outside.Name, Match: hop})
		}
	}
	return out
}

// listed reports whether the plan is taken to show every policy of the group
// r outside the plan (see OutsideGroups).
func listed(r OutsidePrincipal, sources []PolicySource, exclusives []Exclusive) bool {
	for _, s := range sources {
		if s.Kind == KindIdentity && s.Link.MatchOutside(r) == LinkYes {
			return true
		}
	}
	kinds := map[ExclusiveKind]bool{}
	for _, ex := range exclusives {
		if ex.Link.MatchOutside(r) == LinkYes {
			kinds[ex.Kind] = true
		}
	}
	return kinds[ExclusiveInline] && kinds[ExclusiveManaged]
}
