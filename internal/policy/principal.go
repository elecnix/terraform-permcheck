package policy

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Principal matching.
//
// A resource policy names who it applies to with the Principal or NotPrincipal
// element of each statement
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html).
// ForPrincipal reads those elements for the principal a need belongs to, and
// returns the statements that apply to it, ready for Merge. An identity
// policy has no principal to match, as the policy applies to the identity it
// is attached to, so Coverage ignores both elements.

// PrincipalKind is the kind of IAM identity a need belongs to.
type PrincipalKind int

const (
	// KindRole is an IAM role.
	KindRole PrincipalKind = iota
	// KindUser is an IAM user.
	KindUser
)

// arnType returns the resource type of the kind in an IAM ARN.
func (k PrincipalKind) arnType() string {
	if k == KindUser {
		return "user"
	}
	return "role"
}

// Principal is what the tool knows about the principal a need belongs to. An
// empty string means the plan does not show the value.
type Principal struct {
	// Kind says whether the principal is a role or a user.
	Kind PrincipalKind
	// ARN is the principal's ARN, such as
	// arn:aws:iam::123456789012:role/app-task. The plan does not show it for
	// a role it creates, since AWS assigns it at apply time.
	ARN string
	// Name is the principal's name, without its path. It is unknown for a
	// role created with name_prefix. When it is empty, the name comes from
	// ARN.
	Name string
	// Account is the principal's account id. When it is empty, the account
	// comes from ARN.
	Account string
	// PermissionsBoundary reports that the plan shows a permissions boundary
	// on the principal.
	PermissionsBoundary bool
}

// name returns the principal's name, from Name or from the last part of its
// ARN, or "" when neither is known. A role with a path, as in
// role/service/app-task, has the name app-task.
func (p Principal) name() string {
	if p.Name != "" {
		return p.Name
	}
	parts := strings.SplitN(p.ARN, ":", 6)
	if len(parts) < 6 || parts[5] == "" {
		return ""
	}
	res := parts[5]
	return res[strings.LastIndex(res, "/")+1:]
}

// account returns the principal's account id, from Account or from its ARN,
// or "" when neither is known.
func (p Principal) account() string {
	if p.Account != "" {
		return p.Account
	}
	parts := strings.SplitN(p.ARN, ":", 6)
	if len(parts) < 6 || strings.ContainsAny(parts[4], "*?") {
		return ""
	}
	return parts[4]
}

// arnPatterns returns ARN patterns for the principal and for the sessions of
// its role, in lower case. A part the tool does not know is a wildcard. The
// name pattern allows for a path, since the plan may not show it.
func (p Principal) arnPatterns() []string {
	account := p.account()
	if account == "" {
		account = "*"
	}
	name := p.name()
	if name == "" {
		name = "*"
	}
	var patterns []string
	if p.ARN != "" {
		patterns = append(patterns, p.ARN)
	} else {
		prefix := "arn:*:iam::" + account + ":" + p.Kind.arnType() + "/"
		patterns = append(patterns, prefix+name, prefix+"*/"+name)
	}
	for i, pat := range patterns {
		patterns[i] = strings.ToLower(pat)
	}
	if session := p.sessionPattern(); session != "" {
		patterns = append(patterns, session)
	}
	return patterns
}

// sessionPattern returns the ARN pattern of the sessions of the principal's
// role, in lower case, or "" for a user. A part the tool does not know is a
// wildcard. A role session ARN names the role without its path
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-role-session).
func (p Principal) sessionPattern() string {
	if p.Kind != KindRole {
		return ""
	}
	account := p.account()
	if account == "" {
		account = "*"
	}
	name := p.name()
	if name == "" {
		name = "*"
	}
	return strings.ToLower("arn:*:sts::" + account + ":assumed-role/" + name + "/*")
}

// mayBe reports whether an ARN entry of a Principal element may name the
// principal or a session of its role. A wildcard in the entry matches as a
// pattern, as in Resource.
//
// The comparison folds case, and a match is only possible, never definite.
// IAM names "aren't distinguished by case, for example, you can't create
// groups named both ADMINS and admins"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-names),
// so an entry with other capitalisation can't name another principal of the
// account. But "In a Principal element, the user name part of the Amazon
// Resource Name (ARN) is case sensitive"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-users),
// and AWS doesn't say how it matches the role name part. So such an entry may
// fail to name the principal: its Allow may grant, and its Deny isn't
// definite (see grantsEntry and denies, which compare byte for byte).
func (p Principal) mayBe(entry string) bool {
	entry = strings.ToLower(entry)
	for _, pat := range p.arnPatterns() {
		if arnIntersect(entry, pat) {
			return true
		}
	}
	return false
}

// principalField is a Principal or NotPrincipal element. It reads every form
// of the IAM reference: "*", or an object whose keys AWS, Service, Federated
// and CanonicalUser each hold one string or a list. It never fails: a form the
// tool cannot read marks the element unreadable, and ForPrincipal then cannot
// compare it with the principal. Its JSON form is the text it was read from.
type principalField struct {
	// everyone reports the "*" form.
	everyone bool
	// aws holds the entries of the AWS key: "*", an account id, or an ARN.
	aws []string
	// others reports that a Service, Federated or CanonicalUser key holds an
	// entry. None of them names an IAM role or user.
	others bool
	// unreadable reports a form or a key the tool cannot read.
	unreadable bool
	raw        json.RawMessage
}

func (f *principalField) UnmarshalJSON(b []byte) error {
	*f = principalField{raw: append(json.RawMessage(nil), bytes.TrimSpace(b)...)}
	var s string
	if json.Unmarshal(b, &s) == nil {
		// "*" is the only string form AWS accepts.
		f.everyone = s == "*"
		f.unreadable = !f.everyone
		return nil
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		f.unreadable = true
		return nil
	}
	for key, value := range keys {
		var entries actionField
		if err := json.Unmarshal(value, &entries); err != nil {
			f.unreadable = true
			continue
		}
		switch key {
		case "AWS":
			f.aws = append(f.aws, entries...)
		case "Service", "Federated", "CanonicalUser":
			f.others = f.others || len(entries) > 0
		default:
			f.unreadable = true
		}
	}
	return nil
}

func (f principalField) MarshalJSON() ([]byte, error) {
	return f.raw, nil
}

// accountEntry returns the account an AWS entry names, as a bare id such as
// 123456789012 or as the root ARN arn:aws:iam::123456789012:root. The account
// may hold a wildcard.
func accountEntry(entry string) (string, bool) {
	if entry != "" && strings.Trim(entry, "0123456789*?") == "" && strings.ContainsAny(entry, "0123456789") {
		return entry, true
	}
	parts := strings.Split(entry, ":")
	if len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && parts[3] == "" && parts[5] == "root" {
		return parts[4], true
	}
	return "", false
}

// match is how an element relates to the principal.
type match int

const (
	// matchNone means the element provably does not name the principal.
	matchNone match = iota
	// matchMaybe means the tool cannot tell whether it does.
	matchMaybe
	// matchYes means the element names the principal.
	matchYes
)

// PrincipalOption changes how ForPrincipal reads a statement.
type PrincipalOption func(*principalOptions)

type principalOptions struct {
	// accountGrants makes a statement whose Principal is the principal's
	// account grant the principal.
	accountGrants bool
	// beyondBoundary keeps only the Allow statements whose grant a
	// permissions boundary doesn't limit.
	beyondBoundary bool
}

// ResourceSide makes ForPrincipal read a resource policy for the resource
// side of a request that the identity side must allow on its own. There, a
// statement whose Principal is the principal's account grants, since the
// identity side checks the account's IAM policies. An account the tool
// cannot compare with the principal's may grant. Two evaluations have that
// shape:
//
//   - A cross-account request: "AWS performs two evaluations" and "The
//     request is allowed only if both evaluations return a decision of
//     Allow"
//     (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html).
//   - A KMS key policy, whose account statement lets the account "use IAM
//     policies to delegate the permissions specified in the key policy"
//     (https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html#key-policy-elements).
func ResourceSide() PrincipalOption {
	return func(o *principalOptions) { o.accountGrants = true }
}

// BeyondBoundary makes ForPrincipal keep only the Allow statements of a
// resource policy whose grant a permissions boundary of the principal doesn't
// limit. In one account, "Resource-based policies that grant permissions to
// an IAM role ARN are limited by an implicit deny in a permissions boundary",
// while "Permissions granted directly to a session are not limited by an
// implicit deny in an identity-based policy, a permissions boundary, or
// session policy", and a grant to "an IAM user ARN (that is not a federated
// user session) [is] not limited by an implicit deny in an identity-based
// policy or permissions boundary"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).
// So a statement is kept when its Principal names the user, or may name a
// session of the role. An account entry grants through the identity
// policies, which the boundary limits, so it is dropped.
//
// A statement whose Principal is "*" grants the session that makes the
// request. The same page says that a boundary doesn't limit a grant through
// the aws:PrincipalArn condition key with "*" in the Principal element, and
// it doesn't say more about "*" alone. So such a statement, and one whose
// Principal the tool can't compare, is kept marked as a grant the tool can't
// check. A Deny is dropped: the caller applies each Deny of the policies
// apart, as an explicit Deny in any policy denies the request.
func BeyondBoundary() PrincipalOption {
	return func(o *principalOptions) { o.beyondBoundary = true }
}

// ForPrincipal returns the statements of a resource policy that apply to the
// principal, in order, ready for Merge. It keeps each statement as it is,
// keeps it marked with Statement.Unverified and ReasonCondition, or drops it:
//
//   - An Allow whose Principal names the principal is kept. One that may
//     name it is kept marked, so that it counts as coverage by default and
//     is unverified under --strict-resources. Any other Allow is dropped.
//   - A Deny is kept only when it is definite for the principal, and dropped
//     otherwise, as Coverage ignores a conditional Deny.
//   - A NotPrincipal Allow is dropped. A NotPrincipal Deny is kept unless its
//     list may exclude the principal.
//   - A statement with neither element is a statement of a policy that AWS
//     rejects for most services. The tool cannot prove that the service
//     rejects it, so its Allow is kept marked and its Deny is dropped.
//   - A statement with both elements is not valid. Its Allow and its Deny
//     are dropped.
//
// The statement's Resource is left as it is. In a resource policy it applies
// only to the resource the policy is attached to, so the caller replaces it
// before the merge.
//
// The account principal grants nothing to the principal by itself in one
// account: it "delegates authority to the account" and the account's
// administrator "must then grant access to an identity"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-accounts).
// ResourceSide changes that for the resource side of a two-sided
// evaluation.
func (d *Document) ForPrincipal(p Principal, opts ...PrincipalOption) *Document {
	var o principalOptions
	for _, opt := range opts {
		opt(&o)
	}
	out := &Document{Version: d.Version}
	for _, s := range d.Statements {
		switch o.decide(s, p) {
		case matchYes:
			out.Statements = append(out.Statements, s)
		case matchMaybe:
			out.Statements = append(out.Statements, s.Unverified(firstReason(s.unverified, ReasonCondition)))
		}
	}
	return out
}

// decide returns matchYes to keep the statement as it is, matchMaybe to keep
// it marked as a grant the tool cannot check, and matchNone to drop it.
func (o principalOptions) decide(s Statement, p Principal) match {
	if o.beyondBoundary {
		return beyondBoundary(s, p)
	}
	switch {
	case s.Principal != nil && s.NotPrincipal != nil:
		return matchNone
	case s.NotPrincipal != nil:
		if s.Effect == "Deny" && notPrincipalDenies(*s.NotPrincipal, p) {
			return matchYes
		}
		// AWS does not support NotPrincipal with Allow: "Using it with
		// "Effect":"Allow" is not supported"
		// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html).
		return matchNone
	case s.Principal != nil:
		switch s.Effect {
		case "Allow":
			return o.grants(*s.Principal, p)
		case "Deny":
			if denies(*s.Principal, p) {
				return matchYes
			}
		}
		return matchNone
	case s.Effect == "Allow":
		return matchMaybe
	}
	return matchNone
}

// beyondBoundary decides a statement for BeyondBoundary.
func beyondBoundary(s Statement, p Principal) match {
	switch {
	case s.Effect != "Allow" || s.NotPrincipal != nil:
		return matchNone
	case s.Principal == nil:
		// A resource policy statement without a Principal is one the tool
		// can't compare (see ForPrincipal).
		return matchMaybe
	}
	f := *s.Principal
	if f.everyone || f.unreadable {
		return matchMaybe
	}
	best := matchNone
	for _, e := range f.aws {
		if m := unboundedEntry(e, p); m > best {
			best = m
		}
	}
	return best
}

// unboundedEntry reports whether an AWS entry of an Allow grants the
// principal in a way a permissions boundary doesn't limit (see
// BeyondBoundary).
func unboundedEntry(e string, p Principal) match {
	if e == "*" {
		return matchMaybe
	}
	if _, ok := accountEntry(e); ok {
		return matchNone
	}
	if !strings.HasPrefix(e, "arn:") {
		// An entry the tool can't compare, such as a unique id.
		return matchMaybe
	}
	if p.Kind == KindUser {
		switch {
		case p.ARN != "" && e == p.ARN:
			return matchYes
		case p.mayBe(e):
			return matchMaybe
		}
		return matchNone
	}
	if session := p.sessionPattern(); session != "" && arnIntersect(strings.ToLower(e), session) {
		return matchMaybe
	}
	return matchNone
}

// grants reports whether an Allow with the Principal element grants the
// principal. Of the forms in the Principal element page
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html):
//
//   - "*" and {"AWS": "*"} grant. A wildcard Allow grants IAM users and
//     roles in the resource's account access by itself
//     (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-anonymous).
//   - The principal's ARN grants.
//   - An account grants nothing in one account (see ForPrincipal).
//   - An ARN that may name the principal or a session of its role may grant.
//     So does an ARN whose name matches while the account is unknown, an
//     entry with a wildcard that may match, and an entry the tool cannot
//     compare, such as a unique id.
//   - A service, a federated provider, a canonical user and another
//     principal's ARN grant nothing to the principal.
func (o principalOptions) grants(f principalField, p Principal) match {
	if f.everyone {
		return matchYes
	}
	best := matchNone
	if f.unreadable {
		best = matchMaybe
	}
	for _, e := range f.aws {
		if m := o.grantsEntry(e, p); m > best {
			best = m
		}
	}
	return best
}

func (o principalOptions) grantsEntry(e string, p Principal) match {
	if e == "*" {
		return matchYes
	}
	if account, ok := accountEntry(e); ok {
		if !o.accountGrants {
			return matchNone
		}
		return accountMatch(account, p)
	}
	if !strings.HasPrefix(e, "arn:") {
		return matchMaybe
	}
	if p.ARN != "" && e == p.ARN {
		return matchYes
	}
	if p.mayBe(e) {
		return matchMaybe
	}
	return matchNone
}

// accountMatch compares an account entry, which may hold a wildcard, with the
// principal's account.
func accountMatch(account string, p Principal) match {
	own := p.account()
	switch {
	case own == "":
		return matchMaybe
	case account == own:
		return matchYes
	case globContains(account, own):
		return matchMaybe
	}
	return matchNone
}

// denies reports whether a Deny with the Principal element is definite for
// the principal: it names every principal, the principal's ARN, or the
// principal's account, which takes in every identity of the account. An
// explicit Deny that applies overrides every Allow
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).
// An entry that only may name the principal does not make a Deny definite.
// That includes the principal's ARN with other capitalisation, since AWS
// documents the name part of a user ARN in a Principal element as case
// sensitive and doesn't document role names there (see Principal.mayBe).
func denies(f principalField, p Principal) bool {
	if f.everyone {
		return true
	}
	own := p.account()
	for _, e := range f.aws {
		if e == "*" || (p.ARN != "" && e == p.ARN) {
			return true
		}
		if account, ok := accountEntry(e); ok && own != "" && account == own {
			return true
		}
	}
	return false
}

// notPrincipalDenies reports whether a Deny with the NotPrincipal element is
// definite for the principal. Such a Deny denies "all principals except the
// principal specified"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html).
//
// It "will always deny any IAM principal that has a permissions boundary
// policy attached, regardless of the values specified in the NotPrincipal
// element"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html#notprincipal-key-points),
// so it is definite for a principal with a boundary. Otherwise it is definite
// unless the list may exclude the principal (see mayExclude).
func notPrincipalDenies(f principalField, p Principal) bool {
	if p.PermissionsBoundary {
		return true
	}
	return !mayExclude(f, p)
}

// mayExclude reports whether a NotPrincipal list may exclude the principal.
// It may when it holds the principal's ARN, a session of its role, its
// account, an account the tool cannot compare with the principal's, an ARN
// whose name matches while the account is unknown, or an entry the tool
// cannot read. AWS "might validate the account first, then the role, and then
// the assumed-role user", so a list that holds the role but not its account
// may still deny it. The tool cannot prove that it does, so such a list may
// exclude the principal too.
//
// The Principal element page says a wildcard cannot match part of a
// principal name or ARN
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html),
// but the NotPrincipal page does not say how AWS treats such an entry. The
// tool matches it as a pattern, and a possible match may exclude the
// principal. Otherwise a wildcard that spares the principal would turn a
// granted need into a false Missing verdict.
func mayExclude(f principalField, p Principal) bool {
	if f.everyone || f.unreadable {
		return true
	}
	for _, e := range f.aws {
		if e == "*" {
			return true
		}
		if account, ok := accountEntry(e); ok {
			if accountMatch(account, p) != matchNone {
				return true
			}
			continue
		}
		if !strings.HasPrefix(e, "arn:") || p.mayBe(e) {
			return true
		}
	}
	return false
}
