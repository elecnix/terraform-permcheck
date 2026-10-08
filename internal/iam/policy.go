// Package iam parses IAM policy documents and validates that required
// permissions are covered.
package iam

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PolicyDocument is a parsed IAM policy.
type PolicyDocument struct {
	Version    string        `json:"Version"`
	Statements statementList `json:"Statement"`
}

// Statement is a single IAM policy statement. A statement names its actions
// with Action or NotAction, and its resources with Resource or NotResource.
type Statement struct {
	Sid         string                     `json:"Sid,omitempty"`
	Effect      string                     `json:"Effect"`
	Action      actionField                `json:"Action,omitempty"`
	NotAction   actionField                `json:"NotAction,omitempty"`
	Resource    resourceField              `json:"Resource,omitempty"`
	NotResource resourceField              `json:"NotResource,omitempty"`
	Condition   map[string]json.RawMessage `json:"Condition,omitempty"`
}

// statementList handles a Statement given as one object or as an array.
type statementList []Statement

func (l *statementList) UnmarshalJSON(b []byte) error {
	var one Statement
	if err := json.Unmarshal(b, &one); err == nil {
		*l = []Statement{one}
		return nil
	}
	var many []Statement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

// actionField handles the union of string and []string in JSON.
type actionField []string

func (a *actionField) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = []string{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return err
	}
	*a = ss
	return nil
}

// resourceField handles the union of string and []string in JSON.
type resourceField []string

func (r *resourceField) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*r = []string{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return err
	}
	*r = ss
	return nil
}

// ParsePolicy parses a raw IAM policy JSON document.
func ParsePolicy(raw []byte) (*PolicyDocument, error) {
	var doc PolicyDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse IAM policy: %w", err)
	}
	// AWS reads Effect case-sensitively and rejects a document with any
	// other value, so a typo here would make the tool and AWS disagree.
	for i, s := range doc.Statements {
		if s.Effect != "Allow" && s.Effect != "Deny" {
			return nil, fmt.Errorf("parse IAM policy: statement %d: Effect must be \"Allow\" or \"Deny\", got %q", i, s.Effect)
		}
	}
	return &doc, nil
}

// AllowedActions returns the set of actions allowed by this policy
// (all "Allow" statements flattened, with wildcard expansion noted).
func (d *PolicyDocument) AllowedActions() map[string]bool {
	allowed := make(map[string]bool)
	for _, s := range d.Statements {
		if s.Effect != "Allow" {
			continue
		}
		for _, a := range s.Action {
			allowed[a] = true
		}
	}
	return allowed
}

// Covers reports whether the policy allows action when the target resource is
// unknown. An Allow statement that names the action counts, whatever its
// Resource or Condition, because the tool reports only provable gaps. A Deny
// statement overrides it only when the deny is definite: it names the action,
// applies to every resource ("Resource": "*"), and has no Condition.
func (d *PolicyDocument) Covers(action string) bool {
	allowed := false
	for _, s := range d.Statements {
		if !s.matchesAction(action) {
			continue
		}
		switch s.Effect {
		case "Deny":
			if !s.conditional() && s.deniesEveryResource() {
				return false
			}
		case "Allow":
			allowed = true
		}
	}
	return allowed
}

// conditional reports whether the statement carries a Condition. The tool
// cannot evaluate condition keys, so a conditional Deny never counts as a
// definite deny, and a conditional Allow still counts as an allow: either way
// only provable gaps are reported. An empty Condition block sets no condition.
func (s Statement) conditional() bool {
	return len(s.Condition) > 0
}

// matchesAction reports whether the statement names action, through Action or
// through the complement of NotAction.
func (s Statement) matchesAction(action string) bool {
	if len(s.NotAction) > 0 {
		return !coversAny(s.NotAction, action)
	}
	return coversAny(s.Action, action)
}

// deniesEveryResource reports whether the statement's Resource matches every
// ARN. A NotResource list can never be shown to exclude nothing.
func (s Statement) deniesEveryResource() bool {
	for _, r := range s.Resource {
		if globContains(r, "*") {
			return true
		}
	}
	return false
}

// mayApplyTo reports whether the statement can apply to a resource matching
// the target pattern. It returns false only when the statement provably
// excludes the target: no Resource pattern overlaps it, or a NotResource
// pattern contains it. forms lists every ARN form of the same target; a
// Resource pattern is compared with target only when target is one of the
// forms with the pattern's segment count (see targetsLike).
func (s Statement) mayApplyTo(target string, forms []string) bool {
	if len(s.NotResource) > 0 {
		for _, r := range s.NotResource {
			if globContains(r, target) {
				return false
			}
		}
		return true
	}
	for _, r := range s.Resource {
		if !containsString(targetsLike(r, forms), target) {
			continue
		}
		if arnIntersect(r, target) {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// appliesToAll reports whether the statement provably applies to every
// resource matching the target pattern: a Resource pattern contains the
// target, or no NotResource pattern can overlap it. The overlap test is
// arnIntersect, which compares segment by segment because a * in a target
// pattern stands for one segment (a region or an account).
func (s Statement) appliesToAll(target string) bool {
	if len(s.NotResource) > 0 {
		for _, r := range s.NotResource {
			if arnIntersect(r, target) {
				return false
			}
		}
		return true
	}
	for _, r := range s.Resource {
		if globContains(r, target) {
			return true
		}
	}
	return false
}

// coversAny returns true if any action pattern in the list matches the target.
func coversAny(actions []string, target string) bool {
	for _, a := range actions {
		if matchesWildcard(a, target) {
			return true
		}
	}
	return false
}

// matchesWildcard reports whether an IAM action pattern matches an action.
// The pattern may use * (any run of characters) and ? (one character)
// anywhere, as in "secretsmanager:*SecretValue". IAM action names are
// case-insensitive, so the comparison folds case.
func matchesWildcard(pattern, action string) bool {
	return globContains(strings.ToLower(pattern), strings.ToLower(action))
}

// globContains reports whether every string matched by inner is also matched
// by outer. Both use * and ?. When inner has no wildcards, this is ordinary
// glob matching of the string inner. The comparison is case-sensitive, as ARN
// matching is.
//
// The check aligns inner's elements with outer's: an outer * absorbs any run
// of inner elements, an outer ? absorbs one inner literal or ?, and an outer
// literal absorbs the same inner literal. An inner * can only be absorbed by
// an outer *. A false result can mean the containment holds but is not shown
// this way, so callers treat false as "not proven".
func globContains(outer, inner string) bool {
	// reach[i][j]: outer[:i] can absorb inner[:j].
	reach := make([][]bool, len(outer)+1)
	for i := range reach {
		reach[i] = make([]bool, len(inner)+1)
	}
	reach[0][0] = true
	for i := 0; i <= len(outer); i++ {
		for j := 0; j <= len(inner); j++ {
			if !reach[i][j] || i == len(outer) {
				continue
			}
			o := outer[i]
			if o == '*' {
				// Match nothing, or absorb inner[j] and stay on the *.
				reach[i+1][j] = true
				if j < len(inner) {
					reach[i][j+1] = true
				}
				continue
			}
			if j == len(inner) {
				continue
			}
			c := inner[j]
			if (o == '?' && c != '*') || (o == c && c != '*' && c != '?') {
				reach[i+1][j+1] = true
			}
		}
	}
	return reach[len(outer)][len(inner)]
}

// grantsOnlyOnScopedResources reports whether every Allow statement that names
// action limits it to some resources: a Resource list without a pattern that
// matches every ARN, or a NotResource list. Such a grant covers the action only
// for the right target, so without a target ARN the tool cannot confirm it.
// It returns false when no Allow statement names the action.
func (d *PolicyDocument) grantsOnlyOnScopedResources(action string) bool {
	scoped := false
	for _, s := range d.Statements {
		if s.Effect != "Allow" || !s.matchesAction(action) {
			continue
		}
		if s.grantsEveryResource() {
			return false
		}
		scoped = true
	}
	return scoped
}

// grantsEveryResource reports whether a Resource pattern matches every ARN,
// such as "*" or "arn:*".
func (s Statement) grantsEveryResource() bool {
	if len(s.NotResource) > 0 {
		return false
	}
	for _, r := range s.Resource {
		if globContains(r, "arn:*") {
			return true
		}
	}
	return false
}
