// Package policy parses IAM policy documents and decides whether a policy
// grants an action, on a resource when the caller knows its ARN. It depends
// on nothing else in this module.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Document is a parsed IAM policy.
type Document struct {
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

// The first byte picks the form, so a malformed statement reports the error
// of the form it was written in.
func (l *statementList) UnmarshalJSON(b []byte) error {
	if t := bytes.TrimLeft(b, " \t\r\n"); len(t) > 0 && t[0] == '[' {
		var many []Statement
		if err := json.Unmarshal(b, &many); err != nil {
			return err
		}
		*l = many
		return nil
	}
	var one Statement
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*l = []Statement{one}
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

// Parse parses a raw IAM policy JSON document.
func Parse(raw []byte) (*Document, error) {
	var doc Document
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

// Covers reports whether the policy allows action when the target resource is
// unknown. An Allow statement that names the action counts, whatever its
// Resource or Condition, because the tool reports only provable gaps. A Deny
// statement overrides it only when the deny is definite: it names the action,
// applies to every resource (a Resource such as "*", "arn:*" or "arn:aws:*"),
// and has no Condition. An action that takes no resource is matched against
// "*" by AWS, which an arn: pattern does not match. The tool cannot tell such
// actions apart, so it may report one as missing behind an arn:* Deny.
func (d *Document) Covers(action string) bool {
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
// ARN, such as "*", "arn:*" or "arn:aws:*". A NotResource list can never be
// shown to exclude nothing.
func (s Statement) deniesEveryResource() bool {
	for _, r := range s.Resource {
		if globContains(r, inPartitionOf(anyARN, r)) {
			return true
		}
	}
	return false
}

// anyARN stands for an ARN the plan does not show. Every ARN has at least
// six segments.
const anyARN = "arn:*:*:*:*:*"

// inPartitionOf returns the target pattern in the partition that a policy
// pattern names, when the target's partition is unknown.
//
// The plan does not show the partition a resource lives in, so a target
// pattern starts with arn:*. A policy is written for the partition it
// deploys to, so a statement on arn:aws:sqs:*:*:* is taken to reach every
// queue the plan creates. Without this, a Deny that names its partition could
// never be shown to apply, and a definite gap would pass. A pattern whose
// partition holds a wildcard leaves the target as it is.
func inPartitionOf(target, pattern string) string {
	rest, ok := strings.CutPrefix(target, "arn:*:")
	if !ok {
		return target
	}
	parts := strings.SplitN(pattern, ":", 3)
	if len(parts) < 3 || parts[0] != "arn" || parts[1] == "" || strings.ContainsAny(parts[1], "*?") {
		return target
	}
	return "arn:" + parts[1] + ":" + rest
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
// pattern stands for one segment (a region or an account). A target's unknown
// partition takes the partition a Resource pattern names (see inPartitionOf).
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
		if globContains(r, inPartitionOf(target, r)) {
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
func (d *Document) grantsOnlyOnScopedResources(action string) bool {
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
