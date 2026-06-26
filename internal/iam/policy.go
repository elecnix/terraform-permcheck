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
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

// Statement is a single IAM policy statement.
type Statement struct {
	Sid      string        `json:"Sid,omitempty"`
	Effect   string        `json:"Effect"`
	Action   actionField   `json:"Action"`
	Resource resourceField `json:"Resource"`
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

// Covers checks whether the policy explicitly allows the given action,
// including wildcard matching (e.g. "backup:*" covers "backup:CreateBackupVault").
func (d *PolicyDocument) Covers(action string) bool {
	for _, s := range d.Statements {
		if s.Effect != "Allow" {
			continue
		}
		if coversAny(s.Action, action) {
			return true
		}
	}
	return false
}

// coversAny returns true if any action in the list matches the target,
// including wildcard expansion.
func coversAny(actions []string, target string) bool {
	for _, a := range actions {
		if matchesWildcard(a, target) {
			return true
		}
	}
	return false
}

// matchesWildcard checks if a wildcard pattern matches an action string.
// "backup:*" matches "backup:CreateBackupVault".
// "backup:CreateBackupVault" matches "backup:CreateBackupVault" exactly.
// "*" matches anything.
func matchesWildcard(pattern, action string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == action
	}
	// Prefix wildcard: "backup:*" → action starts with "backup:"
	if strings.HasSuffix(pattern, ":*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(action, prefix)
	}
	return false
}
