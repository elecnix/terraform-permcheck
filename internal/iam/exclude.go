package iam

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
)

// Exclusion is a single user-declared permission suppression from the config
// file. It lets reviewers acknowledge a missing permission that is a known,
// unactionable false positive (e.g. a least-privilege deploy role that
// intentionally can't manage an unrelated module's resources).
type Exclusion struct {
	// Permission is the IAM action to suppress. Required. Supports glob
	// patterns via path.Match, e.g. "s3:DeleteBucketPublicAccessBlock" or
	// "s3:*".
	Permission string `json:"permission"`
	// Resource optionally scopes the exclusion to matching terraform
	// resources. Supports glob patterns matched against either the resource
	// type ("aws_secretsmanager_secret") or the full address
	// ("aws_secretsmanager_secret.forwarder"), e.g. "aws_secretsmanager_*".
	// Empty means the exclusion applies to every resource.
	Resource string `json:"resource,omitempty"`
	// Operations optionally limits the exclusion to matching terraform
	// operations ("create", "update", "delete", "read"), so a role can lack a
	// permission for one operation only. Empty means the exclusion applies to
	// every operation, which is the meaning of an entry written before this
	// field existed.
	Operations []string `json:"operations,omitempty"`
	// Reason is an optional audit-trail note explaining why the permission is
	// safe to suppress.
	Reason string `json:"reason,omitempty"`
}

// knownOperations lists the terraform operations a MissingAction can carry.
var knownOperations = map[string]bool{"create": true, "update": true, "delete": true, "read": true}

// Config is the permcheck config file schema (permcheck.json).
type Config struct {
	Exclude []Exclusion `json:"exclude"`
	// StrictResources turns on --strict-resources. The flag, when given,
	// overrides it.
	StrictResources bool `json:"strict_resources,omitempty"`
	// Needs declares permissions a principal needs beyond what the terraform
	// resources imply. They are checked against the same policy.
	Needs []Need `json:"needs,omitempty"`
}

// ExcludedAction is a MissingAction that a config exclusion suppressed, tagged
// with the reason from the matching exclusion.
type ExcludedAction struct {
	MissingAction
	Reason string
}

// LoadConfig reads and validates a permcheck config file at filePath.
func LoadConfig(filePath string) (*Config, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return parseConfig(raw)
}

// parseConfig unmarshals and validates config JSON.
func parseConfig(raw []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	for i := range c.Exclude {
		e := &c.Exclude[i]
		if strings.TrimSpace(e.Permission) == "" {
			return nil, fmt.Errorf("exclude[%d]: permission is required", i)
		}
		if _, err := path.Match(e.Permission, ""); err != nil {
			return nil, fmt.Errorf("exclude[%d]: invalid permission pattern %q: %w", i, e.Permission, err)
		}
		if e.Resource != "" {
			if _, err := path.Match(e.Resource, ""); err != nil {
				return nil, fmt.Errorf("exclude[%d]: invalid resource pattern %q: %w", i, e.Resource, err)
			}
		}
		for j, raw := range e.Operations {
			op := strings.ToLower(strings.TrimSpace(raw))
			if !knownOperations[op] {
				return nil, fmt.Errorf("exclude[%d]: unknown operation %q in operations (want create, update, delete, or read)", i, raw)
			}
			e.Operations[j] = op
		}
	}
	if err := validateNeeds(c.Needs); err != nil {
		return nil, err
	}
	return &c, nil
}

// ApplyExclusions partitions missing actions into those kept (no exclusion
// matched) and those excluded (matched a config exclusion). Input order is
// preserved. With no exclusions, everything is kept.
func ApplyExclusions(missing []MissingAction, exclusions []Exclusion) (kept []MissingAction, excluded []ExcludedAction) {
	for _, m := range missing {
		if e, ok := matchExclusion(m, exclusions); ok {
			excluded = append(excluded, ExcludedAction{MissingAction: m, Reason: e.Reason})
			continue
		}
		kept = append(kept, m)
	}
	return kept, excluded
}

// matchExclusion returns the first exclusion that suppresses m, if any.
func matchExclusion(m MissingAction, exclusions []Exclusion) (Exclusion, bool) {
	for _, e := range exclusions {
		if ok, _ := path.Match(e.Permission, m.Action); !ok {
			continue
		}
		if e.Resource != "" && !resourceMatches(e.Resource, m) {
			continue
		}
		if len(e.Operations) > 0 && !operationMatches(e.Operations, m.Change) {
			continue
		}
		return e, true
	}
	return Exclusion{}, false
}

// operationMatches reports whether the excluded operation list covers m's
// terraform operation. Names are compared case-insensitively so a config may
// write "Delete".
func operationMatches(operations []string, change string) bool {
	for _, op := range operations {
		if strings.EqualFold(op, change) {
			return true
		}
	}
	return false
}

// resourceMatches reports whether the resource glob matches m's resource type
// or its full "type.name" address (with any count/for_each index stripped).
// For a declared need, the glob matches "needs.<sid>".
func resourceMatches(pattern string, m MissingAction) bool {
	if m.Need != "" {
		ok, _ := path.Match(pattern, "needs."+m.Need)
		return ok
	}
	if ok, _ := path.Match(pattern, m.ResourceType); ok {
		return true
	}
	ok, _ := path.Match(pattern, string(KeyOf(m.ResourceType, m.ResourceName)))
	return ok
}
