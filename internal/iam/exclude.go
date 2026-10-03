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
	// Reason is an optional audit-trail note explaining why the permission is
	// safe to suppress.
	Reason string `json:"reason,omitempty"`
}

// Config is the permcheck config file schema (permcheck.json).
type Config struct {
	Exclude []Exclusion `json:"exclude"`
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
	for i, e := range c.Exclude {
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
		return e, true
	}
	return Exclusion{}, false
}

// resourceMatches reports whether the resource glob matches m's resource type
// or its full "type.name" address (with any count/for_each index stripped).
func resourceMatches(pattern string, m MissingAction) bool {
	if ok, _ := path.Match(pattern, m.ResourceType); ok {
		return true
	}
	addr := m.ResourceType + "." + stripResourceIndex(m.ResourceName)
	ok, _ := path.Match(pattern, addr)
	return ok
}

// excludedGroupKey groups excluded actions by permission and reason so
// duplicates across resources collapse into one entry.
type excludedGroupKey struct {
	action string
	reason string
}

// groupExcluded groups excluded actions by (Action, Reason), preserving first-seen order.
func groupExcluded(excluded []ExcludedAction) (map[excludedGroupKey][]ExcludedAction, []excludedGroupKey) {
	groups := make(map[excludedGroupKey][]ExcludedAction)
	order := make([]excludedGroupKey, 0, len(excluded))
	seen := make(map[excludedGroupKey]bool)
	for _, e := range excluded {
		k := excludedGroupKey{action: e.Action, reason: e.Reason}
		groups[k] = append(groups[k], e)
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}
	return groups, order
}

// FormatExcluded renders config-excluded actions as a human-readable block,
// grouped by (Action, Reason). Returns "" when there are none.
func FormatExcluded(excluded []ExcludedAction) string {
	if len(excluded) == 0 {
		return ""
	}
	groups, order := groupExcluded(excluded)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Excluded (per config) (%d):\n", len(order)))
	for _, k := range order {
		b.WriteString(fmt.Sprintf("  %s\n", k.action))
		if k.reason != "" {
			b.WriteString(fmt.Sprintf("    reason: %s\n", k.reason))
		}
		for _, e := range groups[k] {
			b.WriteString(fmt.Sprintf("    → %s.%s (%s)\n", e.ResourceType, e.ResourceName, e.Change))
		}
	}
	return b.String()
}

// FormatExcludedAnnotations renders config-excluded actions as GitHub Actions
// ::notice:: workflow commands, one per (Action, Reason) group. Returns "" when
// there are none.
func FormatExcludedAnnotations(excluded []ExcludedAction) string {
	if len(excluded) == 0 {
		return ""
	}
	groups, order := groupExcluded(excluded)

	var b strings.Builder
	for _, k := range order {
		var parts []string
		for _, e := range groups[k] {
			parts = append(parts, fmt.Sprintf("%s.%s (%s)", e.ResourceType, e.ResourceName, e.Change))
		}
		msg := k.action + " excluded (per config)"
		if k.reason != "" {
			msg += fmt.Sprintf(": %s", k.reason)
		}
		msg += " for: " + strings.Join(parts, ", ")
		b.WriteString(fmt.Sprintf("::notice title=Excluded IAM permission::%s\n", msg))
	}
	return b.String()
}
