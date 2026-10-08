package iam

import (
	"fmt"
	"path"
	"regexp"
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
	// resources. Supports glob patterns matched against the resource type
	// ("aws_secretsmanager_secret"), which matches it in every module, or
	// against the address with its module ("aws_secretsmanager_secret.f" in
	// the root module, "module.app.aws_secretsmanager_secret.f" in a module),
	// e.g. "aws_secretsmanager_*". Empty means the exclusion applies to every
	// resource.
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

// ExcludedAction is a MissingAction that a config exclusion suppressed, tagged
// with the reason from the matching exclusion.
type ExcludedAction struct {
	MissingAction
	Reason string
}

// ValidateExclusions checks the exclude list of a config file. It writes
// each operation back in the lower case the matcher compares.
func ValidateExclusions(exclusions []Exclusion) error {
	for i := range exclusions {
		e := &exclusions[i]
		if strings.TrimSpace(e.Permission) == "" {
			return fmt.Errorf("exclude[%d]: permission is required", i)
		}
		if _, err := path.Match(e.Permission, ""); err != nil {
			return fmt.Errorf("exclude[%d]: invalid permission pattern %q: %w", i, e.Permission, err)
		}
		if e.Resource != "" {
			if _, err := path.Match(e.Resource, ""); err != nil {
				return fmt.Errorf("exclude[%d]: invalid resource pattern %q: %w", i, e.Resource, err)
			}
		}
		for j, raw := range e.Operations {
			op := strings.ToLower(strings.TrimSpace(raw))
			if !knownOperations[op] {
				return fmt.Errorf("exclude[%d]: unknown operation %q in operations (want create, update, delete, or read)", i, raw)
			}
			e.Operations[j] = op
		}
	}
	return nil
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

// matchExclusion returns the first exclusion that suppresses m, if any. An
// unresolved finding has no action, and only a permission pattern that
// matches every action, such as "*", matches its empty one.
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

// resourceMatches reports whether the resource glob matches m's resource
// type, its address without count or for_each indexes, or its full address.
// An address starts with the module, so "aws_sqs_queue.q" names the root
// module's queue only, while "aws_sqs_queue" names the type in every module.
// For a declared need, the glob matches "needs.<sid>".
func resourceMatches(pattern string, m MissingAction) bool {
	if m.Need != "" {
		ok, _ := path.Match(pattern, "needs."+m.Need)
		return ok
	}
	addr := m.Address()
	for _, s := range []string{m.ResourceType, addressIndexRE.ReplaceAllString(addr, ""), addr} {
		if ok, _ := path.Match(pattern, s); ok {
			return true
		}
	}
	return false
}

// addressIndexRE matches an instance key in a resource or module address:
// [0] or ["key"], where a quoted key may hold a "]".
var addressIndexRE = regexp.MustCompile(`\[("[^"]*"|[^\]]*)\]`)
