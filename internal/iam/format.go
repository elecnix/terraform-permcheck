package iam

import (
	"fmt"
	"regexp"
	"strings"
)

// FileLocation records the source file path and line number of a terraform
// resource declaration.
type FileLocation struct {
	Path string // file path relative to --terraform-root
	Line int    // 1-based line number of the resource declaration
}

// stripResourceIndex removes count / for_each index suffixes from a terraform
// resource name so it can be matched against the static HCL map (which only
// carries the local name, never an index).
//
//	cloudtrail[0]       → cloudtrail
//	config["us-east-1"]  → config
func stripResourceIndex(name string) string {
	return resourceIndexRE.ReplaceAllString(name, "")
}

// resourceIndexRE matches a trailing bracket-index suffix like [0] or ["key"].
var resourceIndexRE = regexp.MustCompile(`\[[^\]]*\]$`)

// FormatGitHubAnnotations formats missing actions as GitHub Actions
// ::warning:: workflow commands. Each distinct (Action, Class,
// ConditionAttribute) group produces a single ::warning:: line listing the
// affected resources. When locations is non-nil, the first resource in each
// group that has a matching FileLocation entry (keyed by "type.name") gets
// file= and line= parameters so GitHub surfaces the annotation inline in the
// PR "Files changed" tab. Returns empty string when there are no missing
// actions.
func FormatGitHubAnnotations(missing []MissingAction, locations map[string]FileLocation) string {
	if len(missing) == 0 {
		return ""
	}

	// Group by (Action, Class, ConditionAttribute)
	groups := make(map[missingGroupKey][]MissingAction)
	order := make([]missingGroupKey, 0, len(missing))
	seen := make(map[missingGroupKey]bool)
	for _, m := range missing {
		k := missingGroupKey{action: m.Action, class: m.Class, condition: m.ConditionAttribute}
		groups[k] = append(groups[k], m)
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}

	var b strings.Builder
	for _, k := range order {
		items := groups[k]

		// Find the first resource in this group that has a file location.
		var loc *FileLocation
		if locations != nil {
			for _, m := range items {
				key := m.ResourceType + "." + stripResourceIndex(m.ResourceName)
				if l, ok := locations[key]; ok {
					loc = &l
					break
				}
			}
		}

		// Build the annotation message
		var msgParts []string
		for _, m := range items {
			msgParts = append(msgParts, fmt.Sprintf("%s.%s (%s)", m.ResourceType, m.ResourceName, m.Change))
		}

		msg := k.action
		if k.condition != "" {
			msg += fmt.Sprintf(" [conditional: %s]", k.condition)
		}
		msg += " needed by: " + strings.Join(msgParts, ", ")

		if loc != nil {
			b.WriteString(fmt.Sprintf("::warning file=%s,line=%d,title=Missing IAM permission::%s\n", loc.Path, loc.Line, msg))
		} else {
			b.WriteString(fmt.Sprintf("::warning title=Missing IAM permission::%s\n", msg))
		}
	}

	return b.String()
}
