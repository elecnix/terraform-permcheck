package iam

import (
	"encoding/json"
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

// FormatJSONResult is the structured JSON output produced by --format json.
type FormatJSONResult struct {
	Status   string               `json:"status"`             // "ok" or "gaps_found"
	Checked  int                  `json:"checked"`            // number of resources checked
	Label    string               `json:"label"`              // human-readable label for checked resources
	Missing  []FormatJSONMissing  `json:"missing"`            // empty when status=ok
	Excluded []FormatJSONExcluded `json:"excluded,omitempty"` // config-suppressed findings (only when --show-excluded)
}

// FormatJSONExcluded is a single config-excluded permission in JSON output.
type FormatJSONExcluded struct {
	ResourceType   string `json:"resource_type"`
	ResourceName   string `json:"resource_name"`
	Change         string `json:"change"`
	ExcludedAction string `json:"excluded_action"`
	Reason         string `json:"reason,omitempty"`
}

// FormatJSONMissing is a single missing permission in JSON output.
type FormatJSONMissing struct {
	ResourceType       string `json:"resource_type"`
	ResourceName       string `json:"resource_name"`
	Change             string `json:"change"`
	MissingAction      string `json:"missing_action"`
	Class              string `json:"class"`
	ConditionAttribute string `json:"condition_attribute,omitempty"`
	File               string `json:"file,omitempty"`
	Line               int    `json:"line,omitempty"`
}

// FormatJSON produces a machine-readable JSON representation of the
// validation result. When missing is nil or empty, status is "ok". Excluded
// actions (config-suppressed) are included only when a non-empty slice is
// passed; callers pass nil to omit them from the output.
func FormatJSON(missing []MissingAction, excluded []ExcludedAction, checked int, label string, locations map[string]FileLocation) string {
	result := FormatJSONResult{
		Status:  "ok",
		Checked: checked,
		Label:   label,
	}

	for _, e := range excluded {
		result.Excluded = append(result.Excluded, FormatJSONExcluded{
			ResourceType:   e.ResourceType,
			ResourceName:   e.ResourceName,
			Change:         e.Change,
			ExcludedAction: e.Action,
			Reason:         e.Reason,
		})
	}

	if len(missing) > 0 {
		result.Status = "gaps_found"
		result.Missing = make([]FormatJSONMissing, 0, len(missing))
		for _, m := range missing {
			item := FormatJSONMissing{
				ResourceType:       m.ResourceType,
				ResourceName:       m.ResourceName,
				Change:             m.Change,
				MissingAction:      m.Action,
				Class:              m.Class,
				ConditionAttribute: m.ConditionAttribute,
			}
			if locations != nil {
				key := m.ResourceType + "." + stripResourceIndex(m.ResourceName)
				if loc, ok := locations[key]; ok {
					item.File = loc.Path
					item.Line = loc.Line
				}
			}
			result.Missing = append(result.Missing, item)
		}
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	return string(out) + "\n"
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
