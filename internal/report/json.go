package report

import "encoding/json"

// JSONResult is the structured JSON output produced by --format json.
type JSONResult struct {
	Status   string         `json:"status"`             // "ok" or "gaps_found"
	Checked  int            `json:"checked"`            // number of resources checked
	Label    string         `json:"label"`              // human-readable label for checked resources
	Missing  []JSONMissing  `json:"missing"`            // empty when status=ok
	Excluded []JSONExcluded `json:"excluded,omitempty"` // config-suppressed findings (only when --show-excluded)
}

// JSONExcluded is a single config-excluded permission in JSON output.
type JSONExcluded struct {
	ResourceType   string `json:"resource_type,omitempty"`
	ResourceName   string `json:"resource_name,omitempty"`
	Change         string `json:"change,omitempty"`
	Need           string `json:"need,omitempty"`
	NeedResource   string `json:"need_resource,omitempty"`
	ExcludedAction string `json:"excluded_action"`
	Reason         string `json:"reason,omitempty"`
}

// JSONMissing is a single missing permission in JSON output.
//
// A finding from a declared need has no terraform resource, so it carries
// need and need_resource instead of resource_type, resource_name and change.
type JSONMissing struct {
	ResourceType       string `json:"resource_type,omitempty"`
	ResourceName       string `json:"resource_name,omitempty"`
	Change             string `json:"change,omitempty"`
	Need               string `json:"need,omitempty"`
	NeedResource       string `json:"need_resource,omitempty"`
	MissingAction      string `json:"missing_action"`
	Class              string `json:"class"`
	ConditionAttribute string `json:"condition_attribute,omitempty"`
	File               string `json:"file,omitempty"`
	Line               int    `json:"line,omitempty"`
	// Unverified is "resource_scope" when the policy grants the action only
	// on some resources and the target ARN is unknown (--strict-resources).
	Unverified string `json:"unverified,omitempty"`
}

// json renders the report as one JSON object. Unlike the other formats it
// does not group: missing has one entry per finding, in input order, so CI
// consumers that count entries count findings.
func (r *Report) json() string {
	result := JSONResult{
		Status:  "ok",
		Checked: r.checked,
		Label:   r.label,
	}

	for _, e := range r.excluded {
		result.Excluded = append(result.Excluded, JSONExcluded{
			ResourceType:   e.ResourceType,
			ResourceName:   e.ResourceName,
			Change:         e.Change,
			Need:           e.Need,
			NeedResource:   e.NeedResource,
			ExcludedAction: e.Action,
			Reason:         e.Reason,
		})
	}

	if len(r.findings) > 0 {
		result.Status = "gaps_found"
		result.Missing = make([]JSONMissing, 0, len(r.findings))
		for _, f := range r.findings {
			item := JSONMissing{
				ResourceType:       f.ResourceType,
				ResourceName:       f.ResourceName,
				Change:             f.Change,
				Need:               f.Need,
				NeedResource:       f.NeedResource,
				MissingAction:      f.Action,
				Class:              f.Class,
				ConditionAttribute: f.ConditionAttribute,
			}
			if f.ResourceScopeUnverified {
				item.Unverified = "resource_scope"
			}
			if f.loc != nil {
				item.File = f.loc.Path
				item.Line = f.loc.Line
			}
			result.Missing = append(result.Missing, item)
		}
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	return string(out) + "\n"
}
