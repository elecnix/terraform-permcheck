package iam

import (
	"fmt"
	"strings"
)

// FormatGitHubAnnotations formats missing actions as GitHub Actions
// ::warning:: workflow commands. Each distinct (Action, Class,
// ConditionAttribute) group produces a single ::warning:: line listing the
// affected resources. Returns empty string when there are no missing actions.
func FormatGitHubAnnotations(missing []MissingAction) string {
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

		b.WriteString(fmt.Sprintf("::warning title=Missing IAM permission::%s\n", msg))
	}

	return b.String()
}
