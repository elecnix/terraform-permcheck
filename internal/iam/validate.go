package iam

import (
	"fmt"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/plan"
)

// PermissionClass categorizes an IAM permission as management-plane or data-plane.
type PermissionClass int

const (
	ClassUnknown     PermissionClass = iota
	ClassManagement                  // provisioning/configuration actions (needed by deploy role)
	ClassDataPlane                   // data access actions (belongs to application roles)
	ClassServiceRole                 // actions only AWS service roles need
	ClassOptional                    // actions for optional sub-resources (access policy, notifications, etc.)
)

// MissingAction is a single required permission found to be absent from the policy.
type MissingAction struct {
	ResourceType string // terraform resource type, e.g. "aws_backup_vault"
	ResourceName string // terraform resource name, e.g. "this"
	Change       string // "create", "update", or "delete"
	Action       string // required IAM action, e.g. "kms:CreateGrant"
	Service      string // extracted service prefix, e.g. "kms"
	Filtered     bool   // true if this was filtered out (data-plane / optional)
	Class        string // classification tag: "[required]", "[optional]", "[data-plane]", "[service-role]", or ""
	// ResourceScopeUnverified marks an action the policy grants only on some
	// resources while the target ARN is unknown (--strict-resources). The
	// grant may or may not apply, so the finding is unverified, not missing.
	ResourceScopeUnverified bool
	// ConditionAttribute is the attribute gating this action, e.g.
	// "kms_key_arn": set in the planned resource (d.GetOk) or changed between
	// prior and planned state (d.HasChange). Empty for an unconditional action.
	ConditionAttribute string
	// Need is the sid of the declared need this action comes from. It is
	// empty for an action a terraform resource change needs, and then the
	// resource fields name the source instead.
	Need string
	// NeedResource is the resource of the need that the policy does not
	// cover. Empty when the need lists no resources.
	NeedResource string
}

// FilterConfig controls which permission classes are filtered out of validation.
type FilterConfig struct {
	// ExcludeDataPlane excludes data-plane permissions (dynamodb:PutItem, s3:GetObject, etc.)
	ExcludeDataPlane bool
	// ExcludeOptional excludes optional sub-resource permissions (vault access policy, S3 website, etc.)
	ExcludeOptional bool
	// ExcludeServiceRole excludes permissions only AWS service roles need (backup-storage, etc.)
	ExcludeServiceRole bool
	// ExcludeConditional excludes permissions gated on a schema attribute
	// (d.GetOk or d.HasChange guard). When true, only unconditional [required]
	// actions are kept.
	ExcludeConditional bool
	// StrictResources reports an action as unverified when the tool cannot
	// derive its target ARN and the policy grants it only on some resources.
	// When it is off, an action-only match counts as coverage there.
	StrictResources bool
}

// DefaultFilter returns a FilterConfig that excludes data-plane and optional
// permissions but keeps management-plane and service-role permissions.
func DefaultFilter() FilterConfig {
	return FilterConfig{
		ExcludeDataPlane:   true,
		ExcludeOptional:    true,
		ExcludeServiceRole: false, // keep these — they might be needed
	}
}

// Validate checks all resource changes against the policy and the resolver.
// The filter controls which permission classes are excluded from validation.
func Validate(changes []*plan.ResourceChange, policy *PolicyDocument, resolver Resolver, filter FilterConfig) ([]MissingAction, error) {
	var missing []MissingAction

	inPlan := make(map[string]bool, len(changes))
	for _, rc := range changes {
		inPlan[rc.Type] = true
	}

	for _, rc := range changes {
		schema, err := resolver.Resolve(rc.Type)
		if err != nil {
			continue
		}

		required, ok := schema.Requirements(rc.Change)
		if !ok {
			required, ok = schema.Requirements("create")
		}
		if !ok {
			continue
		}

		for _, paths := range pathsByAction(required) {
			action := paths.action
			// An action is needed when the gate of any path that reaches it
			// holds. A gate holds when its presence test and its change test
			// both pass. When the plan does not show presence (static HCL
			// mode) or change (static mode, or a delete with no planned
			// state), that test passes, so the permission is kept.
			needed, gateAttr, bestEffort := evaluateGates(paths.gates, rc)
			if !needed {
				continue
			}

			// A sub-resource in the plan that owns the action reports it.
			d := decide(rc.Type, action, bestEffort, inPlan)
			if d.absorbedBy != "" {
				continue
			}

			// Action coverage, resource-scoped when the target ARN is derivable
			// from the plan.
			verdict := policy.Coverage(action, resourceTargetARNs(rc, changes), filter.StrictResources)
			if verdict == Covered {
				continue
			}

			// Filter by class
			class := d.class
			if filter.ExcludeDataPlane && class == ClassDataPlane {
				continue
			}
			if filter.ExcludeOptional && class == ClassOptional {
				continue
			}
			if filter.ExcludeServiceRole && class == ClassServiceRole {
				continue
			}
			if filter.ExcludeConditional && gateAttr != "" {
				continue
			}

			missing = append(missing, MissingAction{
				ResourceType:       rc.Type,
				ResourceName:       rc.Name,
				Change:             rc.Change,
				Action:             action,
				Service:            actionService(action),
				Class:              classTag(class),
				ConditionAttribute: gateAttr,

				ResourceScopeUnverified: verdict == Unverified,
			})
		}
	}

	// Cross-service callback permissions: actions in a different service that
	// AWS invokes at apply time (e.g. elasticloadbalancing:SetWebACL for an
	// aws_wafv2_web_acl_association targeting an ALB). These are invisible to
	// schema/source resolution, so they're checked separately here.
	for _, rc := range changes {
		for _, m := range append(crossServiceMissing(rc, policy, filter.StrictResources), passRoleMissing(rc, policy, changes, filter.StrictResources)...) {
			if filter.ExcludeConditional && m.ConditionAttribute != "" {
				continue
			}
			missing = append(missing, m)
		}
	}

	return missing, nil
}

// gateAttribute names the attributes gating an action, for the
// [conditional: <attr>] tag. An action can carry a presence gate, a change
// gate, or both, so both names appear when both apply. Empty when neither
// gate applies.
func gateAttribute(presenceAttr, changeAttr string) string {
	switch {
	case presenceAttr == "":
		return changeAttr
	case changeAttr == "" || changeAttr == presenceAttr:
		return presenceAttr
	default:
		return presenceAttr + "+" + changeAttr
	}
}

// conditionMet reports whether a guard on an attribute lets its call run for
// this resource change.
//
// A presence guard (d.GetOk) needs the attribute to hold a non-zero value in
// the planned or prior state.
//
// A value guard — a set that must be non-empty, say — reads the attribute's
// value, and the provider's default already supplies a non-zero one. Only the
// configuration can tell a set the author wrote from one the provider filled,
// so a value guard asks the configuration section instead. With no
// configuration to read, both kinds fall back to presence, which keeps the
// permission rather than dropping one the provider may still need.
func conditionMet(attr string, valueGuarded bool, rc *plan.ResourceChange) bool {
	if valueGuarded && rc.Configured != nil {
		return rc.Configured[attr]
	}
	if rc.Attributes == nil {
		return true
	}
	return rc.Attributes[attr]
}

// missingGroupKey is a grouping key for deduplicating missing actions.
type missingGroupKey struct {
	action     string
	class      string
	condition  string
	unverified bool
}

// groupKey returns the key that groups m with identical findings on other
// resources.
func groupKey(m MissingAction) missingGroupKey {
	return missingGroupKey{action: m.Action, class: m.Class, condition: m.ConditionAttribute, unverified: m.ResourceScopeUnverified}
}

// unverifiedTag marks a finding whose coverage depends on a resource scope the
// tool cannot check (--strict-resources).
const unverifiedTag = "[unverified: resource scope]"

// groupMissing groups missing actions by groupKey, preserving first-seen order.
func groupMissing(missing []MissingAction) (map[missingGroupKey][]MissingAction, []missingGroupKey) {
	groups := make(map[missingGroupKey][]MissingAction)
	order := make([]missingGroupKey, 0, len(missing))
	for _, m := range missing {
		k := groupKey(m)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], m)
	}
	return groups, order
}

// FormatMissing formats a list of missing actions as a human-readable message.
// Permissions are grouped by (Action, Class, ConditionAttribute) so duplicates
// across resources are collapsed into a single entry, followed by the list of
// affected resources. Findings unverified for resource scope get a section of
// their own after the missing ones. When locations is non-nil and a resource
// has a matching FileLocation entry (keyed by "type.name"), the file path and
// line number are appended to the resource line.
func FormatMissing(missing []MissingAction, locations map[string]FileLocation) string {
	if len(missing) == 0 {
		return ""
	}

	groups, order := groupMissing(missing)
	var plain, unverified []missingGroupKey
	for _, k := range order {
		if k.unverified {
			unverified = append(unverified, k)
		} else {
			plain = append(plain, k)
		}
	}

	var b strings.Builder
	if len(plain) > 0 {
		b.WriteString(fmt.Sprintf("Missing IAM permissions (%d):\n", len(plain)))
		writeMissingGroups(&b, plain, groups, locations)
	}
	if len(unverified) > 0 {
		if len(plain) > 0 {
			b.WriteString("\n")
		}
		b.WriteString(fmt.Sprintf("Unverified IAM permissions (%d), granted only on resources whose ARN the plan does not show:\n", len(unverified)))
		writeMissingGroups(&b, unverified, groups, locations)
	}
	return b.String()
}

// writeMissingGroups writes one action line per group key, each followed by
// its affected resources.
func writeMissingGroups(b *strings.Builder, keys []missingGroupKey, groups map[missingGroupKey][]MissingAction, locations map[string]FileLocation) {
	for _, k := range keys {
		// Action line with optional class and condition tags
		line := k.action
		if k.condition != "" {
			line += fmt.Sprintf(" [conditional: %s]", k.condition)
		} else if k.class != "" {
			line += " " + k.class
		}
		if k.unverified {
			line += " " + unverifiedTag
		}
		b.WriteString(fmt.Sprintf("  %s\n", line))
		// Affected resources
		for _, m := range groups[k] {
			resourceLine := "    → " + m.Source()
			if locations != nil && m.Need == "" {
				key := m.ResourceType + "." + stripResourceIndex(m.ResourceName)
				if loc, ok := locations[key]; ok {
					resourceLine += fmt.Sprintf(" [%s:%d]", loc.Path, loc.Line)
				}
			}
			b.WriteString(resourceLine + "\n")
		}
	}
}

// DistinctCount returns the number of distinct (Action, Class, ConditionAttribute)
// groups in the list, unverified ones included.
func DistinctCount(missing []MissingAction) int {
	_, order := groupMissing(missing)
	return len(order)
}

// UnverifiedCount returns the number of distinct groups that are unverified
// for resource scope.
func UnverifiedCount(missing []MissingAction) int {
	_, order := groupMissing(missing)
	n := 0
	for _, k := range order {
		if k.unverified {
			n++
		}
	}
	return n
}

// classTag returns a human-readable classification tag for a PermissionClass.
func classTag(c PermissionClass) string {
	switch c {
	case ClassOptional:
		return "[optional]"
	case ClassDataPlane:
		return "[data-plane]"
	case ClassServiceRole:
		return "[service-role]"
	case ClassManagement:
		return "[required]"
	default:
		return "[unknown]"
	}
}
