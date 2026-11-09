// Package iam works out the IAM permissions a terraform plan needs and checks
// them against a policy (see the policy package).
package iam

import (
	"errors"

	"github.com/elecnix/terraform-permcheck/internal/plan"
	"github.com/elecnix/terraform-permcheck/internal/policy"
)

// Class categorizes an IAM permission as management-plane or data-plane.
// The report renders it as a tag, such as [required].
type Class int

const (
	// ClassUnknown is the zero Class, of a finding with no action: an
	// unresolved resource type.
	ClassUnknown Class = iota
	// ClassManagement is a provisioning or configuration action, which the
	// deploy role needs.
	ClassManagement
	// ClassDataPlane is a data access action, which belongs to application
	// roles.
	ClassDataPlane
	// ClassOptional is an action for an optional sub-resource, such as an
	// access policy or notifications.
	ClassOptional
)

func (c Class) String() string {
	switch c {
	case ClassManagement:
		return "management"
	case ClassDataPlane:
		return "data-plane"
	case ClassOptional:
		return "optional"
	default:
		return "unknown"
	}
}

// UnverifiedReason names why the tool could not check a grant. It is the
// policy package's reason, re-exported so the report layer names it without
// importing the policy package.
type UnverifiedReason = policy.UnverifiedReason

// The reasons a grant can be unverifiable.
const (
	// ReasonNone is no reason: the tool could check the grant.
	ReasonNone = policy.ReasonNone
	// ReasonResourceScope means the target ARN is unknown and the policy
	// grants the action only on some resources.
	ReasonResourceScope = policy.ReasonResourceScope
	// ReasonCondition means a condition on the grant names a key the plan
	// does not supply, or an operator the tool does not model.
	ReasonCondition = policy.ReasonCondition
)

// MissingAction is a single required permission found to be absent from the policy.
type MissingAction struct {
	// ModuleAddress is the module of the resource, e.g. "module.prod". It
	// is empty for a resource in the root module.
	ModuleAddress string
	ResourceType  string // terraform resource type, e.g. "aws_backup_vault"
	ResourceName  string // terraform resource name with any index, e.g. "this[0]"
	Change        string // "create", "update", or "delete"
	Action        string // required IAM action, e.g. "kms:CreateGrant"
	Service       string // extracted service prefix, e.g. "kms"
	Class         Class  // permission class of Action
	// ResourceScopeUnverified marks an action the policy grants only on some
	// resources while the target ARN is unknown (--strict-resources). The
	// grant may or may not apply, so the finding is unverified, not missing.
	ResourceScopeUnverified bool
	// ConditionUnverified marks an action the policy grants only through a
	// condition the tool cannot evaluate (--strict-resources): the
	// condition names a key the plan does not supply, or an operator the
	// tool does not model. The grant may or may not apply, so the finding
	// is unverified, not missing.
	ConditionUnverified bool
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
	// Reason is the reason the declared need asked for the action, as the
	// need's "reason" field says. It is empty for a finding that comes from
	// a terraform resource change, and then the resource fields name the
	// source instead.
	Reason string
	// DependsOn names the action that makes AWS check Action, when Action is
	// a dependent action (see dependentActions): the finding reads "needed
	// because DependsOn is required". Empty for an action required on its own.
	DependsOn string
	// Unresolved marks a resource change whose type no schema source knows.
	// The tool has no permission data for it, so Action is empty and the
	// change was not checked.
	Unresolved bool
}

// Address returns the terraform address of m's resource, module and index
// included: module.prod.aws_sqs_queue.q[0]. It is empty for a finding from a
// declared need.
func (m MissingAction) Address() string {
	if m.Need != "" {
		return ""
	}
	addr := m.ResourceType + "." + m.ResourceName
	if m.ModuleAddress != "" {
		addr = m.ModuleAddress + "." + addr
	}
	return addr
}

// FilterConfig controls which permission classes are filtered out of validation.
type FilterConfig struct {
	// ExcludeDataPlane excludes data-plane permissions (dynamodb:PutItem, s3:GetObject, etc.)
	ExcludeDataPlane bool
	// ExcludeOptional excludes optional sub-resource permissions (vault access policy, S3 website, etc.)
	ExcludeOptional bool
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
// permissions but keeps management-plane permissions.
func DefaultFilter() FilterConfig {
	return FilterConfig{
		ExcludeDataPlane: true,
		ExcludeOptional:  true,
	}
}

// Validate checks all resource changes against the policy and the resolver.
// The filter controls which permission classes are excluded from validation.
// A no-op change needs no permission: it is there so that a change
// referencing it can derive its target. A change whose type the resolver
// does not know becomes an Unresolved finding. A lookup that fails with ErrLookupFailed stops validation with
// that error, since the tool cannot say whether the type is covered.
//
// Each change's requirements are the schema's requirements for its operation
// plus the ones AWS implies (see impliedRequirements). checkChange decides
// each of them the same way.
func Validate(changes []*plan.ResourceChange, doc *policy.Document, resolver Resolver, filter FilterConfig) ([]MissingAction, error) {
	var missing []MissingAction

	// Every change, no-op included, can be the target of a reference.
	set := newChangeSet(changes)
	var checked []*plan.ResourceChange
	inPlan := make(map[string]bool, len(changes))
	for _, rc := range changes {
		if rc.Checked() {
			checked = append(checked, rc)
			inPlan[rc.Type] = true
		}
	}

	for _, rc := range checked {
		schema, err := resolver.Resolve(rc.Type)
		if errors.Is(err, ErrLookupFailed) {
			return nil, err
		}
		var reqs []Requirement
		if err != nil {
			missing = append(missing, MissingAction{Unresolved: true}.on(rc))
		} else {
			reqs = operationRequirements(schema, rc.Change)
		}
		paths := append(withTargets(reqs, resourceTargets(rc, set), resourceConditions(rc)), impliedRequirements(rc, set)...)
		missing = append(missing, checkChange(rc, paths, doc, isDedicated(schema), inPlan, filter)...)
	}

	return missing, nil
}

// operationRequirements returns the schema's requirements for op, or for
// create when the schema does not know op.
func operationRequirements(schema *Schema, op string) []Requirement {
	if reqs, ok := schema.Requirements(op); ok {
		return reqs
	}
	reqs, _ := schema.Requirements("create")
	return reqs
}

// checkChange returns a finding for each action of reqs that resource change
// rc needs and the policy does not grant, after the filter. dedicated and
// inPlan feed decide. An action with dependent actions (see
// dependentActions) also needs them, and each one the policy does not grant
// is a finding of its own that names the action it depends on.
func checkChange(rc *plan.ResourceChange, reqs []targeted, doc *policy.Document, dedicated bool, inPlan map[string]bool, filter FilterConfig) []MissingAction {
	var missing []MissingAction
	// classify decides whether the plan reports an action on its own: some
	// path's gate holds, no sub-resource owns it, and the filter keeps its
	// class. It returns the class and the gate attribute the report shows.
	classify := func(paths actionPaths) (class Class, gateAttr string, kept bool) {
		action := paths.action
		// An action is needed when the gate of any path that reaches it
		// holds. A gate holds when its presence test and its change test
		// both pass. When the plan does not show presence (static HCL
		// mode) or change (static mode, or a delete with no planned
		// state), that test passes, so the permission is kept.
		gates := withHiddenGates(rc.Type, action, paths.gates())
		needed, gateAttr, bestEffort := evaluateGates(gates, rc)
		if !needed {
			return 0, "", false
		}

		// A sub-resource in the plan that owns the action reports it.
		d := decide(rc.Type, action, bestEffort, dedicated, inPlan)
		if d.absorbedBy != "" {
			return 0, "", false
		}
		// An optional feature the plan sets is required for this apply.
		if d.class == ClassOptional && !bestEffort && featureUsed(action, gates, rc) {
			d.class = ClassManagement
		}

		// Filter by class
		class = d.class
		if filter.ExcludeDataPlane && class == ClassDataPlane {
			return 0, "", false
		}
		if filter.ExcludeOptional && class == ClassOptional {
			return 0, "", false
		}
		if filter.ExcludeConditional && gateAttr != "" {
			return 0, "", false
		}
		return class, gateAttr, true
	}

	groups := pathsByAction(reqs)
	// direct holds the actions the report shows on their own. A dependency on
	// one of them is its finding to make. A dependency on an action the plan
	// lists but does not report, because its gate fails or the filter drops
	// it, is still reported with its parent.
	direct := make(map[string]bool, len(groups))
	for _, g := range groups {
		if _, _, kept := classify(g); kept {
			direct[g.action] = true
		}
	}
	for _, paths := range groups {
		action := paths.action
		class, gateAttr, kept := classify(paths)
		if !kept {
			continue
		}

		// Action coverage, resource-scoped when the target ARN is derivable
		// from the plan, and condition-scoped when the plan shows the
		// value of a condition key the policy uses.
		if verdict := paths.verdict(rc, doc, filter.StrictResources); verdict.Verdict != policy.Covered {
			m := newFinding(action, class, verdict).on(rc)
			m.ConditionAttribute = gateAttr
			missing = append(missing, m)
		}

		// The dependent actions share the action's gate, class and filter,
		// whether or not the action itself is granted. One the plan
		// requires on its own is reported on its own.
		for _, p := range paths.paths {
			if !p.holds(rc) {
				continue
			}
			for _, dep := range dependenciesOf(p.Requirement) {
				if direct[dep.Action] {
					continue
				}
				direct[dep.Action] = true
				if verdict := dependencyVerdict(dep.Action, doc, filter.StrictResources); verdict.Verdict != policy.Covered {
					m := newFinding(dep.Action, class, verdict).on(rc)
					m.ConditionAttribute = gateAttr
					m.DependsOn = dep.dependsOn
					missing = append(missing, m)
				}
			}
		}
	}
	return missing
}

// newFinding returns the finding that the policy does not grant action, of
// class class. A verdict of Unverified marks it unverified, with the reason
// the tool could not check the grant.
func newFinding(action string, class Class, res policy.Result) MissingAction {
	m := MissingAction{
		Action:  action,
		Service: actionService(action),
		Class:   class,
	}
	switch res.Reason {
	case policy.ReasonCondition:
		m.ConditionUnverified = true
	case policy.ReasonResourceScope:
		m.ResourceScopeUnverified = true
	}
	return m
}

// on returns m as a finding on resource change rc.
func (m MissingAction) on(rc *plan.ResourceChange) MissingAction {
	m.ModuleAddress = rc.ModuleAddress
	m.ResourceType = rc.Type
	m.ResourceName = rc.InstanceName()
	m.Change = rc.Change
	return m
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
//
// A guard on a nested path, such as ttl.0.enabled, reads the nested value of
// the plan when the change carries it. The configuration section and the
// top-level maps only know top-level attributes, so otherwise the path's
// first segment decides.
func conditionMet(attr string, valueGuarded bool, rc *plan.ResourceChange) bool {
	top, nested := topAttribute(attr)
	if valueGuarded && rc.Configured != nil {
		return rc.Configured[top]
	}
	if nested {
		if present, known := rc.PathPresent(attr); known {
			return present
		}
	}
	if rc.Attributes == nil {
		return true
	}
	return rc.Attributes[top]
}
