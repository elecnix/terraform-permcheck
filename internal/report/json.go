package report

import (
	"encoding/json"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/principal"
)

// JSONResult is the structured JSON output produced by --format json.
type JSONResult struct {
	Status   string         `json:"status"`             // "ok" or "gaps_found"
	Checked  int            `json:"checked"`            // number of resources checked
	Label    string         `json:"label"`              // human-readable label for checked resources
	Missing  []JSONMissing  `json:"missing"`            // empty when status=ok
	Excluded []JSONExcluded `json:"excluded,omitempty"` // config-suppressed findings (only when --show-excluded)
	// UnresolvedTypes lists the resource types no schema source knows, one
	// entry per type. The tool did not check them. They set status to
	// gaps_found unless allowed.
	UnresolvedTypes []JSONUnresolved `json:"unresolved_types,omitempty"`
	// UnresolvedAllowed counts the unresolved types that do not fail the
	// run: allowed ones and those a config exclusion covers.
	UnresolvedAllowed int `json:"unresolved_allowed,omitempty"`
	// PolicySources lists each mapped principal whose needs the run
	// checked, in label order, with the policy sources that may apply to
	// those needs. It is absent when the run checked no mapped need.
	PolicySources []JSONPrincipalSources `json:"policy_sources,omitempty"`
	// PlanResourcesSkipped is true when the run had no --policy-* source,
	// so it checked the needs of mapped principals only and not the plan's
	// resources. It is absent otherwise.
	PlanResourcesSkipped bool `json:"plan_resources_skipped,omitempty"`
	// NotEvaluated lists the kinds of policy that the check of a mapped
	// principal's needs counts as allowing without reading them (see
	// notEvaluated). It is absent when the run checked no mapped need.
	NotEvaluated []string `json:"not_evaluated,omitempty"`
}

// notEvaluated lists the kinds of policy that the check of a mapped
// principal's needs never reads, in the order the json report gives them.
// Each can only remove permissions that the other policies grant, so the
// check counts each as allowing: a covered verdict means covered by the
// policies the plan shows, and a missing verdict stays provable.
//
//   - "scp" and "rcp": service control policies apply to the principal's
//     account and resource control policies to the resource's account, and
//     both must allow the request
//     (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-scp).
//     The plan doesn't show which account a principal runs in.
//   - "session_policy": the call that creates a session passes it, and the
//     plan never shows it
//     (https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session).
//   - "vpc_endpoint_policy": an endpoint policy limits the requests that go
//     through the endpoint
//     (https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html).
//     The plan doesn't show which path a request takes, and the check
//     doesn't read the policy of aws_vpc_endpoint.
//   - "role_trust_policy": a role's trust policy "must explicitly allow
//     access for principals"
//     (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).
//     The check doesn't read assume_role_policy, so in one account it checks
//     a need for sts:AssumeRole against the identity side alone.
var notEvaluated = []string{"scp", "rcp", "session_policy", "vpc_endpoint_policy", "role_trust_policy"}

// JSONPrincipalSources is a mapped principal and the policy sources that may
// apply to its checked needs.
type JSONPrincipalSources struct {
	// Principal is the principal's key in the config's principals map.
	Principal string `json:"principal"`
	// Address is the terraform address of its role or user. It is absent
	// for a principal outside the plan.
	Address string `json:"address,omitempty"`
	// Name and ARN are the name or the ARN that the principals map gives a
	// role or user outside the plan. Each is absent unless the map sets it.
	Name string `json:"name,omitempty"`
	ARN  string `json:"arn,omitempty"`
	// Complete is set for a role or user outside the plan only. It is true
	// when the plan has both exclusive resources for a role, so the sources
	// list every policy of the role, some perhaps with unknown text. It is
	// false when other stacks may attach policies to the principal, and then
	// the sources end with the implicit source of those policies. It is
	// always false for a user outside the plan, since other stacks may add
	// it to groups. The check assumes that the plan shows every policy and
	// group membership of a role or user in the plan.
	Complete *bool `json:"complete,omitempty"`
	// Sources are in plan order, then the inline policies that an exclusive
	// resource lists and the plan doesn't define, then the groups outside
	// the plan of a user, then the implicit source of a principal outside
	// the plan. The list is empty when no source applies.
	Sources []JSONPolicySource `json:"sources"`
}

// JSONPolicySource is one policy source of a mapped principal.
type JSONPolicySource struct {
	// Address is the terraform address of the resource that sets the
	// policy. It is absent for the implicit source of a role outside the
	// plan.
	Address string `json:"address,omitempty"`
	// Path is the attribute path of the policy in that resource, such as
	// policy, inline_policy.0.policy, policy_arn or policy_names.0. It is
	// absent for the implicit source of a role outside the plan.
	Path string `json:"path,omitempty"`
	// Kind is "identity", "boundary" or "resource".
	Kind string `json:"kind"`
	// Text is "known" when the check read the policy text, and "unknown"
	// when it couldn't. An unknown source may grant any action and never
	// denies. A boundary with unknown text may limit any action.
	Text string `json:"text"`
	// UnknownReason says why the text is unknown: "computed" when
	// terraform computes it at apply time, "unread" when this version
	// doesn't read the source's type yet, and "outside_plan" when the
	// source attaches a managed policy that the plan doesn't contain, when
	// an exclusive resource of inline policies lists an inline policy that
	// the plan doesn't define, or when a membership puts a user in a group
	// outside the plan. The implicit source of a role or user outside the
	// plan has "attached_outside_plan", and the implicit source of a
	// resource in another account than the principal's has
	// "cross_account". It is absent when the text is known.
	UnknownReason string `json:"unknown_reason,omitempty"`
	// PolicyARN is the known ARN of the managed policy the source attaches.
	// It is absent for a source that holds its text itself.
	PolicyARN string `json:"policy_arn,omitempty"`
	// PolicyName is the name of the inline policy, when the plan knows it.
	PolicyName string `json:"policy_name,omitempty"`
	// Unlisted names the kinds of policy, "inline" and "managed", that
	// other stacks may attach to a role or user outside the plan, and
	// "groups" when other stacks may add a user outside the plan to groups.
	// It is set on the implicit source of that principal only.
	Unlisted []string `json:"unlisted,omitempty"`
	// Group is set on a policy of a group that a mapped user belongs to: the
	// group the policy reaches the user through, as the address of an
	// aws_iam_group or the name of a group outside the plan. It is also set
	// on the source of a group outside the plan that a membership puts the
	// user in, whose address is the membership's and whose unknown_reason is
	// "outside_plan". That source has no group when the plan doesn't know
	// the group's name.
	Group string `json:"group,omitempty"`
	// Resource is set on the implicit source of a KMS key outside the plan:
	// the need's resource, whose key policy the plan doesn't show. Its
	// unknown_reason is "outside_plan". The source of a need without
	// resources has no resource. It is also set on the implicit source of a
	// resource in another account than the principal's, whose resource
	// policy the plan doesn't show. Its unknown_reason is "cross_account".
	Resource string `json:"resource,omitempty"`
	// Policy is the address of the aws_iam_policy resource, or of the
	// data "aws_iam_policy" source, whose text the check read for the
	// managed policy the source attaches. It is absent for a source that
	// holds its text itself, and for a managed policy outside the plan.
	Policy string `json:"policy,omitempty"`
	// Link is "yes" when the source attaches to the principal, and "maybe"
	// when the plan can't decide it, or can't decide which policy the
	// attached ARN names. The check counts the Allows of a
	// "maybe" source as grants it can't check, and ignores its Denies. A
	// resource policy is "yes" when its resource is the resource of a
	// checked need, and "maybe" when it may be, or when this version doesn't
	// read its type yet.
	Link string `json:"link"`
}

// JSONUnresolved is one resource type no schema source knows, with the
// resources of that type.
type JSONUnresolved struct {
	ResourceType string `json:"resource_type"`
	// Allowed is true when the run allows unresolved types
	// (--allow-unresolved-types or allow_unresolved_types).
	Allowed   bool                     `json:"allowed"`
	Resources []JSONUnresolvedResource `json:"resources"`
}

// JSONUnresolvedResource is one resource change of an unresolved type.
type JSONUnresolvedResource struct {
	// ModuleAddress is the module of the resource, e.g. "module.prod".
	// It is absent for a resource in the root module.
	ModuleAddress string `json:"module_address,omitempty"`
	ResourceName  string `json:"resource_name"`
	Change        string `json:"change"`
	File          string `json:"file,omitempty"`
	Line          int    `json:"line,omitempty"`
}

// JSONExcluded is a single config-excluded permission in JSON output.
type JSONExcluded struct {
	ModuleAddress  string `json:"module_address,omitempty"`
	ResourceType   string `json:"resource_type,omitempty"`
	ResourceName   string `json:"resource_name,omitempty"`
	Change         string `json:"change,omitempty"`
	Need           string `json:"need,omitempty"`
	Principal      string `json:"principal,omitempty"`
	NeedResource   string `json:"need_resource,omitempty"`
	ExcludedAction string `json:"excluded_action,omitempty"`
	Reason         string `json:"reason,omitempty"`
	// Unresolved is true for an excluded resource type no schema source
	// knows. It has no excluded_action.
	Unresolved bool `json:"unresolved,omitempty"`
}

// JSONMissing is a single missing permission in JSON output.
//
// A finding from a declared need has no terraform resource, so it carries
// need and need_resource instead of resource_type, resource_name and change.
// module_address is absent for a resource in the root module.
type JSONMissing struct {
	ModuleAddress string `json:"module_address,omitempty"`
	ResourceType  string `json:"resource_type,omitempty"`
	ResourceName  string `json:"resource_name,omitempty"`
	Change        string `json:"change,omitempty"`
	Need          string `json:"need,omitempty"`
	// Principal is the label of the mapped principal whose need this is.
	// It is absent for any other finding.
	Principal     string `json:"principal,omitempty"`
	NeedResource  string `json:"need_resource,omitempty"`
	MissingAction string `json:"missing_action"`
	// DependsOn names the action AWS requires missing_action with, for a
	// dependent action. It is absent for an action required on its own.
	DependsOn          string `json:"depends_on,omitempty"`
	Class              string `json:"class"`
	ConditionAttribute string `json:"condition_attribute,omitempty"`
	// Reason is the reason the declared need asked for the action, as the
	// need's "reason" field says. It is absent for a finding from a
	// terraform resource change, and for a need without a reason.
	Reason string `json:"reason,omitempty"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	// Unverified names why the tool could not check the grant:
	// "resource_scope" when the policy grants the action only on some
	// resources and the target ARN is unknown, "condition" when a
	// condition on the grant names a key the plan does not supply or an
	// operator the tool does not model (--strict-resources).
	Unverified string `json:"unverified,omitempty"`
	// GrantedOn lists the resources the policy grants missing_action on,
	// sorted, when it grants it only on resources that do not cover the
	// target. It is absent when the policy does not grant the action at all.
	GrantedOn []string `json:"granted_on,omitempty"`
	// Boundary names the permissions boundary of a mapped principal that
	// makes missing_action missing while the principal's other policies
	// allow it: the address of the aws_iam_policy or data "aws_iam_policy"
	// that holds its text. It is absent for any other finding.
	Boundary string `json:"boundary,omitempty"`
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
			ModuleAddress:  e.ModuleAddress,
			ResourceType:   e.ResourceType,
			ResourceName:   e.ResourceName,
			Change:         e.Change,
			Need:           e.Need,
			Principal:      e.Principal,
			NeedResource:   e.NeedResource,
			ExcludedAction: e.Action,
			Reason:         e.Reason,
			Unresolved:     e.Unresolved,
		})
	}

	for _, g := range r.unresolved {
		u := JSONUnresolved{ResourceType: g.key, Allowed: r.unresolvedAllowed}
		for _, f := range g.items {
			res := JSONUnresolvedResource{ModuleAddress: f.ModuleAddress, ResourceName: f.ResourceName, Change: f.Change}
			if f.loc != nil {
				res.File = f.loc.Path
				res.Line = f.loc.Line
			}
			u.Resources = append(u.Resources, res)
		}
		result.UnresolvedTypes = append(result.UnresolvedTypes, u)
	}
	result.UnresolvedAllowed = r.allowedUnresolved()

	if r.hasGaps {
		result.Status = "gaps_found"
		result.Missing = make([]JSONMissing, 0, len(r.findings))
	}
	if len(r.findings) > 0 {
		for _, f := range r.findings {
			item := JSONMissing{
				ModuleAddress:      f.ModuleAddress,
				ResourceType:       f.ResourceType,
				ResourceName:       f.ResourceName,
				Change:             f.Change,
				Need:               f.Need,
				Principal:          f.Principal,
				NeedResource:       f.NeedResource,
				MissingAction:      f.Action,
				DependsOn:          f.DependsOn,
				Class:              classTag(f.Class),
				ConditionAttribute: f.ConditionAttribute,
				Reason:             f.Reason,
				GrantedOn:          f.GrantedOn,
				Boundary:           f.Boundary,
			}
			if reason := f.unverifiedReason(); reason != iam.ReasonNone {
				item.Unverified = reason.Value()
			}
			if f.loc != nil {
				item.File = f.loc.Path
				item.Line = f.loc.Line
			}
			result.Missing = append(result.Missing, item)
		}
	}

	for _, p := range r.principals {
		item := JSONPrincipalSources{Principal: p.Label, Address: p.Address, Name: p.Name, ARN: p.ARN, Sources: []JSONPolicySource{}}
		if p.Address == "" {
			complete := p.Complete
			item.Complete = &complete
		}
		for _, src := range p.Sources {
			item.Sources = append(item.Sources, jsonPolicySource(src))
		}
		result.PolicySources = append(result.PolicySources, item)
	}
	result.PlanResourcesSkipped = r.resourcesSkipped
	if len(r.principals) > 0 {
		result.NotEvaluated = notEvaluated
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	return string(out) + "\n"
}

// jsonPolicySource renders one policy source of a mapped principal.
func jsonPolicySource(s principal.Applied) JSONPolicySource {
	out := JSONPolicySource{
		Address:    s.Address,
		Path:       s.Path,
		Kind:       string(s.Kind),
		Text:       "known",
		PolicyARN:  s.PolicyARN,
		PolicyName: s.PolicyName,
		Policy:     s.Policy,
		Unlisted:   s.Unlisted,
		Group:      s.Group,
		Resource:   s.Resource,
		Link:       s.Match.String(),
	}
	if s.Unknown {
		out.Text = "unknown"
		out.UnknownReason = unknownReason(s)
	}
	return out
}
