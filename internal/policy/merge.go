package policy

// Merging.
//
// A principal's access in one account comes from several policies: its
// identity policies, and the resource policies of the resources it acts on.
// AWS allows a request when any of them allows it and none denies it: "If an
// action is allowed by an identity-based policy, a resource-based policy, or
// both, then AWS allows the action. An explicit deny in either of these
// policies overrides the allow"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-rdp).
// Inside the identity side, any policy's Allow is enough and any policy's
// explicit Deny overrides it
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html).
//
// A union of Allows with a Deny that overrides them is what Coverage already
// computes over the statements of one document. So Merge puts every statement
// in one document, and Coverage gives AWS's answer without a second
// evaluation path.

// mergedVersion is the policy language version of a merged document. The
// version does not change how Coverage reads a statement.
const mergedVersion = "2012-10-17"

// Merge returns one document that holds the statements of every document, in
// order. Coverage on the merged document gives the same-account answer for
// the documents together: an Allow in any of them grants, and a definite Deny
// in any of them overrides every Allow. A nil document adds nothing.
//
// Merge applies the same-account rule only. A cross-account request needs an
// Allow from each account, which one merged document cannot express
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html).
func Merge(docs ...*Document) *Document {
	merged := &Document{Version: mergedVersion}
	for _, d := range docs {
		if d == nil {
			continue
		}
		merged.Statements = append(merged.Statements, d.Statements...)
	}
	return merged
}

// UnknownSource returns the document that stands for a policy source whose
// text the plan does not show, such as an AWS managed policy or a policy that
// terraform computes at apply time. Such a source may grant any action on any
// resource, and it never denies. Its one statement allows every action on
// every resource, marked unverified with ReasonPolicyUnknown. Merged with the
// known sources, it makes a need that no known source grants covered by
// default and unverified under --strict-resources. A need that a known source
// grants stays covered, and a definite Deny in a known source still makes the
// need missing.
//
// The marker does not survive a JSON round trip: the JSON form of the
// document is a plain Allow of every action.
func UnknownSource() *Document {
	return unknownSource(ReasonPolicyUnknown)
}

// CrossAccountSource returns the document that stands for the resource
// policy of a resource in another account than the principal's, when the
// plan doesn't contain that policy. It is an unknown source (see
// UnknownSource) with ReasonCrossAccount: it may allow any action and never
// denies.
func CrossAccountSource() *Document {
	return unknownSource(ReasonCrossAccount)
}

// unknownSource returns a document whose one statement allows every action
// on every resource, marked unverified with reason.
func unknownSource(reason UnverifiedReason) *Document {
	allowAll := Statement{
		Effect:   "Allow",
		Action:   actionField{"*"},
		Resource: resourceField{"*"},
	}
	return &Document{
		Version:    mergedVersion,
		Statements: []Statement{allowAll.Unverified(reason)},
	}
}

// Unverified returns a copy of the statement that the tool treats as a grant
// it cannot check, with reason as the reason. Its Allow counts as coverage by
// default and makes the action unverified under --strict-resources, as an
// Allow does whose condition the tool cannot evaluate. Its Deny never counts
// as definite, as a conditional Deny does not. A Condition that provably
// cannot match the plan still makes the statement grant nothing.
//
// A resource policy statement whose Principal may match the principal is such
// a statement, with ReasonCondition. So is the grant of an unknown source,
// with ReasonPolicyUnknown (see UnknownSource). ReasonNone removes the marker.
func (s Statement) Unverified(reason UnverifiedReason) Statement {
	s.unverified = reason
	return s
}

// Denies returns a document that holds the Deny statements of d, in order.
// The policy set of a principal with a permissions boundary checks a grant
// that the boundary doesn't limit against the Deny statements of every
// policy: an explicit Deny in any policy denies the request
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).
func (d *Document) Denies() *Document {
	out := &Document{Version: d.Version}
	for _, s := range d.Statements {
		if s.Effect == "Deny" {
			out.Statements = append(out.Statements, s)
		}
	}
	return out
}
