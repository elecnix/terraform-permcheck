package iam

import "github.com/elecnix/terraform-permcheck/internal/policy"

// Dependent actions.
//
// AWS authorizes a few actions only when the caller also holds a second
// action, though the call never names it. The Service Authorization
// Reference lists such pairs in a "Dependent actions" column. Neither the
// machine-readable service reference that gen_iam_services.go reads nor the
// reference's HTML pages carry that column for any service, so the table
// below is curated by hand, and every row cites its evidence.
//
// A dependent action is required wherever its parent action is: from a
// resource type, from a declared need, under the parent's gate and class.
// The check is by action alone, since the dependency acts on a resource the
// plan and the need do not name. A grant limited to some resources is
// covered, or unverified under --strict-resources, as for any action whose
// target the tool cannot derive.

// dependentAction is an action AWS requires of the caller beside another.
type dependentAction struct {
	// action is the action AWS also checks.
	action string
	// evidence says how the dependency was established, so a later reader can
	// repeat or retire the row.
	evidence string
}

// dependentActions maps an action to the actions AWS also requires of the
// caller.
var dependentActions = map[string][]dependentAction{
	"backup:ListRecoveryPointsByResource": {{
		action: "backup:ListRecoveryPointsByBackupVault",
		evidence: "Observed in a controlled test in a real account: with " +
			"backup:ListRecoveryPointsByResource granted on * and no other " +
			"AWS Backup action, the call failed with an \"Insufficient " +
			"privileges\" error. Granting backup:ListRecoveryPointsByBackupVault " +
			"on the vault, with no other change, made it succeed.",
	}},
}

// dependenciesOf returns the dependent actions of action, as requirements
// that carry action's gate and name it in dependsOn.
func dependenciesOf(r Requirement) []targeted {
	var out []targeted
	for _, d := range dependentActions[r.Action] {
		out = append(out, targeted{Requirement: Requirement{Action: d.action, Gate: r.Gate}, dependsOn: r.Action})
	}
	return out
}

// dependencyVerdict returns the policy's verdict on a dependent action. The
// resource it acts on is not known, so the action alone decides.
func dependencyVerdict(action string, doc *policy.Document, strict bool) policy.Result {
	return doc.Coverage(action, nil, nil, strict)
}
