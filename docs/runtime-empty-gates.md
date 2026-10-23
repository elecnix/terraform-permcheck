# A call that needs a non-empty result from an earlier call

This note records why the generator keeps a hand-written correction table for
`iam:RemoveRoleFromInstanceProfile`. It covers whether the parser could express
that condition itself, and the cost of building it.

**Summary: the parser cannot express it today. A fourth gate kind would name
the condition without deciding it, because a plan cannot see a runtime list.
The table is the cheaper fix, and it currently corrects one of the eleven
provider sites that share the pattern.**

## The pattern in the provider source

The provider makes a call that fills a slice, then loops over that slice, and
makes a second call inside the loop body. When the slice is empty the loop body
doesn't run, so the second call happens only if the first call returned
something.

The smallest real example sits in `deleteRoleInstanceProfiles`, in
`internal/service/iam/role.go`:

```go
instanceProfiles, err := findInstanceProfilesForRole(ctx, conn, roleName)
// ...
for _, instanceProfile := range instanceProfiles {
	_, err := conn.RemoveRoleFromInstanceProfile(ctx, input)
	// ...
}
```

`findInstanceProfilesForRole` lives in
`internal/service/iam/instance_profiles_data_source.go` and pages
`ListInstanceProfilesForRole`. A role with no instance profile yields an empty
slice, so the inner call never happens.

The early-return form appears less often:

```go
regions := tfslices.ApplyToAll(replicas, /* ... */)
if len(regions) == 0 {
	return nil
}
_, err := conn.RemoveRegionsFromReplication(ctx, input)
```

`removeSecretReplicas`, in `internal/service/secretsmanager/secret.go`, shows
this form. Its collection comes from the plan rather than from a runtime call,
so the plan can already tell whether `replicas` is empty. It doesn't need new
machinery.

## Gate tests available today

`internal/iam/gates.go` defines `Gate` with three tests, plus a best-effort
flag:

- `Attribute` is a presence test, from `d.GetOk` or `d.Get`.
- `ValueGuarded` is a value test, where the author must have written the
  attribute rather than inherited a provider default.
- `Changed` is a change test, from `d.HasChange`.

`internal/provideraws/guards.go` maps `condGuard` onto those three, so the
parser can emit a gate only for a named plan attribute.

Each of the three tests reads the plan. The condition here is a runtime API
result that the plan does not carry. No attribute means "this role has an
instance profile", so no existing test describes it, and `schemaCorrections`
carries the workaround.

## A fourth gate field

The smallest addition is one field on `Gate`:

```go
// ResultGuarded is the action whose result must be non-empty for this path to
// run, such as "iam:ListInstanceProfilesForRole".
ResultGuarded string
```

The parser would set it in two places. In `walkBody`, on `*ast.RangeStmt`,
when the range expression is a local bound to a call whose target is a runtime
List, Describe or Get. And in `walkStmts`, after an early return on an empty
collection, for the statements that follow it.

The checker cannot evaluate the field. `Gate.holds` would have to assume the
result is non-empty, which keeps the permission reported. That matches today's
ungated entry. The field buys a label:

```
iam:RemoveRoleFromInstanceProfile [conditional: iam:ListInstanceProfilesForRole result]
```

The label separates a call that always runs from one that runs only when
runtime state allows it. `--exclude-conditional` can then drop the second kind,
and the report can explain itself. The label does not remove the false positive
that PR #152 set out to remove. Only dropping the action does that, and the
table drops it.

A test that changed the verdict would need a plan-level signal proving the list
is non-empty. `internal/iam/implied.go` already produces exactly that signal for
this case, in `instanceProfileDetachRequirements`: a co-deleted
`aws_iam_instance_profile` referencing the role. That reasoning holds for one
resource type, not for all of them, so it belongs in the implied-requirements
layer whatever the gate field says.

## Other provider sites with the same pattern

A Go AST scan over `internal/service`, skipping `_gen.go` files and tests, found
37 candidate sites. Classifying each filler, following local helper calls until
a runtime List, Describe or Get appears, leaves 11 real runtime-list sites. They
sit in 10 functions across 9 files and touch 9 resource types. The rest are
plan-derived: `schema.Set.List()`, `Difference`, `flex.ExpandStringValueSet` and
`DiffSlices`.

| File | Function | Call that needs the non-empty list |
| --- | --- | --- |
| `iam/role.go` | `deleteRoleInstanceProfiles` | `RemoveRoleFromInstanceProfile` |
| `iam/role.go` | `readRoleInlinePolicies` | `GetRolePolicy` |
| `iam/user.go` | `deleteUserAccessKeys` | `DeleteAccessKey` |
| `route53/traffic_policy.go` | `resourceTrafficPolicyDelete` | `DeleteTrafficPolicy` |
| `batch/job_definition.go` | `resourceJobDefinitionDelete` | `DeregisterJobDefinition` |
| `workspaces/ip_group.go` | `resourceIPGroupDelete` | `DisassociateIpGroups` |
| `ec2/vpc_dhcp_options.go` | `resourceVPCDHCPOptionsDelete` | `AssociateDhcpOptions` |
| `ec2/vpc_security_group.go` | `forceRevokeSecurityGroupRules` | `RevokeSecurityGroupIngress`, `RevokeSecurityGroupEgress` |
| `comprehend/document_classifier.go` | `resourceDocumentClassifierDelete` | `DeleteDocumentClassifier` |
| `comprehend/entity_recognizer.go` | `resourceEntityRecognizerDelete` | `DeleteEntityRecognizer` |

Three of those still have no gate in the embedded table, so they remain live
false positives of the same class: `route53:DeleteTrafficPolicy`,
`batch:DeregisterJobDefinition` and `workspaces:DisassociateIpGroups`. The read
path of `aws_iam_role` is a fourth, because `iam:GetRolePolicy` has no gate
there and runs only when `ListRolePolicies` returned a name.

The table contains one entry. The pattern occurs about eleven times.

## Recommendation

Extend the table. Reaching the other sites takes a few more entries in
`schemaCorrections`, plus the implied-requirements work for the sites a plan can
corroborate.

| Approach | Files touched |
| --- | --- |
| One table entry per site | `internal/provideraws/source.go` (one struct, one slice and one apply function, already in place), `internal/iam/implied.go` for the re-add path, one regenerated line in `internal/permdata/permissions.json` |
| A fourth gate field | `internal/iam/gates.go` (the field, `holds`, `shownBy`, `evaluateGates`), `internal/iam/schema.go`, `internal/permdata/format.go` (the field plus a format version bump, which invalidates every embedded table), `internal/provideraws/guards.go` and `internal/provideraws/walk.go` (range and early-return detection), plus a filler classifier that separates a runtime list from a plan-derived slice |

The field touches six files across four packages and doesn't change a verdict.
The table touches three files and changes one.

pi-minimax
