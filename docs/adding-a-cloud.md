# Adding a cloud provider

PermCheck 1.0 covers AWS only. Azure and Google Cloud are outside 1.0, and a contributor can add either one. This guide lists the six pieces a cloud needs. For each piece it shows where AWS handles it today and what a new cloud must provide.

Every path below is relative to the repository root. Read the AWS code first, because the new cloud follows the same data flow:

1. The CLI reads a Terraform plan (or static HCL) and a policy.
2. Each resource type resolves to a schema of required actions, per operation.
3. PermCheck checks each required action against the policy.
4. The report lists the actions the policy doesn't grant.

## Permission source

A permission source answers one question: which actions does an operation on this resource type need?

AWS has three sources, chained in `internal/check/check.go` (`providers`), most precise first:

- `internal/permdata` embeds `permissions.json`, a table generated from the `terraform-provider-aws` Go source. `Embedded()` returns it as an `iam.Resolver`. This is the default.
- `internal/provideraws` parses that Go source and finds the SDK calls each resource makes. `go run . generate-permissions --out internal/permdata/permissions.json` writes the table, and `--provider-source live` parses the source at run time. The pinned release is `DefaultProviderRef` in `internal/provideraws/source.go`.
- `internal/cloud/aws.go` reads the CloudFormation resource schema registry. `internal/cloud/cloud.go` has `ChainProvider`, which falls back to it when the first source doesn't know a type or marks an operation incomplete.

A new cloud must provide a type that satisfies the interface in `internal/iam/schema.go`:

```go
type Resolver interface {
	Resolve(tfType string) (*Schema, error)
}
```

`Resolve` returns an `iam.Schema`. Its `Ops` map has the keys `create`, `read`, `update`, `delete` and `list`. Each key lists `iam.Requirement` values, one per code path to an action. A requirement has a `Gate`, which says whether the provider makes the call only when an attribute has a value or has changed.

A resolver wraps `iam.ErrUnknownType` when it doesn't know the type, and PermCheck reports the type as unresolved. It wraps `iam.ErrLookupFailed` when a lookup didn't finish, such as after a network failure, and PermCheck stops with the error.

Pick the most precise source the cloud offers. For Azure that is the `azurerm` provider source, with the resource provider operations API as the fallback. For Google it is the `google` provider source, with the IAM permissions API as the fallback. Generate an embedded table the same way `generate-permissions` does, so a regenerated table diffs as text in review.

## Action format

AWS actions are IAM actions such as `kms:CreateGrant`. Several places read the `service:Operation` shape:

- `iam.MissingAction.Service` takes the part before the colon. It lives in `internal/iam/validate.go`.
- `internal/iam/gates.go` and `internal/iam/knowledge.go` classify actions as data-plane, optional-feature or dedicated to a sub-resource.
- `internal/policy/policy.go` matches an action against a statement with `matchesWildcard`.
- `internal/iam/arn.go` and `internal/policy/arn.go` build and compare AWS ARNs.

Azure uses RBAC operations such as `Microsoft.Storage/storageAccounts/write`. Google uses IAM permissions such as `storage.buckets.create`. Neither has the `service:Operation` shape, so a new cloud must decide how each of the places above reads its action. Keep the action a plain string in `iam.Requirement.Action`, as AWS does, and put the cloud's matching rules behind the policy evaluator described next.

Much of `internal/iam` is AWS knowledge and stays AWS-only: `passrole.go`, `servicelinkedrole.go`, `managedsecret.go`, `cross_service.go` and `condition_keys.go`. A new cloud adds its own equivalents only when its provider has the same kind of implied permission. Start without them, and add one when a test shows a missing finding.

## Policy evaluation

Policy evaluation answers a second question: does the grant cover this action on this resource?

For AWS, `internal/policy` parses an IAM policy document (`policy.Parse`) and decides coverage. `Document.Covers` takes an action and the condition key values the plan supplies. `internal/policy/coverage.go` is the one entry that every check goes through, so requirements, implied requirements and declared needs follow one rule set. `internal/policy/condition.go` decodes the `Condition` block and matches it against the values the plan shows. When the target ARN or a condition value is unknown, the result is unverified rather than covered, and `--strict-resources` reports it.

`internal/iam/validate.go` calls the policy through `iam.Validate(changes, doc, resolver, filter)`. That function is where requirements meet the grant.

A new cloud must provide an evaluator that follows these rules:

- **Azure** grants permissions through role assignments at a scope (management group, subscription, resource group or resource). A role definition lists `actions`, `notActions`, `dataActions` and `notDataActions`. The evaluator must test that the target resource ID sits under the assignment's scope, and that `notActions` doesn't remove the operation.
- **Google** grants permissions through IAM bindings that attach a role to a member on a resource, inherited down the project hierarchy. A binding can carry a CEL condition. The evaluator must expand roles to permissions and test the condition against the values the plan supplies.

Whatever the cloud, the evaluator must return "unverified" when the plan can't show a value the grant depends on. Reporting such a grant as covered hides a gap, and reporting it as missing is a false alarm. AWS keeps these two cases apart, and a new cloud must too.

The AWS code calls `policy.Document` directly. A contributor will likely introduce a small interface at the `iam.Validate` boundary, so `iam` accepts any cloud's evaluator. Do that in its own pull request first, with the AWS tests unchanged, and add the new cloud in a second one.

## Plan reading

The plan reader turns Terraform's JSON into the resource changes PermCheck checks.

- `internal/plan/plan.go` has `Parse(raw, prefix)`. The prefix, `aws_` for AWS, selects which resource types count. `ResourceChange` records the type, the change kind, which attributes are set (`Attributes`), which changed (`ChangedAttributes`), their string values (`AttributeValues`), and the references the configuration section keeps (`References`). Gates read these maps. A replace becomes a delete followed by a create.
- `internal/plan/path.go` reads nested attribute paths such as `ttl.0.enabled`.
- `internal/hcl/parser.go` does the same job for static HCL mode. Its `resourceRE` matches `aws_*` resource and data blocks only, so a new cloud needs its own prefix there.
- `internal/iam` maps a change to its targets, the resources the action acts on. `internal/iam/arn.go` builds the ARN patterns, `internal/iam/references.go` resolves references between resources, and `internal/iam/resource_scope.go` scopes an action to a resource. A new cloud needs its own target form: an Azure resource ID or a Google resource name.

The prefix is the only cloud-specific input to `plan.Parse`, so a plan for `azurerm_` or `google_` resources parses without changing the reader. The target mapping in `internal/iam` is where most new code goes.

## Tests

PermCheck follows red, green, refactor. Write a failing test that shows the wrong finding or the missing one, make it pass, then clean up. The existing tests show the patterns:

- Unit tests sit next to the code, as `*_test.go` files in each package.
- `verdict_iam_test.go` at the repository root runs the `validate` command end to end. Each `verdictCase` names a plan and a policy under `testdata/verdict-iam/`, then lists the findings that must appear (`present`) and must not appear (`absent`). Findings read `<type>.<name> <action>`.
- `verdict_plan_test.go` and `report_golden_test.go` cover plan handling and the report format. Golden files live in `testdata/report/`.
- `internal/provideraws/differential_test.go` pins the parser's output against recorded goldens.
- `internal/permdata/permdata_test.go` checks that the embedded table matches its generator and the pinned ref.
- `testdata/realplan/` has a plan made by a real `terraform plan`, with `regenerate.sh` to rebuild it.

Before a cloud's first release it must cover:

- A resolver test for a known type, an unknown type (`iam.ErrUnknownType`) and a failed lookup (`iam.ErrLookupFailed`).
- A gate test for each gate kind the cloud's source emits. The kinds are an attribute that has a value, an attribute that changed, and a call whose failure the provider ignores.
- Evaluator tests for a grant that covers, one that doesn't, an explicit deny, a wildcard, an unknown target and an unknown condition value.
- A `verdictCase` with a plan and a policy under `testdata/verdict-iam/`, where the cloud's resources need a permission the policy lacks.
- A plan from a real `terraform plan` with the cloud's provider, so the plan reader meets real output.
- A check of the permission table against real calls. AWS is adding this as the probe harness in [#204](https://github.com/elecnix/terraform-permcheck/issues/204). A new cloud's table needs the same comparison.

## CLI and config

The `--cloud` flag is the entry point. In `main.go`, `validateCmd` reads it into `cloudName` and passes it to `check.CloudPrefix` in `internal/check/policysource.go`:

```go
switch name {
case "":
	return "", fmt.Errorf("--cloud is required (supported: aws)")
case "aws":
	return "aws_", nil
}
```

A new cloud adds a `case` that returns its Terraform prefix. The error messages that say `supported: aws` change with it, and so do the flag's help text and the usage comments at the top of `main.go`.

The resolver chain comes from `check.ResolverFor`, which builds one chain for AWS. A new cloud needs its own chain, chosen by cloud name, and `--provider-source` and `PERMCHECK_PROVIDER_SOURCE` must apply to it.

`internal/config/config.go` reads `permcheck.json`. Its fields are mostly cloud-neutral: `exclude`, `strict_resources`, `needs` and `allow_unresolved_types`. These parts assume AWS:

- `iam.Exclusion` matches an IAM action with a glob, and `iam.Need` lists IAM actions. A new cloud's actions need the same fields with their own validation (`ValidateExclusions` and `ValidateNeeds` in `internal/iam`).
- A config file has no cloud field today. When a second cloud exists, decide whether one config file serves both or whether each cloud has its own.

`internal/report` prints findings in text, JSON and GitHub annotation formats. The formats work for any action string, so a new cloud rarely changes them.

## Checklist for a pull request

A pull request that adds a cloud must meet each item:

- [ ] `--cloud <name>` works end to end, and `check.CloudPrefix` returns the cloud's resource prefix.
- [ ] A resolver for the cloud satisfies `iam.Resolver` and wraps `iam.ErrUnknownType` for an unknown type and `iam.ErrLookupFailed` for a lookup that didn't finish. A cloud that embeds a table also adds a generator.
- [ ] The policy evaluator covers the cloud's grant model, and returns "unverified" when the plan can't show a value.
- [ ] Plan reading and static HCL mode both accept the cloud's resource prefix.
- [ ] Every item under "Before a cloud's first release it must cover" has a test, and `go test ./...` passes.
- [ ] Each behavior change has a test that failed before the change.
- [ ] The README's "Supported clouds" table lists the cloud with its schema source, and `site/index.html` says the same.
- [ ] The AWS tests pass unchanged. A change to shared code is in its own pull request when it can be.
- [ ] The pull request body gives the provider version the table comes from, and the command that regenerates it.
