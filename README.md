# PermCheck

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/elecnix/terraform-permcheck)

**Pre-apply IAM policy validation for Terraform — cloud-agnostic.**

PermCheck ensures your Terraform deploy role has the permissions required
by **every resource** in the plan, **before** `terraform apply` touches a
single cloud API. It cross-references the plan's resource types against your
declared IAM policies using each cloud's native schema registry.

```
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan | terraform-permcheck validate
```

If your deploy role is missing `kms:CreateGrant` for a `aws_backup_vault`, you
find out at plan time — not 3 failed deploys later.

## Motivation

Writing least-privilege IAM policies for a Terraform deploy role is tedious and
error-prone. Every new resource type needs its own set of API permissions, and
those permissions are scattered across AWS/GCP/Azure docs. PermCheck automates
the cross-reference:

1. Parses the `terraform plan -json` to extract every resource type being
   created, updated, or deleted.
2. Maps each terraform resource type to its cloud-native equivalent (e.g.,
   `aws_backup_vault` → `AWS::Backup::BackupVault`).
3. Fetches the required IAM permissions from the cloud's schema registry
   (CloudFormation Resource Schema for AWS, Resource Manager for GCP,
   Resource Provider schemas for Azure).
4. Diffs against your declared IAM policy documents.
5. Fails the pipeline if any required permission is missing.

### Provider source first, CloudFormation second

For AWS, PermCheck first looks up the SDK calls that each resource's create,
read, update and delete functions make in the terraform-provider-aws source.
The parser follows calls into helper functions, retry closures and
paginators, in any file of the service package and in other service packages.
The binary embeds the result of that parse as a table, so a run doesn't clone
or parse the provider (see [Embedded permissions table](#embedded-permissions-table)).
When a type is missing from the table, PermCheck uses the CloudFormation
schema.

The parser reads both kinds of provider resource. An `@SDKResource` binds its
functions in a `schema.Resource` literal. An `@FrameworkResource`, such as
`aws_s3_bucket_lifecycle_configuration`, implements `Create`, `Read`, `Update`
and `Delete` as methods of the type its constructor builds. For those methods,
a guard such as `!data.Policy.IsNull()` gates a call on the attribute that the
field's `tfsdk` tag gives, and `!new.X.Equal(old.X)` gates it on a change.
PermCheck reports a call under any other guard as required.

Sometimes the source parse comes back incomplete. A create or delete function
uses an SDK client, yet the parser finds no call that changes anything. A read
function finds no call at all. PermCheck then adds the CloudFormation
permissions for that operation to what the parse found. A function that never
touches a client, such as a delete that only logs that the resource can't be
destroyed, counts as complete.

### Unresolved resource types

PermCheck can't check a resource type that neither the embedded table nor the CloudFormation registry knows. This happens for a resource type newer than the pinned provider tag, and for a Plugin Framework resource that the registry lacks. PermCheck reports each such type as unresolved, with the resources of that type, and counts it as a gap. The checked count in the summary line leaves out the resources of an unresolved type, in plan mode and in static mode. The run fails with exit code 1 and never prints `All required permissions covered`.

Each output format reports unresolved types:

- `text` lists them under `Unresolved resource types (N), no permission data:`, one entry per type, followed by its resources.
- `github-annotations` writes one `::warning` per type, titled `Unresolved resource type`, with the file and line of its first resource when `--terraform-root` gives locations.
- `json` lists them in a top-level `unresolved_types` array. Each entry has `resource_type`, `allowed`, and `resources`, with `resource_name`, `change`, and the file and line when known. The `missing` array keeps its old content.

To accept the gap for every unresolved type, pass `--allow-unresolved-types` or set `"allow_unresolved_types": true` in the config file. A flag, `true` or `false`, overrides the config. To accept it for one type, add an exclusion with `"permission": "*"` and a `resource` pattern that matches the type, such as `{"permission": "*", "resource": "aws_example_widget", "reason": "checked by hand"}`. A narrower permission pattern, such as `s3:*`, doesn't match an unresolved type. In both cases PermCheck still reports the type, and the summary line ends with `N resource types unresolved (allowed)` in place of the all-clear line. In `json`, `unresolved_allowed` gives that count.

A lookup that fails for another reason, such as a network error, a timeout, or an HTTP 5xx or 429 from the registry, stops the run with exit code 2. PermCheck can't tell whether such a type exists, so it neither checks it nor reports it as unresolved. Run the check again once the registry answers. The registry answers 403 or 404 for a type it doesn't hold, and PermCheck reads both as unresolved.

### Conditional & side-effect permissions

Some permissions are only needed when a particular attribute is set. The AWS
provider, for example, makes an extra `kms:TagResource` call when an
`aws_kms_key` declares a `tags` block — a side effect that isn't part of the
primary `kms:CreateKey` action. PermCheck reads the planned attribute values
and only requires such permissions when their gating attribute is actually
present, so you neither miss them (when tags are set) nor get false positives
(when they aren't). A `tags` value computed at apply time (known after apply)
still counts as set — the tags get applied, so the permission is still required.

### Permissions gated on a change

Other permissions are only needed when an attribute **changes**. The provider
calls `iam:PutRolePermissionsBoundary` for an `aws_iam_role` only when
`permissions_boundary` changes, and calls `iam:DeleteRolePermissionsBoundary`
only when a set boundary is removed. A plan that updates `assume_role_policy`
alone needs neither call.

In plan mode PermCheck compares the prior value of the attribute with the
planned value and requires the permission only when the two differ. An
attribute computed at apply time counts as changed, because the provider
applies a diff for it. Static HCL mode has no prior state, so it reports those
permissions; `--only-required` suppresses them.

A guard that compares the attribute's value rather than its presence — a set
that must be non-empty, say — reads a value the provider's own default already
fills. Deleting an `aws_secretsmanager_secret_version` whose `version_stages`
was never written still shows `["AWSCURRENT"]` in the prior state, and the
provider skips `UpdateSecretVersionStage` for that label, so presence alone
reported a permission the apply never needs. For those guards PermCheck reads
the plan's configuration section instead: an attribute the configuration does
not write is one holding a default, and the call does not run. With no
configuration to read — static HCL mode — both kinds of guard fall back to
presence and the permission is reported.

Some calls can fail without failing the apply. The provider discards their
error (`out, _ := conn.GetX(...)`, `if v, err := f(); err == nil`), swallows it
(`if err != nil { return sseList }`), or makes the call only to clean up after
an earlier call failed (`if err != nil { deleteRole(...); return err }`). The
`aws_dynamodb_table` read, for example, looks up the account's default
DynamoDB KMS key and keeps its state as it is when the lookup fails. PermCheck
reports these calls as `[optional]`, so the default filter drops them and
`--no-filter` shows them.

### API Gateway actions by HTTP verb

API Gateway checks the HTTP verb of each call, under the `apigateway` prefix,
for both the v1 (REST) and v2 (HTTP and WebSocket) APIs. IAM has no
`apigatewayv2` prefix. PermCheck reports `apigateway:POST` for
`CreateDomainName`, `apigateway:GET` for `GetApiMapping`, `apigateway:PATCH`
for an update and `apigateway:DELETE` for a delete. Tagging follows the route
of each API: v1 `TagResource` is `apigateway:PUT`, v2 `TagResource` is
`apigateway:POST`, and `UntagResource` is `apigateway:DELETE`. PermCheck
matches the verb only. It does not check the path-style resource ARN, such as
`arn:aws:apigateway:us-east-1::/domainnames/*`.

### Cross-service callback permissions

Some AWS APIs require an IAM action from a *different* service than the one the
Terraform provider calls. `aws_wafv2_web_acl_association` calls
`wafv2:AssociateWebACL`, but AWS WAFv2 then calls into the target service to
attach the ACL — so associating a Web ACL with an **ALB** additionally requires
`elasticloadbalancing:SetWebACL`, an **API Gateway stage** requires
`apigateway:SetWebACL`, and an **AppSync API** requires `appsync:SetWebACL`.
These callbacks are invisible to both the CloudFormation schema and the
provider source, so PermCheck adds them explicitly:

- When the target's `resource_arn` is a known ARN, only the callback for that
  ARN's service is required.
- When `resource_arn` is computed at apply time (it references a resource
  created in the same plan) or you're in static HCL mode, PermCheck can't tell
  which target applies, so it over-approximates and reports every candidate
  callback tagged `[conditional: resource_arn]`. Use `--only-required` to
  suppress that over-approximation.

### Resource-scoped grants

Some IAM grants are scoped to a specific resource ARN rather than the whole
service. A policy that grants `secretsmanager:PutSecretValue` on one secret's
ARN does **not** authorize putting a version on a different secret — yet a
pure action-name check reports it covered, and the apply fails with
`AccessDeniedException`. When the target resource's ARN is derivable from the
plan, PermCheck checks the grant's `Resource` patterns against that ARN
rather than only the action name:

- `aws_secretsmanager_secret_version` derives its target from the referenced
  secret's configured `name` (or a literal ARN `secret_id`).
- `aws_secretsmanager_secret` derives its own ARN from its `name`.
- `aws_sqs_queue` derives its own ARN from its `name`.
- `aws_cloudwatch_log_group` derives its own ARN from its `name`, in both the
  `log-group:<name>` and `log-group:<name>:*` forms that policies grant.
- `aws_cloudwatch_log_stream` derives its group's ARN from `log_group_name`
  (a known value, or a reference to an `aws_cloudwatch_log_group` with a known
  `name`), plus the stream's own `log-stream:<name>` ARN.
- `iam:PassRole` is required for resources that hand a role to a service
  (`aws_lambda_function`, `aws_sfn_state_machine`, `aws_codebuild_project`,
  `aws_ecs_task_definition`, `aws_cloudwatch_event_target`,
  `aws_apigatewayv2_integration`). The role comes from a literal ARN in the
  `role` or `role_arn` attribute, or from a reference to an `aws_iam_role`
  with a known `name`.
- PermCheck checks cross-service callbacks, such as
  `elasticloadbalancing:SetWebACL`, against the `resource_arn` of
  `aws_wafv2_web_acl_association` when that value is a literal ARN.

A grant whose `Resource` provably cannot apply to the target is reported
missing (e.g. `PutSecretValue` on `example-b` with a grant on `example-a-*`).
Where the target ARN is unknown — the value is computed at apply time with no
reference to a managed resource, or you're in static HCL mode — PermCheck
falls back to today's action-only match rather than risk a false positive.

Resource types without a rule above get an action-name check only. For
example, a policy that grants `lambda:*` on one function still passes for a
different function, and the apply then fails with `AccessDenied`. A passing
report is a lower bound for those cases.

### Strict resource scope

Pass `--strict-resources` to stop counting those unchecked grants as coverage.
With it, PermCheck reports an action as unverified when both hold:

- PermCheck can't derive the target ARN from the plan. The resource type has
  no rule above, or its rule can't build the ARN because terraform computes a
  value at apply time.
- Every `Allow` statement that grants the action limits it to some resources.
  A `Resource` list without `"*"` or `"arn:*"` limits it, and so does any
  `NotResource` list.

A grant on `"*"` still covers the action. So does a grant checked against a
derived ARN. The same rule applies to `iam:PassRole` when the role ARN is
unknown, and to cross-service callbacks when `resource_arn` is unknown.

Unverified findings count as gaps: they fail the run unless you pass
`--exit-zero`, and config exclusions apply to them. Each output format tags
them:

- `text` lists them under their own heading, `Unverified IAM permissions`,
  with the tag `[unverified: resource scope]` on each action.
- `github-annotations` writes a `::warning` titled `Unverified IAM permission`
  with the same tag.
- `json` sets `"unverified": "resource_scope"` on each entry in `missing`.

Static HCL mode reads `.tf` files and has no ARNs at all. With
`--strict-resources`, every action that the policy grants only on some
resources gets the unverified tag there.

You can also turn the check on in the config file with
`"strict_resources": true`. A `--strict-resources` or
`--strict-resources=false` flag overrides the config.

### Policy evaluation

PermCheck reads one policy document. `Statement` may be one object or an
array. `Action`, `NotAction`, `Resource` and `NotResource` may each be a
string or a list. `Effect` must be `Allow` or `Deny`, spelled with that case.
AWS rejects any other value, and so does PermCheck.

Action patterns accept `*` and `?` anywhere, so `secretsmanager:*SecretValue`
grants `secretsmanager:PutSecretValue`. Action names match without regard to
case, as in IAM. Resource ARNs match with case.

A `Deny` that matches the action overrides any `Allow`, but only when it
provably applies:

- The `Deny` has no `Condition`. PermCheck can't evaluate condition keys, so
  a conditional `Deny` might never apply. PermCheck doesn't report it.
- The `Deny` covers the whole target. When PermCheck doesn't know the target
  ARN, only a `Resource` that matches every ARN counts, such as `"*"`,
  `"arn:*"` or `"arn:aws:*"`. When it knows the target, a `Resource`
  pattern must contain the target pattern, or no `NotResource` pattern may
  overlap it. A `Deny` on one region or account doesn't count against a target
  that could be in any region or account.
- The plan doesn't show the partition. PermCheck takes the policy to be
  written for the partition it deploys to, so a `Deny` on
  `arn:aws:sqs:*:*:*` covers every queue in the plan. For an action that
  takes no resource, AWS matches the `Deny` against `"*"`, which an `arn:`
  pattern doesn't match. PermCheck can't tell those actions apart, so it may
  report such an action as missing.

An `Allow` with a `Condition` still counts as a grant. `NotAction` grants or
denies every action outside its list. A `NotResource` grant covers any target
outside its list, and doesn't cover a target that a listed pattern contains.

Permission boundaries, service control policies, session policies and
resource-based policies are out of scope.

### Excluding known false positives

Some reported gaps are correct but unactionable — a least-privilege deploy role
may intentionally lack a permission for a resource it never manages (e.g. a role
scoped to application resources that can't touch a separate audit/CloudTrail
module's S3 buckets). Those findings are noise. PermCheck reads an exclusion
list from a config file (`permcheck.json`, auto-discovered in the working
directory, or pointed at with `--config`):

```json
{
  "exclude": [
    {
      "permission": "s3:DeleteBucketPublicAccessBlock",
      "reason": "CloudTrail bucket lifecycle managed by a separate audit role"
    },
    {
      "permission": "secretsmanager:UpdateSecretVersionStage",
      "resource": "aws_secretsmanager_secret.forwarder",
      "reason": "Forwarder key version stages managed out-of-band"
    },
    {
      "permission": "s3:DeleteBucketEncryption",
      "resource": "aws_s3_bucket_server_side_encryption_configuration.*",
      "operations": ["delete"],
      "reason": "Buckets under object lock must never lose their encryption config"
    }
  ]
}
```

- **`permission`** (required) — the IAM action to suppress. Supports glob
  patterns, e.g. `s3:*`.
- **`resource`** (optional) — scopes the exclusion to matching terraform
  resources. Matched against the resource type (`aws_secretsmanager_secret`) or
  the full address (`aws_secretsmanager_secret.forwarder`); supports globs like
  `aws_secretsmanager_*`. Omit to apply the exclusion to every resource.
- **`operations`** (optional) — limits the exclusion to the named terraform
  operations: `create`, `update`, `delete`, or `read`. Omit to apply the
  exclusion to every operation.
- **`reason`** (optional) — a note kept for the audit trail.

The config file also accepts `"strict_resources": true` at the top level. It
turns on `--strict-resources`, described in
[Strict resource scope](#strict-resource-scope). Likewise,
`"allow_unresolved_types": true` turns on `--allow-unresolved-types`, described
in [Unresolved resource types](#unresolved-resource-types).

`operations` lets you suppress a permission for one operation only, so a role
that must never delete a resource still gets checked on create and update. An
unknown operation name is a config error, so a typo fails the run instead of
silently excluding nothing.

Excluded permissions are dropped from the gap report and no longer fail the run,
but the suppression is **not** silent by default — pass `--show-excluded` to
list what was suppressed (and why) so reviewers can audit it. In `--format json`
the suppressed entries appear under an `excluded` array; in `github-annotations`
mode they surface as `::notice::` lines.

### Permissions a principal needs beyond terraform

Terraform resources do not show every permission a role needs. A CI workflow
may call `aws ecr describe-images` before it deploys. An application may read a
secret when it starts. Declare these permissions in the `needs` list of the
config file, and PermCheck checks them against the same policy as the plan:

```json
{
  "needs": [
    {
      "sid": "EcrAuth",
      "actions": ["ecr:GetAuthorizationToken"],
      "resources": ["*"],
      "reason": "docker login in the deploy workflow"
    },
    {
      "sid": "EcrImageVerification",
      "principal": "deploy",
      "actions": ["ecr:DescribeImages"],
      "resources": ["arn:aws:ecr:us-east-1:123456789012:repository/my-app"],
      "reason": "CI verifies images before deploy"
    },
    {
      "sid": "FetchSecrets",
      "principal": "task",
      "actions": ["secretsmanager:GetSecretValue"],
      "resources": ["arn:aws:secretsmanager:us-east-1:123456789012:secret:my-app-*"]
    }
  ]
}
```

- **`sid`** (required) names the need in the report. Needs that run together
  must have different sids. A need without a principal runs on every run, so
  no other need may reuse its sid. Needs under two different principals may
  share a sid.
- **`actions`** (required) lists the IAM actions, each a single
  `service:Action` name without wildcards.
- **`resources`** (optional) lists the ARNs or ARN patterns the actions act
  on. The policy must cover each one. PermCheck uses the same resource-scoped
  check as for plan resources, so a Deny on the resource counts. `"*"` means
  the policy must grant the action on every resource. Without `resources`, any
  grant of the action counts, as for a resource whose ARN the plan does not
  show. `--strict-resources` then reports a grant limited to some resources as
  unverified.
- **`principal`** (optional) names the role the need belongs to. PermCheck
  checks one policy per run, so a need with a principal applies only when
  `--principal` names it. A need without a principal applies on every run.
  An unknown `--principal` value is an error.
- **`reason`** (optional) is a note for reviewers.

With the config above, check the deploy role and the task role in two runs:

```bash
terraform-permcheck validate --plan-file plan.json --cloud aws \
  --policy-from-plan-output deploy_policy_json --principal deploy
terraform-permcheck validate --plan-file plan.json --cloud aws \
  --policy-from-plan-output task_policy_json --principal task
```

A missing need is reported like any other gap, with the need as its source:

```
::warning title=Missing IAM permission::ecr:DescribeImages needed by: needs "EcrImageVerification" on arn:aws:ecr:us-east-1:123456789012:repository/my-app
```

In `--format json`, the finding carries `need` and `need_resource` in place of
`resource_type`, `resource_name` and `change`. A missing need fails the run
unless `--exit-zero` is set. An exclusion can suppress it: its `permission`
matches the action, and its `resource` matches `needs.<sid>`.

PermCheck checks the needs against the one policy it is given. It does not
collect the other policies in the plan or evaluate resource-based policies.

## Supported clouds

| Cloud | Schema source | Status |
|-------|--------------|--------|
| **AWS** | CloudFormation Resource Schema Registry | ✅ MVP |
| **GCP** | Cloud Asset Inventory / IAM API | 🔜 planned |
| **Azure** | Resource Provider operations API | 🔜 planned |

## Usage

### CLI

```bash
# Pipe the plan JSON directly
terraform show -json plan.tfplan | terraform-permcheck validate \
  --policy-file deploy_policy.json \
  --cloud aws

# Or point at files
terraform-permcheck validate \
  --plan-file plan.json \
  --policy-file deploy_policy.json \
  --cloud aws
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `text` | Output format: `text`, `github-annotations`, or `json` |
| `--exit-zero` | `false` | Exit 0 even when gaps are found (warn, don't fail) |
| `--config` | `./permcheck.json` | Path to the config file (auto-discovered in the working directory when present) |
| `--show-excluded` | `false` | List config-excluded permissions in the report (suppressed silently by default) |
| `--principal` | none | Also check the config needs declared for this principal (see [Permissions a principal needs beyond terraform](#permissions-a-principal-needs-beyond-terraform)) |

| `--provider-source` | `embedded` | Where provider-source permissions come from: `embedded` reads the table built into the binary, `live` clones and parses terraform-provider-aws (see [Embedded permissions table](#embedded-permissions-table)). `PERMCHECK_PROVIDER_SOURCE` sets the default |
| `--strict-resources` | `false` | Report an action as unverified when its target ARN is unknown and the policy grants it only on some resources (see [Strict resource scope](#strict-resource-scope)). The config key `strict_resources` sets the default |
| `--allow-unresolved-types` | `false` | Report resource types that no schema source knows, but don't fail the run on them (see [Unresolved resource types](#unresolved-resource-types)). The config key `allow_unresolved_types` sets the default |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All permissions covered (or `--exit-zero` was set) |
| 1 | Permission gaps found, unverified findings under `--strict-resources` and unresolved resource types included (details printed to stderr) |
| 2 | Invalid input or configuration error, or a schema lookup that failed (network error, timeout, HTTP 5xx) |

### Embedded permissions table

The binary embeds the permissions of every terraform-provider-aws resource type at a pinned tag, `v5.90.0`. The table is `internal/permdata/permissions.json`. For each resource type it lists, per operation, each IAM action and the attribute tests that guard the provider's call. It also marks the operations whose parse missed calls, and PermCheck adds CloudFormation permissions to those. A default run reads this table, so it doesn't need git, network access to GitHub, or a provider clone.

To bump the provider version, change `DefaultProviderRef` in `internal/provideraws/source.go`, then regenerate the table and commit it:

```bash
go run . generate-permissions --out internal/permdata/permissions.json
```

The command clones the new tag into the provider cache and parses it. To parse a checkout you already have, pass `--provider-dir DIR`. The checkout must be at `DefaultProviderRef`. Without `--out`, the command writes the table to stdout. The output is deterministic, so regenerating an unchanged tree writes the same bytes. A test fails when the table's tag differs from `DefaultProviderRef`, and the CI job `permissions-drift` regenerates the table and fails when it differs from the committed one. Regenerate the table after a parser change too.

### Live provider source

Pass `--provider-source live`, or set `PERMCHECK_PROVIDER_SOURCE=live`, to clone and parse the provider source at run time. Use it to try a parser change without regenerating the table. The live parse takes the place of the embedded table, and CloudFormation still fills the gaps.

The first live run makes a shallow clone of the pinned tag from GitHub. Later runs reuse the clone and do not fetch again.

The clone goes in a directory named after the tag, under `terraform-permcheck/provider-aws` in your user cache directory. On Linux that is `$XDG_CACHE_HOME`, or `~/.cache` when it is unset. On macOS it is `~/Library/Caches`. Set `PERMCHECK_PROVIDER_CACHE_DIR` to use another base directory. The clone still goes in a subdirectory named after the tag.

Concurrent runs can share one cache. Each run locks a file next to the clone before it reads or writes the clone, so runs take turns. If a clone is incomplete or at the wrong commit, the run replaces it.

To free space, delete the clones that older versions made, unless you use the live source. Older versions cloned into the cache directory above, or into `~/.cache/terraform-permcheck/provider-aws` for the oldest.

### Terraform provider (planned)

```hcl
data "tf-permcheck_iam_check" "deploy_role" {
  cloud             = "aws"
  plan_file         = "plan.tfplan.json"
  policy_documents  = [
    data.aws_iam_policy_document.deploy_core.json,
    data.aws_iam_policy_document.deploy_backup.json,
  ]
}
```

## Install

```bash
go install github.com/elecnix/terraform-permcheck@latest
```

## CI integration

### Hard fail (block the PR on missing permissions)

```yaml
# .github/workflows/pr-tests.yml
- name: Check IAM permissions
  run: |
    terraform plan -out=plan.tfplan
    terraform show -json plan.tfplan | terraform-permcheck validate \
      --policy-file <(terraform output -raw deploy_policy) \
      --cloud aws
```

### Soft warn (annotate the PR diff without failing the check)

```yaml
- name: Check IAM permissions
  run: |
    terraform plan -out=plan.tfplan
    terraform show -json plan.tfplan | terraform-permcheck validate \
      --policy-file <(terraform output -raw deploy_policy) \
      --cloud aws \
      --format github-annotations \
      --exit-zero
```

With `--format github-annotations`, each missing permission group produces a
`::warning::` workflow command that GitHub Actions surfaces as a ⚠️ annotation
in the PR diff. `--exit-zero` ensures the step itself succeeds so the check
passes green while surfacing warnings.

## License

MIT — see [LICENSE](LICENSE).
