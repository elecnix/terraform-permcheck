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

A grant whose `Resource` provably cannot apply to the target is reported
missing (e.g. `PutSecretValue` on `example-b` with a grant on `example-a-*`).
Where the target ARN is unknown — the value is computed at apply time with no
reference to a managed resource, or you're in static HCL mode — PermCheck
falls back to today's action-only match rather than risk a false positive.

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

`operations` lets you suppress a permission for one operation only, so a role
that must never delete a resource still gets checked on create and update. An
unknown operation name is a config error, so a typo fails the run instead of
silently excluding nothing.

Excluded permissions are dropped from the gap report and no longer fail the run,
but the suppression is **not** silent by default — pass `--show-excluded` to
list what was suppressed (and why) so reviewers can audit it. In `--format json`
the suppressed entries appear under an `excluded` array; in `github-annotations`
mode they surface as `::notice::` lines.

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

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All permissions covered (or `--exit-zero` was set) |
| 1 | Permission gaps found (details printed to stderr) |
| 2 | Invalid input or configuration error |

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
