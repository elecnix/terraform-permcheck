# PermCheck

**Pre-apply IAM policy validation for Terraform — cloud-agnostic.**

PermCheck ensures your Terraform deploy role has the permissions required
by **every resource** in the plan, **before** `terraform apply` touches a
single cloud API. It cross-references the plan's resource types against your
declared IAM policies using each cloud's native schema registry.

```
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan | tf-permcheck validate
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
terraform show -json plan.tfplan | tf-permcheck validate \
  --policy-file deploy_policy.json \
  --cloud aws

# Or point at files
tf-permcheck validate \
  --plan-file plan.json \
  --policy-file deploy_policy.json \
  --cloud aws
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All permissions covered |
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

```yaml
# .github/workflows/pr-tests.yml
- name: Check IAM permissions
  run: |
    terraform plan -out=plan.tfplan
    terraform show -json plan.tfplan | tf-permcheck validate \
      --policy-file <(terraform output -raw deploy_policy) \
      --cloud aws
```

## License

MIT — see [LICENSE](LICENSE).
