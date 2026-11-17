# The configuration behind plan.json, which records where `terraform show -json`
# puts a data source. It needs no cloud credentials. To capture it again:
#
#   terraform init && terraform plan -out=plan.tfplan
#   terraform show -json plan.tfplan > plan.json
#
# plan.json drops timestamp, relevant_attributes and the content hashes of
# local_file.

terraform {
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "2.5.2"
    }
  }
}

resource "terraform_data" "later" {
  input = "policy.json"
}

# Every argument is known, so terraform reads it during the plan.
data "local_file" "known" {
  filename = "${path.module}/policy.json"
}

# The filename depends on a value computed at apply time, so terraform
# defers the read to the apply.
data "local_file" "deferred" {
  filename = "${path.module}/${terraform_data.later.id}"
}

resource "terraform_data" "uses" {
  input = data.local_file.known.content
}

module "app" {
  source = "./mod"
}

# Every argument is known, but depends_on on a resource with pending
# changes defers the read to the apply.
data "local_file" "depends" {
  filename   = "${path.module}/policy.json"
  depends_on = [terraform_data.later]
}
