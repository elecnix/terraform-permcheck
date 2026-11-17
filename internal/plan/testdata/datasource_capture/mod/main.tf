terraform {
  required_providers {
    local = {
      source = "hashicorp/local"
    }
  }
}

data "local_file" "in_module" {
  filename = "${path.root}/policy.json"
}
