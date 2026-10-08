# Source of plan.json. Run regenerate.sh after changing it.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.0.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# In the state as "old-q". The new name forces a replace.
resource "aws_sqs_queue" "q" {
  name = "new-q"
}

# Same type and name as aws_sqs_queue.q, inside a module.
module "prod" {
  source = "./modules/queue"
  name   = "prod-orders"
}

# In the state; the removed block forgets it without deleting it.
removed {
  from = aws_sqs_queue.kept
  lifecycle {
    destroy = false
  }
}

resource "aws_iam_role" "r" {
  name = "app"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}

# Reads a value known only after apply, so terraform defers the read.
data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.q.arn]
  }
}

resource "aws_organizations_organizational_unit" "ou" {
  name      = "apps"
  parent_id = "r-abcd"
}

# parent_id comes from the OU, so the plan shows it as unknown.
resource "aws_organizations_account" "a" {
  name      = "acct"
  email     = "a@example.com"
  parent_id = aws_organizations_organizational_unit.ou.id
}
