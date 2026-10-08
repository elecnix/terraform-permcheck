#!/bin/sh
# Regenerates plan.json from main.tf and the hand-written terraform.tfstate.
# The provider runs with fake credentials and -refresh=false, so the plan
# makes no AWS API call. terraform init downloads the provider from the
# registry. The state holds aws_sqs_queue.q as "old-q", so the new name
# forces a replace, and aws_sqs_queue.kept, which the removed block forgets.
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -R main.tf modules terraform.tfstate .terraform.lock.hcl "$work"/
(
	cd "$work"
	terraform init -input=false -no-color >/dev/null
	terraform plan -refresh=false -input=false -no-color -out=plan.tfplan >/dev/null
	terraform show -json plan.tfplan | jq . >plan.json
)
cp "$work"/plan.json plan.json
