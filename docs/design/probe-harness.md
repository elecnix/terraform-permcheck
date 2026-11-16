# A probe harness that checks the permission table against AWS

Status: design for [#204](https://github.com/elecnix/terraform-permcheck/issues/204), part of [#202](https://github.com/elecnix/terraform-permcheck/issues/202).
The owner approved it and answered its open questions. The answers are part of
the design below, and one question is still open.

PermCheck's embedded table comes from parsing the Go source of
terraform-provider-aws. No test compares it with the calls AWS authorizes.
So far a person has checked one requirement by hand in a real account, the
Backup pair in [#179](https://github.com/elecnix/terraform-permcheck/issues/179).

This document describes a harness that makes that comparison for each resource
type it covers. For one type, it applies a minimal configuration taken from the
provider's acceptance tests. The apply runs under a role whose policy grants
exactly what PermCheck says the plan needs. CloudTrail records the calls, the
harness destroys the resources, and a comparison step sorts each action into a
category: confirmed, missing, or granted but never called.

The probe is a manual tool. A maintainer starts it by hand from their own
machine, with their own short-lived credentials. It never runs in CI, and its
results don't block a pull request or a release.

The sections below answer the six questions in the issue, then cover how a
finding becomes a fix, how the harness treats a call that the provider makes
only under a runtime condition, how it runs provider 5.x and 6.x against the
one table from [#200](https://github.com/elecnix/terraform-permcheck/pull/200),
and how it keeps account details out of public output. It ends with the
owner's decisions, the question still open, and the stages.

## Decisions at a glance

| Question | Decision |
|----------|----------|
| 1. Guardrails | A member account used for the harness alone, in `us-east-1` only. Its SCP denies purchases and long commitments. The same SCP denies expensive services to a principal without the `expensive` tier tag, and guards the harness's own roles and trail. A $30 monthly budget applies both a deny policy in the account and a deny-all SCP at its cap. aws-nuke empties the account before and after each run. |
| 2. Credentials | A maintainer signs in on their own machine and gets short-lived credentials, then the runner assumes a harness role in the probe account. The harness role creates a probe role per resource type, and the provider assumes it. The runner refuses long-term access keys. The repository has no trust relationship with the account. |
| 3. Scope | About 30 types first. They include the types with hand-written corrections in `internal/provideraws/source.go` or recent bug reports, plus common types that are free or nearly free to keep for an hour. NAT gateways, RDS, EKS, OpenSearch, MSK and Redshift form an `expensive` tier that a maintainer runs by hand, one type at a time. |
| 4. Comparison | The harness reads the trail's log files from S3 and keeps the events whose `userIdentity.arn` matches a probe session. It maps each event to IAM actions through the AWS service reference, which `gen_iam_services.go` already reads. An access-denied message gives the action directly. For the resource types that a fixture declares, the trail also logs data events. |
| 5. Cadence | By hand only, when a maintainer judges a row worth checking, such as after a move to a new provider ref or a bug report about a row. Each finding opens an issue and doesn't block anything. |
| 6. Cost | Under $0.20 for a full run of the first 30 types on both provider majors, at list prices, and under $5 for one pass of the `expensive` tier. The runner prints an estimate at the end of a run, and a `cost` command on the next day prints the billed amount from Cost Explorer. |
| Findings to fixes | One issue per finding, with redacted CloudTrail evidence. When the call pattern recurs across types, the fix is a parser change, and otherwise a row in `schemaCorrections` or `schemaGates`. Before the fix merges, a maintainer reruns the probe for that type. |
| Conditional calls | The plan decides attribute gates, so the policy leaves out a call whose gate doesn't hold. A granted action that the provider didn't call is a finding. A fixture variant that makes the call, a source-cited entry in `probe/conditional.json`, or a fix closes it. A best-effort call shows up as an expected denial. |
| Provider 5.x and 6.x | Each fixture runs under v5.100.0 and v6.72.0, the refs in the table, and `validate --aws-provider-version` picks the matching view of the table. A finding records the major, and a fix that applies to one major gets a `providers` mark. |
| Public output | Before the runner writes to an issue or to a file in the repository, a redaction step replaces account IDs, organization IDs, the maintainer's identity, bucket names and email addresses. If any of them remains, the scan that follows refuses the write. |

## Table contents and probe coverage

`internal/permdata/permissions.json` lists, for each resource type and
operation (`create`, `read`, `update`, `delete`, `import`, `list`), the actions
the provider calls. A requirement's gate can test a presence attribute
(`attribute`, optionally `value_guarded`) or a change attribute (`changed`). A
requirement is `best_effort` when the provider ignores the call's failure. `validate`
evaluates each gate against the plan and reports the actions whose gate holds.

A probe checks the actions first. Its policy grants each action on
`"Resource": "*"`, since the table lists actions and the ARN rules in
`internal/iam/resource_scope.go` are a separate layer. A later stage adds
probes with resource-scoped policies.

A probe also checks the table through `validate`, not the parser alone. A
finding can come from a parser gap, a hand-written correction, an implied
requirement in `internal/iam/implied.go`, or a gate. Triage tells them apart.

## Terms

- **Fixture**: the terraform configuration for one resource type, in
  `probe/fixtures/<type>/`. It has a `support` root and a `probe` root.
- **Support root**: the resources the type depends on, such as a VPC for a
  security group. The harness role applies it.
- **Probe root**: the resources of the type under test, without their
  dependencies. A probe role applies it.
- **Phase**: one terraform operation on the probe root: create, read, update,
  import or delete.
- **Probe session**: the STS session of one phase, with a session name that
  encodes the run, type, major and phase.
- **Finding**: one action in one phase of one type and major, with a category
  and the events behind it.
- **Runner**: the `tools/probe` program that a maintainer starts on their
  machine.

## Question 1: account guardrails

### The account

The owner creates a member account in an AWS Organization for the harness.
The owner keeps other workloads out of it. The account gets an alias that starts with
`permcheck-probe`, because aws-nuke refuses to run against an account without
an alias.

The harness runs in `us-east-1` only. IAM, STS and Route 53 are global
services whose events CloudTrail records in `us-east-1`, so one region keeps
every event in one trail
([global service events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events)).

### Service control policy

SCPs set the maximum permissions for the IAM roles and users in a member
account, including its root user, and don't apply to service-linked roles
([SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)).
The owner attaches one SCP to the account, from the management account. The
repository keeps its text in `probe/org/scp.json` so that a pull request can
review a change to it. The text uses placeholders for the role ARNs, and the
owner fills them in when attaching it. It has five statements:

1. **Region.** Deny every action outside `us-east-1`, with `NotAction` listing
   the global services, as in the AWS example
   ([deny access based on the requested Region](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html)).
2. **Purchases.** Deny actions that commit money beyond the run, for every
   principal: reserved instances and Savings Plans, Marketplace
   subscriptions, domain registration, Shield Advanced subscriptions, and
   support plan changes.
3. **Expensive tier.** Deny the create actions of the `expensive` services
   (`ec2:CreateNatGateway`, `rds:CreateDBInstance`, `rds:CreateDBCluster`,
   `eks:CreateCluster`, `es:CreateDomain`, `kafka:CreateCluster`,
   `kafka:CreateClusterV2`, `redshift:CreateCluster`, and the Redshift
   Serverless workgroup) unless `aws:PrincipalTag/permcheck-tier` equals
   `expensive`. A second statement limits who can set that tag. It denies
   `iam:CreateRole` and `iam:TagRole` with `aws:RequestTag/permcheck-tier` to
   principals other than the expensive harness role.
4. **Sizes.** Deny `ec2:RunInstances` unless `ec2:InstanceType` is one of
   `t3.micro` and `t4g.nano`, and deny `rds:CreateDBInstance` unless
   `rds:DatabaseClass` is `db.t4g.micro`. A fixture that needs an instance
   uses those sizes.
5. **Harness protection.** Deny changes to the harness's own resources (the
   harness and nuke roles, the trail, its bucket, the state bucket, and the
   budget role) unless `aws:PrincipalArn` is one of the two harness roles. Deny
   `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` and
   `cloudtrail:PutEventSelectors` on the trail to everyone else, and deny
   `organizations:LeaveOrganization` to all.

An SCP document has a size limit of 5,120 characters
([Organizations quotas](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html)).
If the five statements exceed it, statements 2 and 3 move to a second SCP.

An SCP denial is not a table finding. AWS writes the policy type into an
access-denied message, such as `with an explicit deny in a service control
policy` ([access denied error message examples](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html#access-denied-error-examples)).
The comparison reports such a denial as a `guardrail` error for the type, and
someone fixes the fixture or the SCP.

### Budget actions

AWS Budgets can run an action when a budget crosses a threshold, either
automatically or after approval. The action can apply an IAM policy or an SCP,
or target EC2 and RDS instances. Only the management account can apply an SCP
to another account
([budget actions](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-controls.html)).

The account has a monthly cost budget of $30. It sends an alert at 50
percent. At 100 percent two actions run automatically:

- In the member account, a budget action attaches a deny-all IAM policy to the
  harness, nuke and probe roles.
- From the management account, a budget action attaches a deny-all SCP to the
  probe account. It also covers a role that exists outside the first action's
  list, such as a probe role created after the threshold.

A budget reacts late. "AWS billing data, which Budgets uses to monitor
resources, is updated at least once per day"
([Budgets update frequency](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-best-practices.html#budgets-best-practices-updates)).
A leaked EKS cluster runs for up to a day before the actions apply. The SCP
and aws-nuke limit spending as it happens, and the budget actions are the
last line.

### aws-nuke

The harness uses the maintained fork of aws-nuke
([ekristen/aws-nuke](https://github.com/ekristen/aws-nuke),
[documentation](https://aws-nuke.ekristen.dev/)), downloaded at a pinned
release and checked against its published checksum. The committed config in
`probe/nuke.yaml` lists `us-east-1` and the global region, and filters out the
harness resources by name and by the tag `permcheck-harness=true`. It uses
placeholders for the account IDs. The runner fills in the probe account and
the management account, which goes in the blocklist, from the maintainer's
local config at run time.

The runner runs aws-nuke at two points:

- before a run, to remove what an earlier run left if it stopped early;
- at the end of a run, after `terraform destroy`, including when a phase
  fails or the maintainer interrupts the run.

The runner traps an interrupt, destroys what the run created, and runs
aws-nuke before it exits. Leaving a run without cleanup takes a second
interrupt, and the runner then prints a warning to run `tools/probe nuke`.
If the maintainer's machine stops mid-run, the next run's first nuke removes
the leftovers, and the budget actions limit the cost until then.

The nuke role is separate from the harness role. It can delete resources but
can't create any, and the probe roles can't assume it.

## Question 2: credentials

### A maintainer's machine, not CI

The probe never runs in CI, as the owner decided. The issue asked about
GitHub Actions with OIDC, and the design keeps the probe on a maintainer's
machine, without a `workflow_dispatch` path, for these reasons:

- **Public output.** The repository is public, and so are its Actions logs and
  job summaries. Terraform, the AWS SDK and CloudTrail print ARNs that contain
  the account ID, and error messages quote the caller's identity. On a
  maintainer's machine, raw output remains on that machine, and only redacted
  findings leave it.
- **Account access.** An OIDC trust lets a workflow in a public repository
  assume a role in the account. The trust conditions can limit it to one
  environment, but local runs avoid the trust relationship entirely.
- **What CI adds.** A `workflow_dispatch` run is still a run that a person
  starts by hand. CI would add a clean runner and a log, and the redaction
  step covers the log's purpose for findings.

### Short-lived credentials

The maintainer signs in through IAM Identity Center or another federated
sign-in, and gets temporary credentials
([temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)).
The runner checks the access key ID before it makes any call. A key that
starts with `ASIA` is temporary, and one that starts with `AKIA` is a
long-term key
([unique ID prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes)).
The runner refuses a long-term key and stops.

From those credentials, the runner assumes one of these roles in the probe
account:

| Role | Who can assume it | Permissions |
|------|-------------------|-------------|
| `permcheck-harness` | The maintainers' sign-in roles | Apply support roots, create and delete probe roles, read the trail bucket, call Cost Explorer |
| `permcheck-harness-expensive` | The same, with `--tier expensive` | The same, plus tagging a probe role with `permcheck-tier=expensive` |
| `permcheck-nuke` | The same | Delete resources, as aws-nuke needs |

`probe/account/` declares the trust policies with a variable for the
maintainers' sign-in role ARNs. The owner sets it from a local file when
applying, so the repository never contains those ARNs.

### Probe roles

For each type and major, the harness creates `permcheck-probe-<hash>` with an
inline policy that lists the phase's actions, and a trust policy that allows
only the harness role. The provider assumes it through its `assume_role` block
with a session name such as `r1234.sqs-queue.v6.create`. STS records that name
in the session ARN, which CloudTrail writes as `userIdentity.arn`
([AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html),
[userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)).

AWS sets limits that matter here:

- Role chaining caps a session at one hour
  ([role chaining](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-role-chaining)).
  Each phase has its own session, so a phase must finish within the hour. The
  slowest planned type, an MSK cluster, takes about 30 minutes to create.
- IAM is eventually consistent, so a new role or policy may fail for a short
  time
  ([eventual consistency](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency)).
  The harness assumes the new role in a retry loop until a call with the new
  policy succeeds, before it starts terraform.
- A role's inline policies can total 10,240 characters at most
  ([IAM quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)).
  The largest create list in the table fits.

A session policy could narrow one role per phase, but its plain text can't
exceed 2,048 characters, and some types need more
([session policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session)).
A role per type and major has no such limit.

## Question 3: scope, and the expensive types

### Fixtures

The provider's acceptance tests build each configuration in Go: a function
such as `testAccQueueConfig_basic(rName)` returns HCL from `fmt.Sprintf` and
helpers like `acctest.ConfigCompose` and `acctest.ConfigVPCWithSubnets`
([running and writing acceptance tests](https://hashicorp.github.io/terraform-provider-aws/running-and-writing-acceptance-tests/)).
The harness doesn't run the acceptance tests, because their `CheckExists`
and `CheckDestroy` functions call AWS with the same credentials as the
provider, and their calls would mix with the provider's in CloudTrail.

Each fixture is HCL copied from the `_basic` configuration at the table's
ref, split into two roots:

- `support/` creates the dependencies and reads the data sources
  (`aws_partition`, `aws_availability_zones`, `aws_caller_identity`), and
  writes outputs.
- `probe/` declares only resources of the type under test, with the support
  outputs as variables. It sets no `default_tags`, which would add tag calls
  to each type.

The fixture's `fixture.json` records the source test function and ref, the
update variant (an attribute change from the test's `_update` step, or none),
whether the type supports import, the data-event resource types it needs, and
the tier. When `generate-permissions` moves to a new provider ref, a check
diffs each source test file between the two refs and lists the fixtures to
review.

A variant for a gated requirement is a second probe root, such as
`probe-kms/` that sets `kms_master_key_id` on `aws_sqs_queue`. The run report
gives, per type, how many gated requirements a fixture exercised.

Resource names in a fixture use the prefix `permcheck-` and the run ID, so a
name doesn't identify a person or an organization.

### First types

The first batch is about 30 types, picked for three reasons:

- **Hand-written rows.** `aws_iam_role` and `aws_acm_certificate` have entries
  in `schemaCorrections` and `schemaGates`. `aws_s3_bucket`,
  `aws_secretsmanager_secret_version` and `aws_lambda_function` got rows in
  [#200](https://github.com/elecnix/terraform-permcheck/pull/200). A probe is
  the first check of those rows against AWS.
- **Common types.** The IAM, S3, SQS, SNS, CloudWatch Logs, KMS, Secrets
  Manager, SSM, DynamoDB, ECR and EventBridge types that the README and the
  `testdata` fixtures use, plus `aws_vpc`, `aws_subnet` and
  `aws_security_group`.
- **Cost while they exist.** Each is free, or a fraction of a cent, for the
  minutes it exists. A KMS key costs $1 per month prorated hourly, and AWS
  doesn't charge for a key pending deletion
  ([KMS pricing](https://aws.amazon.com/kms/pricing/)). A Route 53 hosted zone
  deleted within 12 hours of creation isn't charged
  ([Route 53 pricing](https://aws.amazon.com/route53/pricing/)).

`aws_acm_certificate` imports a self-signed certificate that the support root
makes with the `tls` provider, since a requested certificate needs DNS
validation.

### Expensive types

One probe of a NAT gateway, RDS, EKS, OpenSearch, MSK or Redshift costs a
few cents. Their risks are a leak, since a cluster left running bills by the hour
until aws-nuke runs, and a create time of 10 to 30 minutes. They form the
`expensive` tier, which runs by hand only:

- The SCP denies their create actions to any role without the tier tag, and
  only `permcheck-harness-expensive` can set it.
- The runner assumes that role only when the maintainer passes
  `--tier expensive`, and it then runs one type per invocation.
- The runner destroys the resources and runs aws-nuke on exit, after an error
  or an interrupt too.
- A fixture uses the smallest size that the SCP allows.

The table has other types that cost money by the hour (SageMaker, Elastic
Beanstalk, Directory Service, FSx, and others). A type joins the first batch
only after its fixture's `fixture.json` gives a tier, and the default for an
unknown type is `expensive`.

## Question 4: from CloudTrail events to IAM actions

### The trail

The account has one trail for `us-east-1` that logs management events, read
and write, to an S3 bucket in the account. One copy of management events is
free, with only S3 storage charged
([Lambda and CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html),
[CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/)).
CloudTrail event history doesn't record data events, so the harness reads
the trail's log files and doesn't use `LookupEvents`.

CloudTrail doesn't log most data events by default. The trail logs them through advanced event
selectors on `eventCategory` and `resources.type`
([logging data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)).
A fixture lists the resource types whose data events it needs, such as
`AWS::S3::Object` for `aws_s3_object`, `AWS::Lambda::Function` for
`aws_lambda_invocation`, and `AWS::DynamoDB::Table` for
`aws_dynamodb_table_item`. The harness role sets the selectors before the run,
and only it can change them. S3 logs object-level calls, such as
`PutObject` and `GetObject`, as data events and bucket-level calls as
management events
([S3 CloudTrail events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)).

### Waiting for delivery

"Typically, CloudTrail delivers an event within 5 minutes of the API call"
([CloudTrail FAQ](https://aws.amazon.com/cloudtrail/faqs/)). Log files aren't
ordered, and events in a file don't appear in any specific order. The harness
reads events after all phases of all types finish. It waits until the bucket
has a log file whose newest event is at least 15 minutes past the end of the
last phase, then reads the files for the run's time window. A type with zero
events is a run error.

### Selecting events

An event belongs to a probe when its `userIdentity.arn` is the probe role's
assumed-role ARN with the run's session name. The session name encodes the
type, major and phase. The harness keeps:

- events the provider made directly;
- events a service made on the session's behalf with forward access sessions.
  These record the caller's identity and set `invokedBy` to the service, such as
  the `kms:GenerateDataKey` call that S3 makes when the provider writes an
  object to a bucket encrypted with a KMS key
  ([forward access sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_forward_access_sessions.html)).
  IAM authorizes a forward access session against the caller's policy, so the
  call counts as a need.

It drops the `AssumeRole` call itself, which the harness role makes, and
events of service-linked roles.

### Mapping an event to actions

Each event has an `eventSource`, such as `sqs.amazonaws.com`, and an
`eventName`, usually the API operation
([CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)).
The mapping goes in three steps:

1. **Access denied.** When `errorCode` is an access-denied code
   (`AccessDenied`, `AccessDeniedException`, `Client.UnauthorizedOperation`,
   `AuthorizationError` and the like), the action comes from the error
   message: `is not authorized to perform: <action>`. EC2 encodes the message,
   and the harness role decodes it with `sts:DecodeAuthorizationMessage`
   ([DecodeAuthorizationMessage](https://docs.aws.amazon.com/STS/latest/APIReference/API_DecodeAuthorizationMessage.html)).
   The `because no identity-based policy allows` phrase marks a table finding.
   An explicit deny or another policy type marks a `guardrail` error.
2. **Event source to IAM prefix.** The event source host is usually the
   service's endpoint prefix, which can differ from the IAM prefix. A small table in
   `internal/probe` maps the exceptions, such as `monitoring` to `cloudwatch`
   and `email` to `ses`. A test checks it against the AWS SDK endpoint
   metadata.
3. **Event name to action.** The harness strips a version suffix and looks up
   the operation in the service reference, the same data that
   `gen_iam_services.go` reads for `sdkOperationActions`
   ([service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)).
   The service reference lists, per operation, each IAM action the call
   needs. A successful event confirms each of them.

Examples of event names that differ from their actions:

| Event source | Event name | IAM action | Rule |
|--------------|------------|------------|------|
| `sqs.amazonaws.com` | `CreateQueue` | `sqs:CreateQueue` | same name |
| `lambda.amazonaws.com` | `CreateFunction20150331` | `lambda:CreateFunction` | Lambda appends a date and version to the operation ([Lambda CloudTrail events](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)) |
| `s3.amazonaws.com` | `PutBucketLifecycleConfiguration` | `s3:PutLifecycleConfiguration` | rename in the service reference |
| `s3.amazonaws.com` | `HeadBucket` | `s3:ListBucket` | rename in the service reference |
| `monitoring.amazonaws.com` | `PutMetricAlarm` | `cloudwatch:PutMetricAlarm` | event source differs from the IAM prefix |
| `apigateway.amazonaws.com` | `CreateRestApi` | `apigateway:POST` | API Gateway authorizes HTTP verbs on resource paths |
| `s3.amazonaws.com` (data event) | `PutObject` | `s3:PutObject` | logged only with a data event selector |

An event that none of the steps maps is `unmapped`, a run error for the type
until a mapping row exists. The harness doesn't derive an action from a name
by pattern.

### Actions with no event

Some actions authorize a call without being one. `iam:PassRole` is a
permission that IAM checks when a service receives a role, and it has no API
of its own
([passing a role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)).
Dependent actions such as the Backup pair in #179 work the same way. Some
services don't log some calls in CloudTrail at all
([unsupported services](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-unsupported-aws-services.html)).

The harness checks such an action by ablation. It reruns the phase with the
action removed and expects the apply to fail with that action in an
access-denied message. Ablation costs one more apply per action, so it runs
for permission-only actions, for dependent actions, and for `unseen` actions
that a maintainer marks for it. The harness caches a result per type, major,
action and table hash.

### Comparison

For each type, major and phase, the harness compares the set of actions it
granted with the events it kept, and puts each action in one category:

| Category | Meaning | Effect |
|----------|---------|--------|
| `confirmed` | Granted, and an event used it | none |
| `missing` | Denied because the probe policy lacks it, and the apply failed | finding, labelled `probe-missing` |
| `missing_tolerated` | Denied, the apply succeeded, and the table doesn't list it as best-effort | finding |
| `expected_denial` | Denied, and the table lists it as best-effort, which `validate` doesn't report | none |
| `unseen` | Granted, and no event or explanation accounts for it | finding |
| `unseen_explained` | Granted, with no event, and an entry in `probe/conditional.json`, a CloudTrail gap, or an ablation that proves it | none |
| `guardrail` | Denied by an SCP, a boundary or an explicit deny | run error |
| `unmapped` | An event that maps to no action | run error |

A `missing` denial stops terraform in most cases, and the calls after it never
happen. The harness then adds the denied action to the phase's policy, destroys
what exists, and repeats the phase, up to five rounds. The findings of each
round add up, and the last round's events decide `confirmed` and `unseen`. One
run then reports each missing action of a phase, not only the first. A phase
that still fails after five rounds is a run error.

## Question 5: cadence and blocking

The probe runs by hand only. A maintainer starts it with
`go run ./tools/probe run`, naming the types and majors, or `--all` for the
types outside the `expensive` tier. It isn't a pull request check or a
required check, and its results don't block a pull request or a release tag.

A maintainer runs it when a row's evidence matters:

- after `generate-permissions` moves the table to a new provider ref, for the
  types whose rows changed;
- before a release, for the rows that changed since the last probe of them;
- when a bug report questions a row;
- to confirm a fix before its pull request merges.

A `missing` finding means a user who grants what PermCheck reports gets an
access-denied error in their apply. Its issue has the `probe-missing`
label, and triage treats it like a bug report from a user. A run error
(`guardrail`, `unmapped`, a type with zero events, a failed destroy) says
nothing about the table, so the runner prints it and doesn't open an issue.

Only one run uses the account at a time. The runner takes a lock before its
first nuke: it writes `lock.json` to the harness's state bucket with the
`If-None-Match: *` header, which S3 rejects with `412 Precondition Failed`
when the object exists
([conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)).
The lock records the run ID and start time, and the runner deletes it at the
end. `tools/probe unlock` removes a lock that a stopped run left. Within a run,
up to eight types run in parallel, each with its own probe roles and state.

## Question 6: cost per run, and cost reports

### Estimate

The AWS cost of a run of the first 30 types on both majors, at list prices:

| Item | Estimate |
|------|----------|
| Resources of the first batch, up to an hour each | under $0.10 (KMS keys, Secrets Manager secrets at $0.40 per month prorated, S3 requests) |
| CloudTrail management events | $0, first copy |
| CloudTrail data events | under $0.01 at $0.10 per 100,000 events |
| S3 storage for the trail and state | under $0.01 |
| Cost Explorer API, a few calls a day after the run | $0.01 per request ([Cost Explorer pricing](https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/)) |
| **Run total** | **under $0.20** |

An `expensive` pass assumes each resource exists for one hour, since some of
these services bill by the hour. An EKS cluster is $0.10 per hour
([EKS pricing](https://aws.amazon.com/eks/pricing/)) and a NAT gateway $0.045
per hour in `us-east-1` ([VPC pricing](https://aws.amazon.com/vpc/pricing/)).
The smallest RDS, OpenSearch, MSK and Redshift configurations add a few
dollars together. A pass on both majors comes to under $5. The expensive
stage confirms these figures against each pricing page before the tier runs.

The $30 budget leaves room for one leaked expensive resource for most of a
day, until the next run's first nuke or the budget actions stop it.

### Reporting

The runner writes its report locally, in `.probe/runs/<run-id>/` under the
repository, which `.gitignore` excludes:

- **Terminal summary.** A table per type and major with the phase durations,
  the categories, and an estimate: the hours each resource existed times its
  price in `probe/prices.json`, which lists the hourly price of each priced
  type and zero for the rest.
- **`report.json`.** Each finding, its events, and the estimate. The raw
  version remains on the machine. A redacted copy, `report.public.json`, is what a
  maintainer may attach to an issue or a pull request.
- **Billed cost.** Cost Explorer data refreshes at least once every 24 hours
  ([Cost Explorer](https://docs.aws.amazon.com/cost-management/latest/userguide/ce-what-is.html)).
  On the next day, `tools/probe cost <run-id>` calls `GetCostAndUsage` for the
  account by service for the run's day and prints it. The owner keeps other
  workloads out of the account, so its cost for the day is the harness's cost.
  The amount is a dollar figure, which redaction leaves as it is.

## Public output and redaction

The project is public. Findings, issues, terminal summaries that a maintainer
pastes, committed files, and this document must never show any of these:

- an AWS account ID, alone or inside an ARN;
- an organization ID (`o-` followed by 10 to 32 characters) or an
  organizational unit ID (`ou-`);
- a role name or session name that identifies the owner or a maintainer, such
  as an IAM Identity Center role or a session named after a person;
- a bucket name, including the trail and state buckets;
- an email address;
- an access key ID.

### Where data goes

Raw data remains on the maintainer's machine: terraform output and state,
CloudTrail log files, `report.json`, and the local config. These outputs leave
the machine: what the runner writes to GitHub (issue bodies and comments),
and the files that someone commits, such as fixtures and
`probe/conditional.json`. The runner writes to GitHub with the maintainer's
own `gh` session, and each of those writes goes through redaction first. A
test scans the committed files.

### The redaction step

`internal/probe/redact` replaces sensitive values in a string before the runner
writes it to GitHub or to `report.public.json`. It works in two passes.

The first pass replaces known values, read from the local config at run time:
the probe account ID, the management account ID, the organization ID, the
bucket names, and the maintainer's sign-in role and session names. Each value
gets a fixed placeholder:

| Value | Placeholder |
|-------|-------------|
| Probe account ID | `111122223333` |
| Management account ID | `444455556666` |
| Organization ID | `o-exampleorgid` |
| Trail bucket, state bucket | `<trail-bucket>`, `<state-bucket>` |
| Maintainer's role and session | `<maintainer-role>`, `<maintainer-session>` |

The account placeholders are the ones the AWS documentation uses in its
examples, so a redacted ARN still has the ARN format and reads like the
documentation's examples.

The second pass replaces patterns, wherever they appear in the text, so it
also covers an ID in free text such as an error message:

| Pattern | Placeholder |
|---------|-------------|
| Any other run of exactly 12 digits | `999988887777` |
| An `o-` or `ou-` ID | `o-exampleorgid`, `ou-exampleouid` |
| An email address | `<email>` |
| An access key ID (`AKIA` or `ASIA` and 16 more characters) | `<access-key-id>` |
| A bucket name with the harness prefix (`permcheck-trail-` or `permcheck-state-`) | `<trail-bucket>`, `<state-bucket>` |
| An IAM Identity Center role name (`AWSReservedSSO_` and the rest of the name) | `<maintainer-role>` |

The 12-digit rule also replaces a number that only looks like an account ID,
such as a 12-digit request field. Over-redaction loses little, since the
event ID and event name still identify the call.

After both passes, a scan checks the output for each known value and each
pattern again. The scan allows the placeholders that the passes insert,
`111122223333`, `444455556666` and `999988887777`, and the bracketed
placeholders. If it finds anything else, the runner doesn't write, and prints
the location of the match in the local raw file so the maintainer can extend
the rules. The step is fail-closed, so the runner drops a write that it can't
redact.

### Checks on committed files

A test in the repository scans `probe/`, `docs/design/probe-harness.md` and
`testdata` files under `internal/probe` with the patterns of the second pass:
12-digit numbers, `o-` and `ou-` IDs, email addresses, access key IDs, bucket
names with the harness prefix, and Identity Center role names. It allows the
AWS documentation placeholders (`111122223333`, `123456789012`,
`444455556666`, `999988887777`) and the bracketed placeholders, and fails on
any other match. When `probe/local.json` exists, as on a maintainer's
machine, the test also fails on each known value it lists. It runs in the
normal `go test` job, since it reads files and doesn't call AWS.

The harness prefixes are part of the design so that the scan can find a
bucket name without knowing it: `probe/account/` names the trail and state
buckets `permcheck-trail-` and `permcheck-state-` followed by a random suffix.

`probe/account/`, `probe/org/scp.json` and `probe/nuke.yaml` take account IDs,
role ARNs and bucket names as variables or placeholders. The values are in
`probe/local.json`, which `.gitignore` excludes, and
`probe/local.example.json` shows its format with placeholders.

## From a finding to a fix

The runner opens one issue per finding, keyed by type, major, operation,
action and category. A later run that reports the same finding comments on the
issue, and a run that no longer reports it closes the issue. The redacted
issue body gives the event ID, event name, error code and message, the session
name, the table's requirement and gate for the action, and the run ID.

Triage follows the category.

**`missing` and `missing_tolerated`.** Run `generate-permissions` with
`--provider-source live` at the table's ref and find where the provider makes
the call.

- If the parser misses a call pattern, such as a handler-struct binding
  ([#183](https://github.com/elecnix/terraform-permcheck/issues/183)), fix the
  parser with a regression test in `internal/provideraws` on a minimal Go
  fixture, then regenerate the table. A pattern that the harness finds in two
  or more types is always a parser fix.
- If the call depends on a runtime value that no parser can follow, add the
  requirement through a correction with a comment that cites the provider
  function and the issue.
- If the action is a dependent action, it goes into the dependent-action table
  from [#180](https://github.com/elecnix/terraform-permcheck/pull/180).
- If the apply succeeded despite the denial, the requirement goes in with
  `best_effort`.

**`unseen`.** Check the gate first.

- If the gate held in the plan but the call depends on something else in the
  configuration, fix the gate in the parser or in `schemaGates`.
- If the call depends on runtime state, such as a non-empty list from AWS,
  add an entry to `probe/conditional.json` with the provider function and line
  at the table's ref. If the plan can never show the condition, the action
  also leaves the table through `schemaCorrections`, and an implied rule in
  `internal/iam/implied.go` can add it back from a plan signal, as for
  `iam:RemoveRoleFromInstanceProfile`.
- If the provider never calls it, remove it with a parser fix or a
  `schemaCorrections` row.

Before the fix merges, a maintainer reruns the probe for that type on the
fix's branch. The runner closes the issue when the finding is gone and
comments on the pull request with the redacted result.

## Calls the provider makes only under a condition

The table records three kinds of condition, and AWS state adds a fourth:

1. **Attribute gates** (`attribute`, `changed`). `validate` evaluates them
   against the plan, so the probe policy has a gated action only when its gate
   holds. A fixture variant that sets the attribute exercises the gate. The
   run report lists the gated requirements that the variants left untested.
2. **Value guards** (`value_guarded`). The same, with the configured value.
3. **Best-effort calls** (`best_effort`). `validate` classes them optional and
   the default filter leaves them out, so the probe policy omits them. The
   provider makes the call and continues after the denial. The event shows
   as `expected_denial`. It proves that the call happens and that the
   provider ignores its failure. The `s3:TagResource` fallback on `aws_s3_bucket`
   create in 6.x, from
   [#195](https://github.com/elecnix/terraform-permcheck/issues/195), is such a
   case.
4. **Runtime conditions**. A call can depend on what AWS returns: a list that
   is empty or not, a waiter that polls a varying number of times, a retry
   after an eventual-consistency error, a fallback after a failure. The plan
   can't show these. An action granted for such a call and never used is
   `unseen`. It becomes `unseen_explained` through an entry in
   `probe/conditional.json` that cites the provider source. A run never
   removes an action from the table on its own. A removal needs a source
   reading in a pull request, since a false negative breaks a user's apply.

A call that happens more than once, such as a waiter's `Describe` call, maps
to one action, and the comparison counts actions, not calls.

## Provider 5.x and 6.x

After [#200](https://github.com/elecnix/terraform-permcheck/pull/200), the
table records the refs `{"5": "v5.100.0", "6": "v6.72.0"}` and marks each
type, operation and requirement that only one major has. `validate` picks the
major from `--aws-provider-version`, the lock file, or the plan's version
constraints.

The harness runs each fixture under both refs:

- It generates `versions.tf` with `version = "5.100.0"` or `"6.72.0"`, runs
  `terraform init`, and passes the same version to `validate
  --aws-provider-version`, so the policy and the provider agree.
- A type that the table marks `"providers": ["6"]` runs under 6 only.
- A fixture whose HCL differs between majors has a `probe.v5/` root that
  overrides `probe/`. 6.x added a `region` argument to most resources, and a
  fixture doesn't use it, so most fixtures don't need an override.
- A finding records its major. A finding under one major leads to a fix with a
  `providers` mark. A finding under both is a plain row.

Running both majors doubles the run, which still costs under $0.20. A finding that
shows up under one major only also tests the `providers` marks of #200.

## Worked example: `aws_sqs_queue` under 6.x

This example shows the steps. No run has happened, and the events below are
illustrative.

The fixture's probe root, copied from `testAccQueueConfig_basic` at v6.72.0:

```hcl
variable "name" { type = string }

resource "aws_sqs_queue" "test" {
  name = var.name
}
```

The update variant sets `visibility_timeout_seconds = 60`. The type supports
import and doesn't need data events.

Phase create: the harness runs `terraform plan`, then `validate
--plan-file plan.json --policy-file empty.json --format json --exit-zero
--aws-provider-version 6`. The `missing_action` values of its report become the
probe policy, one Allow statement on `"Resource": "*"`. The provider applies
the plan with the session `r1234.sqs-queue.v6.create`.

The comparison for that phase could look like this:

| Action | Events | Category |
|--------|--------|----------|
| `sqs:CreateQueue` | `CreateQueue` | `confirmed` |
| `sqs:GetQueueAttributes` | `GetQueueAttributes` (3) | `confirmed` |
| `sqs:ListQueueTags` | `ListQueueTags` | `confirmed` |
| `sqs:TagQueue` | none | `unseen` |

An `unseen` row like the last one opens an issue. Triage reads the create
function at v6.72.0 to decide whether the provider sends tags only when the
configuration sets them, which makes the fix a gate on `tags`.

The read, update, import and delete phases repeat the steps with their own
session names. Delete uses `terraform destroy -refresh=false`, and the update
plan uses `-refresh=false`, so that each session makes only the calls of its
own operation. The read phase runs `terraform plan -refresh-only`. A
refresh-only plan has no change for `validate` to check, so its policy comes
from the type's `read` requirements, with gates evaluated against the state
that create left.

## Layout in the repository

| Path | Contents |
|------|----------|
| `internal/probe` | Event selection, the event-to-action mapping, the comparison and the report, in Go whose unit tests don't call AWS. |
| `internal/probe/redact` | The redaction passes and the scan after them. |
| `tools/probe` | The runner. It checks credentials and takes the lock, then creates probe roles, runs the phases, retry rounds and ablations, and updates issues. |
| `probe/fixtures/<type>/` | `fixture.json`, `support/`, `probe/`, variants. |
| `probe/conditional.json` | Runtime-conditional actions, each with a provider source citation. |
| `probe/prices.json` | Hourly prices for the estimate. |
| `probe/nuke.yaml` | aws-nuke config, with placeholders for the account IDs. |
| `probe/account/` | Terraform for the harness and nuke roles, the trail with its bucket, the state bucket, and the budget with its in-account action. The owner applies it with their own credentials. |
| `probe/org/` | The SCP text and the management-account budget action, with placeholders, which the owner applies from the management account. |
| `probe/local.example.json` | The format of the local config, with placeholders. |
| `.probe/` | Local run output, excluded by `.gitignore`. |

`tools/probe` is a separate main package in the same module. The released
binary doesn't include it, and no workflow runs it.

## Test plan

Each code stage starts with a failing test.

- **Event selection** (`internal/probe`): CloudTrail records from the AWS
  documentation examples, adapted to probe session ARNs. Cases: a direct call,
  a forward-access-session call with `invokedBy`, the harness role's
  `AssumeRole`, another session in the same run, a service-linked role.
- **Mapping**: one case per row of the event-name table, an access-denied
  event of each error code, an encoded EC2 message, an event that maps to
  nothing, and an operation that the service reference maps to two actions.
- **Comparison**: one case per category, the union of retry rounds, and an
  entry in `conditional.json` that turns `unseen` into `unseen_explained`.
- **Redaction**: an event with each kind of sensitive value from the list
  above, in an ARN, in a JSON field and in the free text of an error message.
  A redacted ARN passes the scan. The output has
  each one replaced. A value that the passes miss on purpose makes the scan
  refuse the write. The committed-files scan fails on a planted account ID and
  passes on the documentation placeholders.
- **Policy building**: a `validate` JSON report becomes the expected policy
  document, and a best-effort action stays out.
- **Credentials**: an `AKIA` key stops the runner before its first call, and
  an `ASIA` key passes.
- **Runner**: the phase order and session names, plus the lock and cleanup on
  an interrupt, against a fake that records terraform and AWS calls.
- **Infrastructure**: the canary in stage 3, run first on each pass, with a
  known expected report. If it fails, the run stops and reports nothing about
  the table.

## Stages

1. **Account and guardrails (owner).** Create the member account and its
   alias, attach the SCP, set up both budget actions, and apply
   `probe/account/`. The later stages need this account to run against AWS.
2. **Mapping, comparison and redaction.** `internal/probe` and
   `internal/probe/redact` with the tests above, and the committed-files scan.
   No AWS calls. Redaction comes before any stage that writes to GitHub.
3. **The first probe.** `tools/probe` with the credential check, the lock,
   `aws_sqs_queue` under 6.x, create and delete only, and aws-nuke before and
   after. This type becomes the canary. Red: the comparison test for its
   recorded events.
4. **Read, update, import, and retry rounds.** Red: a fake terraform that
   fails with an access-denied error on round one and passes on round two.
5. **Provider 5.x.** `versions.tf` generation and `--aws-provider-version`.
   Red: the runner skips a type with a `providers` mark under the other major.
6. **The first batch and findings as issues.** About 30 fixtures, one issue per
   finding through redaction, the terminal summary, and the cost estimate and
   `cost` command.
7. **Ablation.** For permission-only and dependent actions, starting with
   `iam:PassRole` on `aws_lambda_function`.
8. **Data events.** `aws_s3_object`, `aws_lambda_invocation`,
   `aws_dynamodb_table_item`, with selectors set per run.
9. **The expensive tier.** One type per pull request, each with its prices
   confirmed.
10. **Resource-scoped policies.** A second probe policy per phase that grants
    each action only on the ARNs that `--strict-resources` derives for the
    plan, so that a probe tests `internal/iam/resource_scope.go`. A denial
    that the `"Resource": "*"` run doesn't show is a finding about an ARN rule.

## The owner's decisions

1. **Region.** `us-east-1` only.
2. **Budget.** Both actions, the deny policy in the member account and the
   deny-all SCP from the management account, at $30 a month.
3. **Cadence.** The probe runs by hand, never in CI. It isn't a pull request
   check or a required check, and it doesn't block a pull request or a release
   tag. It runs from a maintainer's machine with their own short-lived
   credentials, as question 2 explains.
4. **Resource-scoped policies.** Yes, as a later stage (stage 10).
5. **Expensive types.** By hand only.
6. **Issues.** One issue per finding.
7. **Public output.** Public output never shows an account ID, an ARN with an
   account ID, an organization ID, a role name that identifies the owner, a
   bucket name or an email address. The redaction step enforces it.

## The question still open

Should the harness cover the `list` operation, for `terraform query`?

`terraform query` reads `list` blocks from `.tfquery.hcl` files. A `list` block
asks a provider to find existing resources of one type, so that a user can
import them ([`list` block](https://developer.hashicorp.com/terraform/language/block/tfquery/list)).
The AWS provider's list resource for a type calls the service's paginated
`List` or `Describe` API. With `include_resource = true`, the result contains
the full resource, so the provider also makes the type's read calls for each
result.

The table already records a `list` operation for some types. To cover it,
PermCheck needs an input that reads `list` blocks from the query files, as
static mode reads HCL, because `terraform query` doesn't write a plan. Each block's
type then requires the table's `list` actions, plus its `read` actions when
`include_resource` is set. The probe would add a `list` phase that runs
`terraform query` under a policy built the same way.

## References

- AWS, [Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- AWS, [General SCP examples](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html)
- AWS, [Organizations quotas](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html)
- AWS, [Configuring budget actions](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-controls.html)
- AWS, [Best practices for AWS Budgets](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-best-practices.html)
- AWS, [Temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
- AWS, [IAM identifiers: unique ID prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes)
- AWS, [Roles terms and concepts: role chaining](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-role-chaining)
- AWS, [Troubleshoot IAM: eventual consistency](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency)
- AWS, [IAM quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)
- AWS, [Session policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session)
- AWS, [Troubleshoot access denied error messages](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)
- AWS, [Forward access sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_forward_access_sessions.html)
- AWS, [Grant a user permissions to pass a role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)
- AWS, [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- AWS, [DecodeAuthorizationMessage](https://docs.aws.amazon.com/STS/latest/APIReference/API_DecodeAuthorizationMessage.html)
- AWS, [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- AWS, [CloudTrail userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- AWS, [Logging data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- AWS, [CloudTrail concepts: global service events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events)
- AWS, [CloudTrail unsupported services](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-unsupported-aws-services.html)
- AWS, [CloudTrail FAQ](https://aws.amazon.com/cloudtrail/faqs/)
- AWS, [CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/)
- AWS, [Logging Lambda API calls with CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)
- AWS, [Logging S3 API calls with CloudTrail](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)
- AWS, [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- AWS, [Service Authorization Reference: service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)
- AWS, [Cost Explorer](https://docs.aws.amazon.com/cost-management/latest/userguide/ce-what-is.html)
- AWS pricing: [KMS](https://aws.amazon.com/kms/pricing/), [Route 53](https://aws.amazon.com/route53/pricing/), [EKS](https://aws.amazon.com/eks/pricing/), [VPC](https://aws.amazon.com/vpc/pricing/), [Cost Explorer](https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/)
- HashiCorp, [Running and writing acceptance tests](https://hashicorp.github.io/terraform-provider-aws/running-and-writing-acceptance-tests/)
- HashiCorp, [`list` block reference](https://developer.hashicorp.com/terraform/language/block/tfquery/list)
- aws-nuke, [ekristen/aws-nuke](https://github.com/ekristen/aws-nuke)
