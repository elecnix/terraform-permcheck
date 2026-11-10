# Checking needs against every IAM policy in the plan

Status: proposal for [#175](https://github.com/elecnix/terraform-permcheck/issues/175).
Nobody writes code for it until the owner approves this document.

PermCheck checks a principal's declared needs against one policy document per
run, which the user passes in. This document proposes how PermCheck can check
each need against the policies the plan attaches to that principal, and against
the resource policies on the resources the need acts on. It answers the five
questions in the issue and states the evaluation rule with links to the AWS
documentation. The last sections split the work into pull requests.

## Decisions at a glance

| Question | Decision |
|----------|----------|
| 1. Policy sources | Inline and attached policies of an IAM role or user, the policies of its groups, its permissions boundary, and the resource policies of Secrets Manager first, then one service per pull request. Each source has a terraform address. A source whose text the plan lacks is an *unknown source*. |
| 2. Principal key | A new `principals` map in the config file. It maps the `principal` label a need already uses to the terraform address of an `aws_iam_role` or `aws_iam_user`. |
| 3. Evaluation rule | In one account, a need is covered when an identity policy or a resource policy allows it and no policy has a definite Deny. A permissions boundary in the plan must also allow it. The plan doesn't show SCPs, RCPs or session policies, so they count as allowing. A cross-account need needs an identity Allow and a resource-policy Allow, and a resource policy outside the plan is an unknown source. |
| 4. Unknown policy text | An unknown source may grant anything and never denies. The need is covered by default and unverified under `--strict-resources` with the reason `policy_unknown`. The run prints one notice per unknown source. |
| 5. Compatibility | A config without `principals` gives the same output as today, byte for byte. Mapped principals are opt-in, and the CLI flags keep their meaning. |

## The one-policy run today

`iam.CheckNeeds` in `internal/iam/needs.go` sends each need through
`policy.Document.Coverage`, the same path a plan resource takes. The document
comes from `check.PolicySource` in `internal/check/policysource.go`, which
accepts exactly one of `--policy-file`, `--policy-from-plan-output` and
`--policy-from-state-output`, and rejects a second one. `--principal` selects
which needs run, and the `principal` field of a need is a free-form label.

The code limits what a run can see:

- `policy.Document` keeps `Version` and `Statement` only. It drops a
  statement's `Principal` element, so it can't tell which principal a resource
  policy grants.
- `plan.Parse` keeps managed resource changes and drops data sources. It
  records known string attributes in `AttributeValues` and the references of
  each attribute in `References`, but it extracts no policy documents.
- `Coverage` counts an undecidable overlap as coverage, as `arnIntersect` in
  `internal/policy/arn.go` states: "the caller only reports a gap when
  non-coverage is provable".

The README already says that permission boundaries, SCPs, session policies and
resource policies are out of scope. This design changes that sentence for
boundaries and resource policies only.

## Terms

- **Principal**: an `aws_iam_role` or `aws_iam_user` in the plan that a need
  belongs to.
- **Policy source**: one policy document the plan attaches to a principal or
  to a resource, with the terraform address that sets it, such as
  `aws_iam_role_policy.task_secrets`.
- **Identity policy**: an inline or managed policy attached to the principal,
  or to a group the user belongs to.
- **Resource policy**: a policy attached to a resource, such as a secret's
  policy. Its statements have a `Principal` element.
- **Unknown source**: a policy source whose JSON the plan doesn't contain. It
  includes a value computed at apply time, an AWS managed policy, and a
  customer managed policy created outside this plan.

## Question 1: which resource types become policy sources

### Decision

PermCheck reads the policy sources in the tables below from
`resource_changes`. For a create or update it reads the planned `after` value,
since that's the policy AWS will evaluate once the apply finishes. A
delete doesn't add a source, since the policy goes away. A no-op adds its
current value, which `plan.Parse` already retains so that references can find
it.

Identity policies of a role:

| Resource type | Policy text | Principal link |
|---------------|-------------|----------------|
| `aws_iam_role_policy` | `policy` | `role` |
| `aws_iam_role` | `inline_policy[*].policy` | the role itself |
| `aws_iam_role_policy_attachment` | the policy at `policy_arn` | `role` |
| `aws_iam_role` | the policies at `managed_policy_arns` | the role itself |
| `aws_iam_policy_attachment` | the policy at `policy_arn` | each of `roles`, `users`, `groups` |
| `aws_iam_role_policy_attachments_exclusive` | the policies at `policy_arns` | `role_name` |

Identity policies of a user add `aws_iam_user_policy`,
`aws_iam_user_policy_attachment`, and the group policies
(`aws_iam_group_policy`, `aws_iam_group_policy_attachment`) of each group that
`aws_iam_user_group_membership` or `aws_iam_group_membership` puts the user in.

A permissions boundary comes from the `permissions_boundary` attribute of
`aws_iam_role` or `aws_iam_user`, which is a policy ARN.

Resource policies, in the order the stages add them:

| Resource type | Policy text | Resource link |
|---------------|-------------|---------------|
| `aws_secretsmanager_secret_policy` | `policy` | `secret_arn` |
| `aws_secretsmanager_secret` | `policy` | the secret itself |
| `aws_s3_bucket_policy` | `policy` | `bucket` |
| `aws_sqs_queue_policy`, `aws_sqs_queue` | `policy` | `queue_url`, or the queue |
| `aws_sns_topic_policy`, `aws_sns_topic` | `policy` | `arn`, or the topic |
| `aws_ecr_repository_policy` | `policy` | `repository` |

Each resource-policy service joins in its own pull request, and that pull
request links the service's documentation for how its resource policy combines
with identity policies in one account. The IAM evaluation page says that
services other than IAM and KMS "may also require an explicit `Allow`
statement within the same account", so PermCheck can't assume the general
rule for a service until its documentation confirms it
([policy evaluation logic, resource-based policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)).

### Mapping a source to its principal

A link such as `role` is matched in this order:

1. The `References` of the link attribute, from the plan's configuration
   section. `role = aws_iam_role.task.id` references `aws_iam_role.task`,
   whether or not the role's name is known at plan time.
2. The known value of the link attribute, compared with the principal's
   known `name` (for a role or user) or `arn`.
3. Otherwise the link is undecidable, and the source *may* attach to the
   principal.

A reference to a resource with `count` or `for_each` omits the instance key.
It matches each instance unless the known names differ, and that case is
undecidable too.

A policy ARN, from `policy_arn`, `managed_policy_arns` or
`permissions_boundary`, resolves the same way to an `aws_iam_policy` in the
plan, whose `policy` attribute is the text. An ARN that matches no
`aws_iam_policy` in the plan is an unknown source.

### Policies whose text the plan lacks

An AWS managed policy such as `arn:aws:iam::aws:policy/ReadOnlyAccess`, or a
customer managed policy created by another stack, is an unknown source. So is
a `policy` attribute that terraform computes at apply time, such as an
`aws_iam_policy_document` that references the ARN of a role this plan creates.

The user can give PermCheck the text of a managed policy through a
`data "aws_iam_policy"` block with the same `arn`. Terraform reads the data
source during the plan when its arguments are known, and PermCheck then uses
its `policy` attribute. The repo has no plan fixture yet that shows where
`terraform show -json` records a data source read at plan time. Terraform's
[JSON output format](https://developer.hashicorp.com/terraform/internals/json-format)
doesn't say whether `prior_state` includes it. Stage 4 starts by capturing a
real plan to settle this, and the README documents the result.

### The plan as the complete set of policies

A one-policy run assumes the document it receives is the principal's whole
policy. A mapped principal makes the same assumption about the plan: the plan
shows each policy attached to it. A policy attached by another stack, or by
hand, can grant a need that PermCheck reports as missing.

Terraform can make the assumption true. The `aws_iam_role_policies_exclusive`
and `aws_iam_role_policy_attachments_exclusive` resources remove any inline
policy or managed attachment the configuration doesn't list
([provider docs for `aws_iam_role`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role)).
When the plan has one of them for a principal, PermCheck reads its list as the
complete set of that kind. Whether a Missing verdict should require them is an
open question for the owner.

### Options rejected

- **Embed the text of AWS managed policies in the binary.** AWS updates them:
  "AWS occasionally updates the permissions defined in an AWS managed policy"
  ([managed and inline policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#aws-managed-policies)).
  A stale copy would miss an action AWS added later, and PermCheck would
  report a gap that doesn't exist. The repo's rule is to report only gaps it
  can prove.
- **Call the IAM API for the policies the plan lacks.** PermCheck runs without
  AWS credentials today, including in static HCL mode, and a pull-request
  check often has none. A live lookup also checks the account as it is now,
  while the plan describes it after the apply.
- **Rebuild a computed `aws_iam_policy_document` from the configuration
  section.** The configuration keeps the expressions, so PermCheck could
  evaluate the literal parts of the document. That means a partial
  interpreter for terraform expressions, with its own bugs, for a result that
  is still partly unknown. An unknown source gives a correct answer with less code.
- **Treat `aws_lambda_permission` as a resource policy now.** It builds one
  statement from separate arguments, and the principal is usually a service,
  which a need doesn't model. It can join later as its own stage.

## Question 2: the key a need uses to select its principal

### Decision

The config file gains a `principals` map. Each key is a label that needs
already use in their `principal` field, and each value gives the terraform
address of the role or user:

```json
{
  "principals": {
    "task": { "address": "aws_iam_role.task" },
    "deploy": { "address": "module.ci.aws_iam_role.deploy" }
  },
  "needs": [
    {
      "sid": "FetchSecrets",
      "principal": "task",
      "actions": ["secretsmanager:GetSecretValue"],
      "resources": ["arn:aws:secretsmanager:us-east-1:123456789012:secret:app-*"]
    }
  ]
}
```

The address is the full instance address as `terraform show -json` prints it,
the same string as `plan.ResourceChange.Address`, with any module path and
instance key: `module.app["eu"].aws_iam_role.task[0]`. Its type must be
`aws_iam_role`, or `aws_iam_user` from stage 11 on. A run with a mapped principal fails with
exit code 2 when the address matches no resource change in the plan, so a
typo doesn't pass as an empty policy set.

The terraform address is always known at plan time and is unique in the plan.
It also tells PermCheck where to find the principal's `name`, `arn` and
`permissions_boundary`.

### Options rejected

- **The role name.** `name_prefix` makes it unknown at plan time, and two
  modules can create roles with the same name in different accounts.
- **The role ARN.** For a role the plan creates, the ARN is computed at apply
  time, so the plan can't match it.
- **Reinterpret the `principal` field as an address.** Users already write
  labels such as `"task"` there, and some of those labels could also parse as
  an address. A separate map keeps each need unchanged and makes the switch
  to the new mode explicit.

A role that isn't in the plan has no address. Whether `principals` should also
accept a role name or ARN for that case is an open question. Such a role's
identity policies are outside the plan, so only its resource policies would be
visible.

## Question 3: how identity and resource policies combine

### Same-account rule

AWS documents the rule for a request in one account: "If an action is allowed
by an identity-based policy, a resource-based policy, or both, then AWS allows
the action. An explicit deny in either of these policies overrides the allow"
([evaluating identity-based policies with resource-based policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-rdp)).
Inside the identity side, any policy's Allow is enough, and any policy's
explicit Deny overrides it
([policy evaluation for requests in one account](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html)).

PermCheck applies the rule by building one `policy.Document` per need and
resource, and passing it to the `Coverage` function that exists today:

1. Take every statement of every identity policy of the principal.
2. Add the statements of each resource policy whose resource may be the
   need's resource, and whose `Principal` may match the principal (see the
   next table). A resource policy statement applies only to the resource the
   policy is attached to, even when its `Resource` is `"*"`. PermCheck
   replaces that `Resource` with the attached resource's ARN, or with its
   target pattern when the ARN is computed, before the merge. Without that
   step, a secret's `"Resource": "*"` would grant the action on every
   resource.
3. Call `Coverage(action, targets, conds, strict)` on the merged document.

A union of Allows with a Deny that overrides them is the same thing as one
document that contains each of their statements, so merging gives AWS's answer without a
second evaluation path. The checks can't drift apart, which is the property
the owner kept when #109 routed needs through `Coverage`.

A resource policy statement matches the principal as follows. The Principal
forms come from the IAM reference
([Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)).

| Principal in the statement | Allow | Deny |
|----------------------------|-------|------|
| The principal's role or user ARN, when PermCheck knows it | grants | definite |
| `"*"` or `{"AWS": "*"}` | grants | definite |
| The account (`arn:aws:iam::111122223333:root` or `111122223333`) | dropped: it delegates to the account's IAM policies and grants nothing to the role by itself | definite when the account is the principal's |
| An ARN whose name part matches the principal's name, with an account PermCheck can't read | may grant | not definite |
| A role session (`arn:aws:sts::...:assumed-role/...`) | may grant | not definite |
| A service, a federated provider, or another principal's ARN | dropped | dropped |
| `NotPrincipal` | dropped: AWS supports `NotPrincipal` only with Deny | definite unless the list may exclude the principal (see [Explicit deny](#explicit-deny)) |

The account row follows the IAM reference: an account principal "delegates
authority to the account" and its administrator "must then grant access to an
identity"
([AWS account principals](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-accounts)).
The `"*"` row follows the same page, which says a wildcard Allow grants IAM
users and roles in the resource's account access by itself, while principals in
other accounts also need an identity policy
([all principals](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-anonymous)).

A statement that *may* grant enters the merged document as an Allow whose
condition PermCheck can't evaluate, so `Coverage` returns covered by default
and unverified under `--strict-resources`. A Deny that isn't definite is
dropped, as `Coverage` already ignores a conditional Deny.

The need's resource selects which resource policies apply. PermCheck compares
the need's ARN with the resource's ARN when the plan knows it. When the plan
doesn't, it compares the need's ARN with the target pattern `internal/iam`
already builds for that resource type, such as a secret's name followed by
AWS's random suffix. A resource whose ARN and pattern are both unknown *may*
be the need's resource. A need without `resources` acts on an unknown
resource, so every resource policy of that service may apply. Their Allows
count, and their Denies apply only when `Coverage` would apply them to an
unknown target today.

### Explicit deny

AWS checks for an explicit Deny in each policy that applies, and "If the
enforcement code finds even one explicit deny that applies, the enforcement
code returns a final decision of Deny"
([how AWS enforcement code logic evaluates requests](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)).
PermCheck applies its current rule to a Deny from any source: the Deny counts
only when it has no `Condition` and covers the whole target. The merged
document applies the rule to resource-policy statements unchanged.

A resource policy can deny through `NotPrincipal`, which denies "all
principals except the principal specified"
([NotPrincipal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html)).
For the need's principal, such a Deny is definite unless its list may exclude
that principal. The list may exclude it when it contains:

- the principal's role or user ARN, or an ARN whose name part matches the
  principal's name while the account is unknown;
- a role session ARN for the principal's role;
- the principal's account, or an account PermCheck can't compare with the
  principal's;
- an entry with a wildcard (`*` or `?`) that may match the principal's ARN,
  a session ARN for its role, or its account, such as
  `arn:aws:iam::444455556666:role/*` for a role in account `444455556666`.

The [Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)
page says a wildcard can't match part of a principal name or ARN, but the
NotPrincipal page doesn't say how AWS treats such an entry. PermCheck matches
the entry as a pattern with the existing ARN matcher and counts a possible
match as an exclusion. Otherwise a wildcard that spares the principal would
turn a granted need into a false Missing verdict.

The list also may exclude the principal when PermCheck can't compare it at
all, such as a principal created with `name_prefix` whose name is unknown at
plan time. In those cases the Deny isn't definite, as a conditional Deny isn't
today.

A listed role isn't always spared. AWS "might validate the account first,
then the role, and then the assumed-role user", and recommends listing both
the role ARN and its account ARN. AWS also says a `NotPrincipal` Deny "will
always deny any IAM principal that has a permissions boundary policy
attached, regardless of the values specified in the `NotPrincipal` element"
([NotPrincipal key points](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html#notprincipal-key-points)).
So when the plan shows a `permissions_boundary` on the principal, PermCheck
treats the Deny as definite whatever the list contains. A Deny whose list
contains the role but not its account is still not definite, since the
documentation says "might", and PermCheck reports only gaps it can prove.

A `NotPrincipal` Allow is unsupported ("Using it with `"Effect":"Allow"` is
not supported", same page), so it grants nothing.

### Permissions boundaries

When the boundary's text is in the plan, PermCheck checks the need against the
boundary on its own, with the same `Coverage` call. A boundary that provably
doesn't allow the action makes the need missing, since identity policies and
a boundary give "the intersection of the two categories"
([evaluating identity-based policies with permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-bound)).

One exception follows the enforcement-code page. A resource policy that grants
a role session ARN directly isn't limited by the boundary. A grant to the role
ARN is limited
([how AWS enforcement code logic evaluates requests](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)).
A session ARN in a resource policy already counts as "may grant", so a
boundary gap with such a grant is covered by default and unverified under
`--strict-resources`. A grant to an IAM user ARN isn't limited by the
boundary either, and PermCheck follows the same page for users.

A boundary whose text the plan lacks is an unknown source. It can only remove
permissions, so it never changes a covered verdict by default. Under
`--strict-resources` a need that a boundary might block is unverified with the
reason `policy_unknown`.

### Organization and session policies

Service control policies apply to the principal's account and resource control
policies to the resource's account, and both must allow the request
([evaluating identity-based policies with SCPs or RCPs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html#policy-eval-basics-id-scp)).
A session policy comes from the call that created the session. The plan may
contain an `aws_organizations_policy`, but it doesn't show which account the
principal runs in, and it never shows a session policy.

PermCheck treats each of them as allowing. They can only remove permissions,
so a covered verdict means "covered by the policies the plan shows", and a
missing verdict stays provable. The README says so, and the JSON report of a run with a mapped principal gains
a top-level `not_evaluated` list with `scp`, `rcp` and `session_policy` so
that a consumer can read the limit without the README.

### Cross-account needs

For a request across accounts, "AWS performs two evaluations" and "The request
is allowed only if both evaluations return a decision of Allow"
([cross-account policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html)).
The identity side must allow the request on its own, and a resource policy in
the other account must also allow it.

PermCheck treats a need as cross-account when it knows both account IDs and
they differ: the account in the need's resource ARN, and the account in the
principal's known `arn`. A plan can create resources in more than one account,
through provider aliases, so the resource's policy may be in the plan. PermCheck
evaluates the two sides apart, and the need is covered only when both are:

1. **Identity side.** The principal's identity policies and its boundary, with
   the same `Coverage` call as in one account. A provable gap here makes the
   need missing, whatever the resource policy says.
2. **Resource side.** The resource policies in the plan whose resource may be
   the need's resource, with the statements whose `Principal` may match the
   principal. The account principal row of the Principal table now grants,
   since it specifies the principal's own account and the identity side already
   allowed the call. A provable gap here also makes the need missing. When
   the plan has a policy source for the resource, PermCheck reads it as the
   resource's whole policy, since Secrets Manager, for one, replaces the existing
   policy on each `PutResourcePolicy` call
   ([Secrets Manager resource-based policies](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html#auth-and-access_resource_sdk)).
3. When the plan has no policy source for the resource, its policy is an
   unknown source. The need is covered by default and unverified under
   `--strict-resources` with the reason `cross_account`.

When either account ID is unknown, PermCheck applies the same-account rule,
which allows more than the cross-account rule does. A wrong guess there can
hide a gap, and it can't report a false one.

### Key policies and role trust policies

AWS names these two as exceptions: they "must explicitly allow access for
principals"
([how AWS enforcement code logic evaluates requests](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)).
For a KMS key, an IAM policy has effect only when the key policy lets the
account use IAM policies, through a statement with the account principal
([default key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#key-policy-default-allow-root-enable-iam)).

The union rule would give the wrong answer for both. So the first stages
don't read `aws_kms_key.policy`, `aws_kms_key_policy` or
`assume_role_policy`, and a need on a KMS key or on `sts:AssumeRole` is
checked against the identity side, as today. A later stage can add the KMS
rule: covered when the key policy allows the principal, or when it allows the
account and an identity policy allows the action.

## Undecidable overlaps in the new cases

`arnIntersect` in `internal/policy/arn.go` returns true for a pair of patterns whose
overlap is undecidable, so PermCheck reports a gap only when it can prove one. The design
extends the rule to each new case:

| New undecidable case | Default | `--strict-resources` |
|----------------------|---------|----------------------|
| A source whose link to the principal is undecidable | its Allows count, its Denies don't | unverified, `condition` |
| A resource whose ARN may be the need's resource | its policy's Allows count, its Denies apply only when definite | unverified, `resource_scope` |
| A resource policy statement whose `Principal` may match | the Allow counts, the Deny doesn't | unverified, `condition` |
| An unknown source (computed text, managed policy outside the plan, unknown boundary) | it may grant, it never denies | unverified, `policy_unknown` |
| A cross-account need whose resource policy isn't in the plan | the identity side decides Missing | unverified, `cross_account` |

`policy.UnverifiedReason` gains `ReasonPolicyUnknown` and `ReasonCrossAccount`.
Their `Value()` strings are `policy_unknown` and `cross_account`, so a JSON
consumer that matches on `resource_scope` and `condition` keeps working.

An unknown source can't supply a definite Deny, so it never turns a covered
need into a missing one. It can turn a missing need into a covered one. That
direction is the one the rule allows.

### Sources a release doesn't read yet

The stages add source types one pull request at a time, so a release can meet
a plan resource that sets a policy PermCheck doesn't read yet. If PermCheck
skipped it, a grant the plan shows would be absent, and the need would be
reported missing although the plan grants it. So from the first release that
a user can turn on, PermCheck knows the full list of source types in the
tables of question 1. A resource of a listed type that the release doesn't
read yet is an unknown source, with the same link rules as a read one:

- An identity or boundary source whose link may match the principal makes the
  need covered by default and unverified under `--strict-resources` with the
  reason `policy_unknown`.
- A resource-policy source whose resource may be the need's resource does the
  same. Before stage 6 parses `Principal`, every resource policy counts this
  way, read or not.

Each stage that reads a type moves it from that path to the read path, and its
red test shows a verdict that changes from unverified to covered or missing.
Stage 3 also accepts only `aws_iam_role` addresses in `principals`. An
`aws_iam_user` address fails with exit code 2 until stage 11 reads user and
group policies, since a user's grants come mostly from group policies.

## Question 4: the report for a policy whose JSON is unknown

### Decision

An unknown source doesn't produce a finding of its own. Its effect on each need follows
the table above: covered by default, unverified under `--strict-resources`.
The run also prints one notice per unknown source, to stderr, in every format
except `json`:

```
notice: aws_iam_role_policy.task_secrets: policy text is known only after apply; needs of "task" may be granted by it
```

In `--format json`, the report gains a `policy_sources` list per mapped
principal, with each source's address, kind (`identity`, `boundary` or
`resource`) and `"text": "known"` or `"text": "unknown"`. A notice doesn't
change the exit code, as a warning doesn't today.

### Options rejected

- **Fail the run.** A computed policy is common: an `aws_iam_policy_document`
  that references a role or secret the same plan creates is computed at apply
  time. Failing would break the main use case.
- **Treat the unknown source as empty.** The source may grant the need, so the
  gap isn't provable. PermCheck would report gaps that the apply then
  disproves.
- **Make the need unverified in the default mode.** The default mode reports
  only provable gaps, and `--strict-resources` is the existing switch for "tell
  me what you couldn't check". A second switch for the same idea would split
  it.

## Question 5: config, CLI, and compatibility

### Config

`principals` is the only new key. A need's `principal` keeps its meaning as a
label. A need whose label appears in `principals` is a *mapped need*, and
PermCheck checks it against the plan's policies. Any other need keeps today's
behavior and is checked against the document from the `--policy-*` flag.

`ValidateNeeds` gains two checks. The address must have the type
`aws_iam_role`, or `aws_iam_user` from stage 11 on. A key in `principals` that
no need uses is an error, as an unknown `--principal` is today.

### CLI

No new flag. The current flags keep their meaning:

- One `--policy-*` source stays required in plan mode. It's the policy of the
  principal that runs terraform, which the plan-resource check needs, and
  that principal is rarely in the plan it applies.
- Mapped needs ignore the `--policy-*` document. They read the plan's
  policies.
- `--principal NAME` runs the needs without a principal, plus the needs
  labelled NAME, as today. When NAME is mapped, those needs use the plan's
  policies.
- Without `--principal`, a run with a `principals` map checks the needs of
  every mapped principal. It answers the question
  [#36](https://github.com/elecnix/terraform-permcheck/issues/36) opened with
  in one run. An unmapped label still runs only when `--principal` selects it.
- Static HCL mode has no plan, so a mapped need there is a usage error with
  exit code 2.

A finding from a mapped need shows the principal's label in the text and
annotation source line, `needs "FetchSecrets" of task`, and a `principal` key
in the JSON. Needs of different mapped principals can then share a sid.

### Compatibility

A config file without `principals` behaves as today. The flags, the needs
selection and the exit codes don't change, and the output is the same byte for
byte. The
golden tests in `report_golden_test.go` prove it, since stage 3 adds the new
JSON keys only when a principal is mapped.

`config.parse` uses `json.Unmarshal` without `DisallowUnknownFields`. So a
binary older than this change ignores `principals` and checks every
need against the `--policy-*` document. The README states the version that
first reads the key.

## Worked example 1: an ECS task role reads a secret

```hcl
resource "aws_iam_role" "task" {
  name               = "app-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
}

resource "aws_iam_role_policy" "task_logs" {
  role   = aws_iam_role.task.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "*"
    }]
  })
}

resource "aws_secretsmanager_secret" "app" {
  name = "app-db"
}

resource "aws_secretsmanager_secret_policy" "app" {
  secret_arn = aws_secretsmanager_secret.app.arn
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:role/app-task" }
      Action    = "secretsmanager:GetSecretValue"
      Resource  = "*"
    }]
  })
}
```

```json
{
  "principals": { "task": { "address": "aws_iam_role.task" } },
  "needs": [
    {
      "sid": "FetchSecrets",
      "principal": "task",
      "actions": ["secretsmanager:GetSecretValue"],
      "resources": ["arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-*"]
    }
  ]
}
```

PermCheck finds one identity source, `aws_iam_role_policy.task_logs`, through
the reference from `role` to `aws_iam_role.task`. It finds one resource source,
`aws_secretsmanager_secret_policy.app`, whose `secret_arn` references
`aws_secretsmanager_secret.app`. The secret's ARN is computed, so PermCheck
compares the need's ARN with the target pattern for a secret named `app-db`,
and they may overlap. The statement's principal is the role ARN
`arn:aws:iam::123456789012:role/app-task`. The role's name `app-task` is
known, and its ARN is computed, so the name part matches and the account is
undecidable. The statement *may* grant.

| Variant | Verdict | Strict verdict |
|---------|---------|----------------|
| As written | covered | unverified (`condition`): the principal's account isn't known at plan time |
| The role's ARN is known (an existing role) | covered | covered |
| The secret policy is removed | missing: no identity policy allows `GetSecretValue` | missing |
| The secret policy adds `{"Effect": "Deny", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}` | missing: a definite Deny | missing |
| The same Deny with `"Condition": {"StringNotEquals": {"aws:sourceVpce": "vpce-1a2b"}}` | covered | unverified (`condition`) |
| The secret policy uses `data.aws_iam_policy_document` with `aws_iam_role.task.arn` | covered, with a notice | unverified (`policy_unknown`) |

The last row is the common one. The role's ARN is computed, so terraform
reads the data source during the apply, and the plan shows the policy text as
unknown. The notice tells the user why the check couldn't use the secret's
policy.

The fourth row is the one the one-policy run gets wrong today. A user who
exports the inline policy and the secret grant into one document sees the
need as covered, while AWS denies the call.

## Worked example 2: a CI deploy role with an attached managed policy

```hcl
resource "aws_iam_role" "deploy" {
  name               = "ci-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_oidc.json
}

resource "aws_iam_role_policy_attachment" "deploy_ecr" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"
}

resource "aws_iam_policy" "deploy_ecs" {
  name   = "ci-deploy-ecs"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ecs:UpdateService", "ecs:DescribeServices"]
      Resource = "arn:aws:ecs:us-east-1:123456789012:service/app/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "deploy_ecs" {
  role       = aws_iam_role.deploy.name
  policy_arn = aws_iam_policy.deploy_ecs.arn
}
```

```json
{
  "principals": { "deploy": { "address": "aws_iam_role.deploy" } },
  "needs": [
    {
      "sid": "VerifyImage",
      "principal": "deploy",
      "actions": ["ecr:DescribeImages"],
      "resources": ["arn:aws:ecr:us-east-1:123456789012:repository/app"]
    },
    {
      "sid": "RollService",
      "principal": "deploy",
      "actions": ["ecs:UpdateService"],
      "resources": ["arn:aws:ecs:us-east-1:123456789012:service/app/web"]
    },
    {
      "sid": "ReadParams",
      "principal": "deploy",
      "actions": ["ssm:GetParameter"],
      "resources": ["arn:aws:ssm:us-east-1:123456789012:parameter/app/*"]
    }
  ]
}
```

PermCheck finds two attachments. `deploy_ecs` resolves through its reference
to `aws_iam_policy.deploy_ecs`, whose text is known. `deploy_ecr` names an AWS
managed policy that the plan doesn't contain, so it's an unknown source.

| Need | Verdict | Strict verdict |
|------|---------|----------------|
| `RollService` | covered by `aws_iam_policy.deploy_ecs` | covered |
| `VerifyImage` | covered, with a notice for `deploy_ecr` | unverified (`policy_unknown`) |
| `ReadParams` | covered, with a notice for `deploy_ecr` | unverified (`policy_unknown`) |

`ReadParams` shows the cost of an unknown source. The managed policy is about
ECR, but PermCheck can't read its text to prove the SSM gap. Adding the
data source below gives PermCheck the text, if stage 4 confirms that the plan
records it:

```hcl
data "aws_iam_policy" "ecr_power_user" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"
}
```

With the text known, the statements of the managed policy decide
`VerifyImage`, and `ReadParams` is missing, since no source the plan shows
grants `ssm:GetParameter`.

The one-policy run can't express this role at all. Its policy is the union of
two documents, and one of them isn't in the plan.

## Test plan

Each stage starts with a failing test. The tests use plan JSON fixtures in
`testdata`, built from `terraform show -json` where a stage depends on how
terraform writes a value, and hand-written otherwise.

- **Plan extraction** (`internal/plan`): one test per source type in the
  tables above. Each checks the address, the kind, the text or the unknown
  marker, and the link to the principal or resource by reference, by value,
  and as undecidable. Cases: a replace, a delete (no source), a no-op (the
  current value), `count` and `for_each` instances, and a module path.
- **Merging and coverage** (`internal/policy`): the merged document gives the
  same verdict as `Coverage` on a hand-merged document, for each row of the
  same-account and undecidable-overlap tables. A property test can check that
  splitting a document into two sources never changes a verdict.
- **Principal matching** (`internal/policy`): one case per row of the
  Principal table, including `{"AWS": "111122223333"}`, a list of principals,
  and an ARN with a name match and an unknown account. `NotPrincipal` cases:
  a Deny whose list holds another role only (definite), the principal's role
  and account (not definite), a name match with an unknown account (not
  definite), a wildcard entry `arn:aws:iam::444455556666:role/*` that may
  match the principal (not definite), a wildcard in another account
  (definite), another role while the principal has a boundary (definite), and
  an Allow (dropped).
- **Boundaries**: a boundary that allows, that provably doesn't, that has
  unknown text, and a resource policy that grants the role ARN under a
  boundary that doesn't allow.
- **Cross-account**: known and differing accounts, one unknown account, and a
  need without resources.
- **Wiring** (`internal/check`): a mapped need ignores the `--policy-*`
  document, an unmapped need uses it, `--principal` with and without a
  mapping, a mapped principal missing from the plan (exit 2), and static mode
  (exit 2).
- **Compatibility** (`report_golden_test.go`): the existing golden files
  don't change. New golden files cover the notice line, the `principal` key,
  `policy_sources`, and `not_evaluated`.
- **Worked examples**: both examples become fixtures in `testdata`, and a test
  asserts each row of their verdict tables.

## Stages

Each stage is one pull request that opens with a red test. After each one,
`main` is releasable. Stages 1 and 2 add code that nothing calls yet. Stage 3 is the
first that a user can turn on.

1. **Extract inline role policies from the plan.** `plan.PolicySources`
   returns `aws_iam_role_policy` and `aws_iam_role.inline_policy` sources with
   their address, text or unknown marker, and role link. Red: a fixture with
   one known and one computed `aws_iam_role_policy`.
2. **Merge documents and carry unknown sources.** `policy.Merge` concatenates
   statements, and an unknown source enters as a grant with
   `ReasonPolicyUnknown`. Red: a need covered only by the second of two
   documents, and a need that an unknown source makes unverified under strict.
3. **The `principals` config key and its wiring.** A mapped need runs against
   the merged inline policies of its role. Each other source type of
   question 1 that may apply is an unknown source, as
   [Sources a release doesn't read yet](#sources-a-release-doesnt-read-yet)
   describes. The notice line and the JSON `principal` and `policy_sources`
   keys arrive here. Red: the worked example 1 fixture without the secret
   policy reports `FetchSecrets` missing. With the secret policy it reports
   covered, and unverified under strict. Worked example 2 reports
   `RollService` unverified under strict, not missing, because its grant
   comes from an attachment. The golden files don't change.
4. **Managed policy attachments.** `aws_iam_role_policy_attachment`,
   `aws_iam_policy_attachment`, `managed_policy_arns`, resolution to
   `aws_iam_policy`, AWS managed ARNs as unknown sources, and the
   `data "aws_iam_policy"` lookup once a captured plan shows where terraform
   records it. Red: worked example 2, where `RollService` changes from
   unverified to covered under strict.
5. **Exclusive attachment resources.** `aws_iam_role_policies_exclusive` and
   `aws_iam_role_policy_attachments_exclusive` mark a role's set as complete.
   Red: depends on the owner's answer to open question 1.
6. **Parse `Principal` and `NotPrincipal`.** `policy.Statement` gains both,
   with the matching rules of the Principal table. Identity policies ignore
   them, as AWS does. Red: one case per table row.
7. **Secrets Manager resource policies.** `aws_secretsmanager_secret_policy`
   and `aws_secretsmanager_secret.policy` join the merged document. Red:
   worked example 1, each row.
8. **One more service per pull request**: S3, SQS, SNS, ECR. Each links the
   service's documentation for the same-account rule. Red: one fixture per
   service.
9. **Permissions boundaries.** Red: the boundary cases in the test plan.
10. **Cross-account needs.** `ReasonCrossAccount`. Red: the cross-account
    cases in the test plan.
11. **IAM users and groups.** User policies, group policies, and group
    membership, and `principals` accepts `aws_iam_user` addresses. Red: a
    user whose only grant comes from a group.
12. **README and `not_evaluated`.** The README's "Policy evaluation" and
    "Permissions a principal needs beyond terraform" sections describe the
    new mode, and the JSON report gains `not_evaluated`. The README changes
    alongside each stage too, so stage 12 rewrites the overview only.

## Open questions for the owner

1. Should a Missing verdict for a mapped principal require an exclusive
   attachment resource in the plan? Requiring it makes each reported gap
   provable against policies attached outside terraform, but most
   configurations don't use those resources, so few gaps would be reported.
   This design proposes no, with the closed-world assumption documented.
2. Should `principals` accept a role name or ARN for a role outside the plan,
   so that its resource policies in this plan can be checked?
3. Should a run with only mapped needs accept no `--policy-*` source, so that
   a stack that creates roles can check their needs without a deploy policy?
4. Should the KMS key policy rule join the stages, and before or after the
   other resource-policy services?
5. Is one notice per unknown source the right volume, or should the text
   report print one summary line with a count?

## References

- AWS, [Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- AWS, [Policy evaluation for requests in one account](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html)
- AWS, [How AWS enforcement code logic evaluates requests to allow or deny access](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)
- AWS, [Cross-account policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html)
- AWS, [The Principal element of IAM JSON policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)
- AWS, [Managed policies and inline policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- AWS, [Default key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html)
- AWS, [Secrets Manager resource-based policies](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html)
- HashiCorp, [JSON output format](https://developer.hashicorp.com/terraform/internals/json-format)
- HashiCorp, [`aws_iam_role` resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role)
