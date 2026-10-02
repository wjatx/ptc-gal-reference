# CDK context contract — every value a deploy can be given, and what happens without it

`infra/` takes all of its deploy-time configuration from CDK context, passed as `-c key=value` at
synth or deploy. There are **31 keys**. `infra/cdk.json` supplies a value for none of them (its
`context` block holds two CDK feature flags), so every deploy either passes a key explicitly or
gets the code's default.

This document is the reference for which ones you must pass. `docs/operator-identities.md` is the
operator runbook for the five ceremony gates and goes deeper on those; this is the complete list.

## Read this part first: three failure modes, and only one of them is loud

The reason this document exists is that "required" is the wrong axis. Almost nothing here is
required in the sense of stopping you. Sort by what a missing value *does*:

| Mode | What you see | How many |
|---|---|---|
| **(a) Hard fail** | synth or deploy stops, or the service never starts | 11 |
| **(b) Silent degradation** | deploy succeeds, and a resource, a gate or a control is quietly absent | 11 |
| **(c) Harmless default** | deploy succeeds with a documented, intended default | 9 |

Mode (b) is the whole hazard. A deploy that omits `channelsVerifyKeysArn` comes up green with
signature verification switched off. A redeploy that omits `makerTrustedPrincipals` comes up green
having deleted half of maker≠checker. Neither prints a warning, because from CloudFormation's point
of view you asked for exactly what you got.

**The standing protection is `cdk diff` before every deploy, read for resource-level removals.**
Capture it with `> file 2>&1`: CDK writes the diff to stderr, so a plain `> file` produces an empty
file that any grep passes vacuously.

## Required — mode (a)

**`environment`** is the only key required on every deploy, and the only one with no silent-failure
mode at all. It must be exactly `development`, `staging` or `production`. A missing value throws
naming the three legal values; a misspelling (`dev`, `prod`, `stage`) throws a second, distinct
error, because stack names, tags and cross-stack `ImportValue` interpolate the literal string and a
one-character difference breaks the wiring silently at a layer where it is much harder to see.

```
cdk deploy -c environment=development ...
```

The image digests are required wherever a stack deploys an image, and have their own section
below.

Five more mode-(a) keys are **conditionally** required, and each is required only because
another key was supplied:

- `channelsDrainManifestPath` and `channelsDrainReceiver` are required if and only if a drain
  image key is set (`channelsDrainImageDigest`, or `channelsDrainImageTag` under the override).
  Synth throws naming both.
- `channelsMissileerDrainManifestPath` and `channelsMissileerDrainReceiver` stand in the same
  relation to the missileer drain's image key.
- Setting either drain's image key while `channelsDeployFunction=false` throws rather than
  deploying no drain, because the drain construct lives past that flag's early return.

`brokerManifestPath` is required for a different reason: the broker cannot start without it. It
sets `BROKER_MANIFEST`, and the broker task runs `BROKER_STORE=dynamo`, where an unset manifest is a
boot refusal (`BrokerConfigError`, "refusing to fall back to the checked-in example manifest"), not
a fallback. Synth does not check it, because a `brokerDesiredCount=0` bringup legitimately deploys
before any consumer image exists. So the failure arrives at deploy time with one or more tasks: each
task exits at boot, the service never reaches steady state, and the deployment circuit breaker rolls
the rollout back. CloudFormation reports the circuit breaker; only the broker log group
(`/safe-agents/<env>/broker`) names the missing variable. The path names a manifest inside the
image, normally one a consumer layer built `FROM` the base broker image copies in;
`examples/embedded_agent/Containerfile.broker` is the smallest such layer.

> `channelsMissileerDrainManifestPath` is read through a line-wrapped `tryGetContext(` call, so the
> obvious one-line grep for context keys does not find it. It was missing from every inventory of
> this surface until 2026-08-10. If you are enumerating these keys with a regex, match across
> newlines.

## Images are pinned by digest — mode (a), with one recorded override

Every container image a stack deploys is named by digest, and no image has a default. A digest is
the SHA-256 of the image manifest, so the image that runs is the image you reviewed. A tag is a
pointer that can be moved after the review, and `latest` moves on every push.

| Image | Digest key | Tag key (override only) | Required when |
|---|---|---|---|
| broker (the broker service task and the client task) | `brokerImageDigest` | `brokerImageTag` | the Compute stack is deployed |
| channels airlock | `channelsAirlockImageDigest` | `channelsAirlockImageTag` | `channelsDeployFunction` is not `false` |
| channels drain | `channelsDrainImageDigest` | `channelsDrainImageTag` | never: the key is the drain's phase gate |
| missileer drain | `channelsMissileerDrainImageDigest` | `channelsMissileerDrainImageTag` | never: the key is the drain's phase gate |

One broker key pins two task definitions, because the broker service and the client task read the
same repository and run the same image.

The rules are the same for all four images and live in `infra/lib/image-pin.ts`:

- A digest key takes `sha256:` followed by exactly 64 lowercase hexadecimal characters. Anything
  else throws at synth, including an empty value from an unset shell variable, which is never read
  as "unset".
- A tag key throws at synth unless `-c allowMutableImageTags=true` is also passed. The message
  names the digest key to pass instead.
- Both keys for one image throw.
- Neither key, for an image its stack deploys, is an error on that stack. `cdk synth`, `cdk diff`
  and `cdk deploy` refuse any selection that includes the stack. The service or function stays in
  the template, so a redeploy that forgot the key is refused. It deletes nothing, and it does not
  fall back to a tag.

The last rule is scoped to the stack on purpose. All five stacks are built by every `cdk` command,
so a throw would make a Network or Identity deploy, or a `cdk destroy`, ask for an image digest it
does not use. Those commands need no image key. The refusal is the CDK CLI's handling of an error
on a stack, and `--ignore-errors` skips it. The template then names `sha256:` followed by 64
zeros, a digest no image has, so there is nothing for the deploy to pull.

**The override.** `-c <image>ImageTag=<tag> -c allowMutableImageTags=true` deploys that image by
tag. It exists for one case: the first Compute deploy, before any image has been pushed. Besides
rendering the tag, it does two things. Synth prints a warning naming the image and the tag on every
run, and `--strict` turns that warning into a failure. The stack also gets the CloudFormation
stack tag `safe-agents:mutable-image-tags`, whose value lists every image in that stack deployed
by tag, for example `broker=bootstrap` or `channels-airlock=v3 channels-drain=v7`. The stack tag
is the record. It is sent to CloudFormation with the deploy, so
`aws cloudformation describe-stacks --query 'Stacks[0].Tags'` shows it on the deployed stack and
CloudTrail records it with the call. Redeploying by digest removes it.

**Images outside this app.** The agent task image and the AMIs are chosen by the provisioners
(`safe_agents/arms/`), which this app does not deploy. They follow the same rule through
`safe_agents/pipeline/image_pin.py`: the Fargate arm takes `--image-uri` by digest, the instance
arms take `--ami-id`, and both refuse when nothing is named. Their overrides are
`--allow-mutable-image-tag` and `--allow-newest-ami`. The record those overrides leave is a WARNING
log line and a line in the pipeline plan. Nothing is written on the task definition or the
instance, so it is a weaker record than the stack tag above. `docs/consuming-the-sdk.md` §4 has the
flags.

**Reading a digest.** Push under a tag that has not been used, and have the push write the digest
down:

```
TAG="broker-$(git rev-parse --short HEAD)-$(date +%Y%m%d%H%M%S)"
podman push --digestfile /tmp/broker.digest safe-agents-broker:dev "docker://${REPO}:${TAG}"
DIGEST="$(cat /tmp/broker.digest)"     # sha256:<64 hex>
```

`--digestfile` records the digest of what that push sent. Without podman, ask the registry what
the tag you just pushed points at:

```
aws ecr describe-images --repository-name safe-agents-<env>-broker \
  --image-ids imageTag="${TAG}" --query 'imageDetails[0].imageDigest' --output text
```

For a stack that was deployed by tag before this rule, the digest to pass is the one that is
running, which the tag may no longer point at. Read it from the running task
(`aws ecs describe-tasks --cluster safe-agents-<env>-cluster --tasks <task-arn> --query
'tasks[0].containers[0].imageDigest'`) or from the function (`aws lambda get-function
--function-name safe-agents-<env>-airlock --query Code.ResolvedImageUri`).

**The first Compute deploy.** No image exists until the stack has created the repository, so the
first deploy uses the override and runs no task:

```
cdk deploy SafeAgents-Compute-<env> -c environment=<env> \
  -c brokerImageTag=bootstrap -c allowMutableImageTags=true -c brokerDesiredCount=0 \
  -c brokerManifestPath=<path in the image>
# push the image under a unique tag and read its digest (above), then:
cdk deploy SafeAgents-Compute-<env> -c environment=<env> \
  -c brokerImageDigest="${DIGEST}" -c brokerManifestPath=<path in the image>
```

Nothing pulls the `bootstrap` tag, because no task runs at a desired count of zero. The second
deploy starts the broker on the pinned image and removes the stack tag. The airlock needs no
override: its first deploy is `channelsDeployFunction=false`, which deploys no function and so
needs no image.

**The repositories.** The four ECR repositories (broker, agent, airlock, channels-drain) are
created with immutable tags. A push to a tag that already exists is refused, so every push needs a
unique tag, such as one built from the commit and the time. Two limits apply:

- Each repository's lifecycle rule keeps the ten most recent images, and it counts images, not
  references. A digest that a task definition or a function still names can be expired. The next
  task start or function update then fails with a pull error; it does not run a different image.
- Under `reuseComputeArtifacts` or `reuseChannelsArtifacts` the repositories are imported by name
  and the stack does not manage them. Their tag mutability is whatever it already was.

## The five ceremony gates — mode (b), and the sharpest instance of it

All five take a list of IAM principal ARNs, as an array or a comma-separated string. **Unset and
empty are indistinguishable**; both mean the gate is off. None of them fails synth. They split into
two groups whose failure modes are genuinely different, and conflating them is the mistake to avoid:

| Context | Role | If omitted |
|---|---|---|
| `makerTrustedPrincipals` | **MakerRole** | role is **not synthesized**; a redeploy **deletes** it |
| `checkerTrustedPrincipals` | **CheckerRole** | role is **not synthesized**; a redeploy **deletes** it |
| `auditorTrustedPrincipals` | **AuditorRole** | role is **not synthesized**; a redeploy **deletes** it |
| `promotionTrustedPrincipals` | **PromotionRole** | role **survives**; only operator assumability drops |
| `demotionTrustedPrincipals` | **DemotionRole** | role **survives**; only operator assumability drops |

For the first three the role is wrapped in `if (principals.length > 0)`, so omitting the context on
a redeploy removes a role that already exists. Omit maker and checker together and you have silently
deleted maker≠checker.

For the last two the context is *additive* to a trust policy that always exists: supplied, the named
ARNs join the service principals; omitted, trust reverts to the service principals alone. The role,
its policies and its ARN export are unaffected. What breaks is the human path, and it breaks in the
way this platform specifically warns about: a failed `sts:assume-role` from an admin baseline falls
back to admin, which is more authority than intended rather than less.

Pass the underlying role ARN (`arn:aws:iam::<acct>:role/<name>`). An
`arn:aws:sts::...:assumed-role/...` form is not valid as an IAM trust principal.

To recover the values for an already-deployed stack, read them off the deployed trust policies
rather than guessing:

```
aws iam get-role --role-name <physical-id> --query Role.AssumeRolePolicyDocument
```

## Controls that ship OFF — mode (b), by design

These are off unless you switch them on. That is deliberate (see `docs/friction-doctrine.md`: a tiny
non-negotiable floor, every other bound an envelope knob shipping off), but each one is a control
you may believe you have and do not.

**`channelsVerifyKeysArn`** points at a Secrets Manager secret holding peer verification keys. The
stack never creates it. Omitted, the execution role gets no second `GetSecretValue` statement and
`BROKER_VERIFY_KEYS_SECRET_ARN` is unset, so key resolution returns nothing and **unsigned peers
pass**. This key is the one that was documented nowhere before this file existed.

**`channelsScreenModelArns`** is a comma-separated list of Bedrock model ARNs. Omitted, the
execution role carries no `bedrock:InvokeModel` statement at all, which is intentional: an off
control's authority must not sit in the role. The trap is the combination — if a consumer's manifest
enables the classifier screen while this context is omitted, the screen has no IAM path to Bedrock
and fails closed, surfacing only as a `ScreenError` alarm.

**`capabilityRoles`** takes a JSON array of capability specs. Omitted, no per-capability roles are
created and no `sts:AssumeRole` statement is added. A malformed JSON value throws, and an entry with
empty `actions` or `resources` throws a named error, so a *present* value fails loudly even though
an absent one does not.

**`secureNetwork`** is the one mode-(c) control worth stating here anyway. Absent (or any value
other than boolean `true` / string `'true'`, so `'True'` and `'1'` are false) you get the flat public
VPC: no NAT, no interface endpoints, broker security group `allowAllOutbound`, broker task assigned a
public IP. Network-layer egress containment is traded back to the code and credential layer, which
stays on. The deploy publishes `network-mode` as `secure` or `open` so the choice is self-describing.

## Phase gates — mode (b), where absence is the interface

In the channels stack, several keys work as build-order switches. Absence is not a misconfiguration;
it is how you deploy phase 1 before the images exist.

`channelsDeployFunction` defaults to **true** (note the inverted default: only an explicit `false`
turns it off). Set false, the stack early-returns after synthesizing the two ECR repos, the accepted
queue, the webhook secret and five exports. No Lambda, no HTTP API, no alarms, no drains.

Each drain's image key is its own gate. With neither `channelsDrainImageDigest` nor
`channelsDrainImageTag` set, the drain Lambda, role, log group and event source are not created,
while the ECR repo is created unconditionally so you can push an image before first supplying the
key. The missileer drain's keys work the same way. The gate is still mode (b) on a redeploy: one
that omits a deployed drain's image key removes that drain.

`channelsManifestPath` omitted yields a deliberately manifestless airlock, which is a supported
state rather than a broken one.

**The airlock image has no default.** `channelsAirlockImageTag` used to default to `latest`, so a
redeploy that omitted it repointed the live airlock Lambda at whatever `latest` was. A redeploy
that omits `channelsAirlockImageDigest` is now refused at synth. The rest of the airlock's live
context (`channelsManifestPath`, `channelsScreenModelArns`, `channelsVerifyKeysArn`) is still mode
(b) and still has to be passed again on every channels deploy.

## Redeploy traps — mode (a), but only on the second deploy

`reuseComputeArtifacts` and `reuseChannelsArtifacts` both default to false, which is correct on a
first deploy into a clean account: CDK creates the ECR repositories and log groups (for Compute,
the broker's and the client task's). In a durable
environment those resources are `RETAIN`, so they survive a stack deletion, and a subsequent
re-create collides on their fixed names and **fails at deploy time**, not at synth. Pass them as
true when redeploying a stack whose retained artifacts still exist. A repository imported this way
is not managed by the stack, so it does not get the immutable-tag setting described above.

Both were documented nowhere in this repository before this file.

`brokerDesiredCount` defaults to `1`. On a first bringup, before the broker image and HMAC secret
exist, one task can never reach steady state and the deployment circuit breaker rolls the rollout
back. Deploy at `0` under the image override, push the image, then redeploy by digest
(`docs/broker-service-bringup.md`).

## GitHub Actions OIDC — mode (c), where the default trusts nobody

**`githubOidcSubjects`** names the OIDC subject patterns the two read-only watcher roles accept,
as an array or a comma-separated string. Unset, both roles are still created and their ARNs still
exported, but their trust policy carries a sentinel no GitHub token can present, so nothing can
assume them. That is the intended default: a watcher role that trusts an unnamed repository would
be worse than one nobody can use.

Pass **both spellings of your repository**, because GitHub emits two for the same workflow:

```
cdk deploy -c environment=development \
  -c githubOidcSubjects=repo:acme/widget:*,repo:acme@12345678/widget@87654321:*
```

The plain `owner/repo` form is what older organizations send. Newer ones append the immutable
numeric org and repo IDs. Getting this wrong produces a trust policy that is correct in IAM and
still refuses `sts:AssumeRoleWithWebIdentity`, because it is right about a subject GitHub is not
sending; only CloudTrail's `userIdentity.principalId` shows the claim that actually arrived. The
ID form is the rename-proof one, since the numbers outlive any repo or org rename.

## The complete list

| Key | Mode | Default | Stack |
|---|---|---|---|
| `environment` | (a) | none, required | app |
| `secureNetwork` | (c) | `false` | app → network, compute |
| `brokerDesiredCount` | (a) on first deploy | `1` | compute |
| `brokerGrantClasses` | (c) | unset | compute |
| `brokerImageDigest` | (a) | none; the stack is refused without an image key | compute |
| `brokerImageTag` | (c) | unset; throws without `allowMutableImageTags=true` | compute |
| `allowMutableImageTags` | (c) | `false` | compute, channels |
| `brokerManifestPath` | (a) when a task starts | unset; the broker refuses to boot | compute |
| `capabilityRoles` | (b) | `[]` | compute |
| `reuseComputeArtifacts` | (a) on redeploy | `false` | compute |
| `reuseChannelsArtifacts` | (a) on redeploy | `false` | channels |
| `channelsDeployFunction` | (c) | **`true`** | channels |
| `channelsAirlockImageDigest` | (a) unless `channelsDeployFunction=false` | none; the stack is refused without an image key | channels |
| `channelsAirlockImageTag` | (c) | unset; throws without `allowMutableImageTags=true` | channels |
| `channelsManifestPath` | (b) | unset | channels |
| `channelsScreenModelArns` | (b) | `[]` | channels |
| `channelsVerifyKeysArn` | (b) | unset | channels |
| `channelsDrainImageDigest` | (b) | unset; no drain | channels |
| `channelsDrainImageTag` | (c) | unset; throws without `allowMutableImageTags=true` | channels |
| `channelsDrainManifestPath` | (a) if a drain image key is set | unset | channels |
| `channelsDrainReceiver` | (a) if a drain image key is set | unset | channels |
| `channelsMissileerDrainImageDigest` | (b) | unset; no missileer drain | channels |
| `channelsMissileerDrainImageTag` | (c) | unset; throws without `allowMutableImageTags=true` | channels |
| `channelsMissileerDrainManifestPath` | (a) if a missileer drain image key is set | unset | channels |
| `channelsMissileerDrainReceiver` | (a) if a missileer drain image key is set | unset | channels |
| `makerTrustedPrincipals` | (b) | `[]` | identity |
| `checkerTrustedPrincipals` | (b) | `[]` | identity |
| `auditorTrustedPrincipals` | (b) | `[]` | identity |
| `promotionTrustedPrincipals` | (b) | `[]` | identity |
| `demotionTrustedPrincipals` | (b) | `[]` | identity |
| `githubOidcSubjects` | (c) | a sentinel nothing can match | identity |

Source of truth is the code: `infra/bin/safe-agents.ts`, `infra/lib/environment.ts`,
`infra/lib/image-pin.ts`, and the `tryGetContext` calls in
`infra/lib/{compute,channels,identity}-stack.ts`. If this table and the
code disagree, the code is right and this file is a bug.
