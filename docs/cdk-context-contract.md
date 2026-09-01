# CDK context contract — every value a deploy can be given, and what happens without it

`infra/` takes all of its deploy-time configuration from CDK context, passed as `-c key=value` at
synth or deploy. There are **25 keys**. `infra/cdk.json` supplies a value for none of them (its
`context` block holds two CDK feature flags), so every deploy either passes a key explicitly or
gets the code's default.

This document is the reference for which ones you must pass. `docs/operator-identities.md` is the
operator runbook for the five ceremony gates and goes deeper on those; this is the complete list.

## Read this part first: three failure modes, and only one of them is loud

The reason this document exists is that "required" is the wrong axis. Almost nothing here is
required in the sense of stopping you. Sort by what a missing value *does*:

| Mode | What you see | How many |
|---|---|---|
| **(a) Hard fail** | synth or deploy stops with an error naming the key | 6 |
| **(b) Silent degradation** | deploy succeeds, and a resource, a gate or a control is quietly absent | 13 |
| **(c) Harmless default** | deploy succeeds with a documented, intended default | 6 |

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

The other five mode-(a) keys are **conditionally** required, and each is required only because
another key was supplied:

- `channelsDrainManifestPath` and `channelsDrainReceiver` are required if and only if
  `channelsDrainImageTag` is set. Synth throws naming all three.
- `channelsMissileerDrainManifestPath` and `channelsMissileerDrainReceiver` stand in the same
  relation to `channelsMissileerDrainImageTag`.
- Setting either drain image tag while `channelsDeployFunction=false` throws rather than deploying
  no drain, because the drain construct lives past that flag's early return.

> `channelsMissileerDrainManifestPath` is read through a line-wrapped `tryGetContext(` call, so the
> obvious one-line grep for context keys does not find it. It was missing from every inventory of
> this surface until 2026-08-10. If you are enumerating these keys with a regex, match across
> newlines.

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

**`brokerManifestPath`** sets `BROKER_MANIFEST`. Omitted, the broker falls back to its checked-in
**example** manifest. Fine for a smoke bringup, never right for a durable environment: you get a
healthy, running broker configured for the wrong principal with the wrong connectors.

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

`channelsDrainImageTag` and `channelsMissileerDrainImageTag` are their own gates: unset, the
corresponding drain Lambda, role, log group and event source are not created, while the ECR repo is
created unconditionally so you can push an image before first supplying the tag.

`channelsManifestPath` omitted yields a deliberately manifestless airlock, which is a supported
state rather than a broken one.

**`channelsAirlockImageTag` defaults to `latest`, and this is a live-regression trap.** A redeploy
that does not pass it silently repoints the airlock Lambda at `latest`, reverting whatever tag is
actually running. Recover the live tag before any channels deploy.

## Redeploy traps — mode (a), but only on the second deploy

`reuseComputeArtifacts` and `reuseChannelsArtifacts` both default to false, which is correct on a
first deploy into a clean account: CDK creates the ECR repositories and log groups. In a durable
environment those resources are `RETAIN`, so they survive a stack deletion, and a subsequent
re-create collides on their fixed names and **fails at deploy time**, not at synth. Pass them as
true when redeploying a stack whose retained artifacts still exist.

Both were documented nowhere in this repository before this file.

`brokerDesiredCount` defaults to `1`. On a first bringup, before the broker image and HMAC secret
exist, one task can never reach steady state and the deployment circuit breaker rolls the rollout
back. Deploy at `0`, push the image, then scale — see `docs/broker-service-bringup.md`.

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
| `brokerManifestPath` | (b) | example manifest | compute |
| `capabilityRoles` | (b) | `[]` | compute |
| `reuseComputeArtifacts` | (a) on redeploy | `false` | compute |
| `reuseChannelsArtifacts` | (a) on redeploy | `false` | channels |
| `channelsDeployFunction` | (c) | **`true`** | channels |
| `channelsAirlockImageTag` | (b) | `latest` | channels |
| `channelsManifestPath` | (b) | unset | channels |
| `channelsScreenModelArns` | (b) | `[]` | channels |
| `channelsVerifyKeysArn` | (b) | unset | channels |
| `channelsDrainImageTag` | (b) | unset | channels |
| `channelsDrainManifestPath` | (a) if tag set | unset | channels |
| `channelsDrainReceiver` | (a) if tag set | unset | channels |
| `channelsMissileerDrainImageTag` | (b) | unset | channels |
| `channelsMissileerDrainManifestPath` | (a) if tag set | unset | channels |
| `channelsMissileerDrainReceiver` | (a) if tag set | unset | channels |
| `makerTrustedPrincipals` | (b) | `[]` | identity |
| `checkerTrustedPrincipals` | (b) | `[]` | identity |
| `auditorTrustedPrincipals` | (b) | `[]` | identity |
| `promotionTrustedPrincipals` | (b) | `[]` | identity |
| `demotionTrustedPrincipals` | (b) | `[]` | identity |
| `githubOidcSubjects` | (c) | a sentinel nothing can match | identity |

Source of truth is the code: `infra/bin/safe-agents.ts`, `infra/lib/environment.ts`, and the
`tryGetContext` calls in `infra/lib/{compute,channels,identity}-stack.ts`. If this table and the
code disagree, the code is right and this file is a bug.
