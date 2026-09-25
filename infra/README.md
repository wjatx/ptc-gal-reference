# infra — shared platform substrate IaC

> **Status: foundation deployed to `development` (sa#11 · #12–#17).** The layered CDK app (#12),
> NetworkStack (#13), StateStack (#14), and IdentityStack (#15) are implemented; the conformance
> test-table (#16, `npm test`) asserts the `ARCHITECTURE.md` invariants against synthesized
> CloudFormation — 15 checks, green. All three stacks are **live in `development`**
> (the account and region CDK resolves from your environment); 22 cross-stack exports + SSM params resolve and the
> deployed invariants verify (agent role holds zero policies, tables ACTIVE with PITR, audit bucket
> Object Lock enabled). Epic: **sa#11** (Platform foundation). Decisions (2026-06-28): **AWS CDK
> (TypeScript)** for the foundation; **multi-stack, same account** now (multi-account for
> production = future hardening); **defense-in-depth egress** (subnet routing + security group +
> netns). Note: keep all resource description fields ASCII-only — EC2 (SecurityGroup) and IAM
> (Role) reject non-ASCII at create time; the conformance gate enforces this.

The platform depends on shared external state that must survive any ephemeral compute arm going
away and that must be provisioned before any agent or broker can run. This directory owns the IaC
for that substrate. Component-specific stacks (the airlock Lambda, a per-agent runner) may live
with their component; this owns the cross-cutting shared pieces.

## What lives here

**Durable state tables (DynamoDB).** Three tables the broker and grant lifecycle depend on:

- `grants` — the per-principal grant records, including level (`in-loop` / `on-loop` /
  `out-of-loop`), envelope, promotion chain, demotion triggers, and named owners. Writable only
  by the maker-checker promotion path; the agent IAM role has no write permission here.
- `counters` — atomic error/attention/escalation/fallback budgets per principal per period. Used
  by the PIP at decision time; cap breaches trigger `deny` or escalation.
- `intents` — durable `Intent` records for the `require_approval` path. Stored here so they
  survive the broker process restarting and can be acted on by the human through a separate
  authenticated path.

All three tables are **on-demand billing** and **point-in-time recovery enabled**. They live
outside every compute arm by design.

Plus the `agent-runs` run-record table (RUNNER-CONTRACT element 5 — liveness/observability),
re-derived from the proven pattern in a consumer agent (the one store that already exists in a
reference implementation). `observability/` consumes it.

**The Object Lock audit bucket (S3).** Write-once storage for broker-emitted `AuditRecord`s (see
`audit/`). The bucket policy enforces Object Lock in WORM mode; the writing IAM role can
`PutObject` only. No agent or broker process holds a role that can delete or overwrite objects.

**The broker secret store (Secrets Manager).** Invariant #1 made real: **all connector credentials
live here, per-agent scoped** (e.g. `<agent>/connectors/*`). The **broker role is the only reader**;
the **agent role has zero Secrets Manager access**. This is where "the broker holds the creds, the
agent holds nothing" physically lives — without it the invariant has no home.

**The separate IAM identities (invariant #3 made concrete).** infra/ defines the four boundary
roles so a compromised agent inherits nothing:

- **agent role** — no connector creds, no Secrets Manager, **no write to the `grants` table**,
  egress only to the broker. The dumbest role in the chain.
- **broker role** — reads the secret store, reads `grants`, reads/writes `counters` + `intents`,
  `PutObject`-only to the audit bucket. Holds the keys; cannot promote itself.
- **promotion role** — writes the `grants` table via the maker-checker path, and reads the
  `*/issuer/*` signing key to sign the records that RAISE authority.
- **demotion role** — deterministic grant writes on triggers, no model in the loop, and reads the
  `*/evaluator/*` signing key to sign the records that LOWER it (`demotion`, `lapse`). The two
  key namespaces are disjoint, so neither signing identity can mint the other's record type.
- (woken-EC2 arm) **waking-Lambda role** — `StartInstances` + scoped; carries no connector creds.

**KMS** — customer-managed keys encrypting the tables, the audit bucket, and the secret store.

**Network substrate (defense in depth).** The VPC, subnets, and security-group rules that enforce
"agent egress = broker only" at the network layer — invariant #2 from `ARCHITECTURE.md` made
topological, not a code-level guard the agent could bypass. **Three independent layers**, so a
misconfig in one does not open direct egress:

1. **Subnet routing** — the agent runs in a private subnet whose route table has **no path to a
   NAT/IGW** except to the broker's ENI/endpoint; the broker sits in a subnet with NAT egress to
   connectors.
2. **Security groups** — the agent SG permits egress **only to the broker SG**; the broker SG
   egress reaches the connector hosts.
3. **netns** (on EC2 arms) — the agent process runs in a network namespace whose only route is the
   broker, isolating it even from other processes on the same host.

infra/ provides these primitives; `core/`'s arm adapters wire the agent into them (EC2 netns +
subnet/SG; Fargate awsvpc per-container task networking + SG).

The full topology (three subnet tiers, one NAT gateway, ten interface endpoints, the three-SG egress
shape) is **flag-gated behind `secureNetwork` and ships OFF** (default). Open mode keeps the security
groups and their default-deny ingress but drops the NAT/endpoints/isolation and gives tasks public IPs
— trading network-layer outbound containment for ~$4/mo vs ~$375/mo, warranted while this platform is a
low-risk experiment floor. Both modes publish the same six outputs plus a `network-mode` value.
`secureNetwork: true` restores the proven topology for a high-risk consumer. The design, cost, hard-won
lessons (the sa#83 prefix-list bug, the SG dependency-cycle workaround, `open: false`), and re-enable
steps live in `docs/network-security-layer.md`.

**Environment naming.** Stacks use exactly `development` / `staging` / `production`. Never `dev`,
`prod`, or `stage`. CloudFormation exports, stack names, and cross-stack `ImportValue` calls
interpolate `${Environment}`; a single character difference in the name breaks cross-stack
references silently.

**Environment ownership.** `development` is the platform team's ephemeral iteration floor —
torn down and rebuilt freely. `staging`/`production` are durable (`RemovalPolicy.RETAIN`) and
`production` is claimed by a real consumer agent; coordinate before deploying to or
destroying anything there. The binding rules live in `docs/environments.md` (sa#111).

## Planned architecture — layered CDK foundation, per environment

A **CDK (TypeScript)** app, **layered into three foundation stacks** (not one mega-stack) so blast
radius is bounded — the VPC rarely changes, a table often does:

```
per environment { development | staging | production }   (same AWS account for now)
  NetworkStack    — VPC · subnets · route tables · SGs · NAT          (rarely changes)
  StateStack      — grants · counters · intents · agent-runs · channel-dedupe (DynamoDB)
                    · audit bucket (S3 Object Lock) · deploy bucket (S3, agent + platform bundles)
                    · KMS keys
  IdentityStack   — the 4 IAM roles · the Secrets Manager secret store
        │  CfnOutput / SSM-param exports
        ▼
  ChannelsStack   — the inbound airlock (sa#152): POST /inbound HTTP API · airlock Lambda (outside
                    the VPC) · accepted-event SQS queue · webhook secret · its own execution role
  broker / arm stacks             ──import──►  the foundation above
```

CDK is the sanctioned choice for complex stacks (the substrate is VPC + tables + IAM + secrets +
multi-env, which clears that bar). Component stacks (the broker Lambda, the channels airlock) may
stay SAM or also adopt CDK — either way they consume the foundation's CloudFormation exports.

**Deploy order (the dependency floor).** NetworkStack → StateStack → IdentityStack → the component
stacks → agent hosts. A fresh environment deploys infra/ first; `tests/` conformance gates on the
foundation being present before anything else runs.

**Multi-account is the future hardening step:** production eventually moves to its own AWS account
(hard isolation of prod state/audit/secrets) — deferred now (account setup + cross-account roles +
SCPs), but the stacks are parameterized by `Environment` so the split is additive.

## Environment promotion

The platform runs three stacks of the substrate (development → staging → production). Promoting
to the next tier is a deployment ceremony, not a rename: the staging stack gets a fresh deployment
and the integration tests (`tests/`) run against it before any production traffic is routed.

## Using the CDK app

The app lives here as an npm project (`package.json`, `cdk.json`, `bin/`, `lib/`). Every command
takes the target environment as **context**, validated against `development` / `staging` /
`production` — a missing or misspelled value (`dev`) fails fast with an actionable error.

> **`docs/cdk-context-contract.md` is the reference for all 25 context values.** `environment` is
> the only one that stops you on every deploy; eight more hard-fail under a condition, four take
> harmless defaults, and **twelve degrade silently** — a deploy that omits `channelsVerifyKeysArn`
> comes up green with peer signature verification off. One that omits `brokerManifestPath` fails
> later: the broker refuses to boot and the circuit breaker rolls the service back.
> Read it before a first deploy. This README documents two of the twenty-five.

```bash
cd infra
npm install                                   # one-time / on dependency change
npx cdk list   -c environment=development     # the three foundation stacks
npx cdk synth  -c environment=development      # synthesize CloudFormation (no AWS creds needed)
npm test                                       # conformance gate (#16) — asserts invariants on synth
npx cdk deploy -c environment=development --all   # deploy (needs credentials; see bootstrap below)
npm run build                                  # tsc type-check
```

The conformance gate (`npm test`) is the deterministic exit predicate for the foundation: it
instantiates the stacks in process and asserts the `ARCHITECTURE.md` pre-deployment checklist
against synthesized CloudFormation (egress confinement, durable/WORM state, the four IAM role
boundaries). Run it before every deploy; it needs no AWS credentials.

**Bootstrap (once per account × region, before the first deploy of any environment).** CDK needs
its toolkit stack present in each account/region it deploys into. Because all environments share one
account for now, a single bootstrap covers `development` / `staging` / `production`; the multi-account
production split (future hardening) will need its own bootstrap in the new account.

```bash
# Bootstrap runs the app, so it needs the environment context like every other command:
npx cdk bootstrap aws://<account-id>/<region> -c environment=development
```

The `development` environment is bootstrapped and deployed in whichever account and region
`CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION` resolve to (`infra/bin/safe-agents.ts`). Nothing in
the stacks pins an account; confirm yours with `aws sts get-caller-identity`.

**Cross-stack wiring.** Producing stacks call `publish(scope, env, key, value)` (`lib/naming.ts`),
which emits both a CloudFormation export and an SSM parameter at deterministic names derived from
`(environment, key)`. Consumers call `importValue(env, key)` (CFN) or `importFromSsm(...)` (SSM) —
producer and consumer agree on a `key`, never a literal string. The deploy order is
Network → State → Identity; only Identity has a hard dependency (it scopes role policies to State's
ARNs), so Network and State are parallelizable.

## What does NOT live here

Per-agent stacks (a specific runner's EC2 ASG, a specific Lambda's SAM template) belong with the
agent's own repo or in `core/`. This directory is the shared substrate those stacks depend on via
CloudFormation `ImportValue`.

## Relationships

- `broker/` — reads grant table, counters, intents. Writes audit records to the S3 bucket.
- `audit/` — the Object Lock bucket is provisioned here; `audit/` owns the reader/loop logic.
- `channels/` — the deduplication DynamoDB table (StateStack) and the inbound airlock stack
  (ChannelsStack: HTTP API + Lambda + accepted-event queue) are provisioned here; `channels/`
  owns the contracts and the airlock handler code the stack runs.
- `core/arms.md` — arm adapters reference the shared security groups and subnet outputs from
  this stack.
- `tests/` — conformance checks verify the pre-deployment checklist against infrastructure
  deployed from this dir.
