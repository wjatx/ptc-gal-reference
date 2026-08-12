# Environment ownership — who may touch what, and when

> **Status: binding convention (sa#111).** The mechanism below is already encoded in
> `infra/lib/environment.ts`; this document makes the *ownership* rules explicit so nobody
> discovers them by tearing down someone else's floor.

## The mechanism (already in code)

Environments are exactly `development` / `staging` / `production` (a closed enum — see
`infra/lib/environment.ts`). The code draws one durability distinction:

- **`development` is ephemeral** (`isEphemeral() === true`): stateful resources get
  `RemovalPolicy.DESTROY`, and the whole floor is torn down and redeployed hands-off, often
  several times a day.
- **`staging` / `production` are durable**: stateful resources get `RemovalPolicy.RETAIN` —
  grants, budgets, held intents, run history, and the audit chain survive a stack teardown.

## The ownership rule (what this document adds)

**`development` belongs to the platform team; `production` belongs to consumers.**

- **`development` is the platform's iteration floor.** Platform development, arm bringups,
  G-gate-style live proofs, and teardown/rebuild cycles all happen here, without coordination.
  Nothing anyone else depends on may live in `development` — observed reality is multiple
  `SafeAgents-Compute-development` delete cycles in a single morning.
- **`production` is real consumers' durable infrastructure.** As of 2026-07-01 it is claimed by
  **a live consumer agent**, the first real SDK consumer (`docs/consuming-the-sdk.md`), which stands up
  its own floor under `-c environment=production` precisely because it needs a lifecycle *it*
  controls. `SafeAgents-*-production` stacks are **never** free real estate: do not `cdk destroy`,
  redeploy, or "quickly test against" them the way you would `development`. If platform work ever
  genuinely needs a durable-environment live proof (e.g. `RETAIN`-specific behavior), coordinate
  with the consumer first.
- **`staging` is the promotion tier** (see `infra/README.md` §Environment promotion) and follows
  the durable rules: coordinate before touching.

The rule survives even though all three environments currently share one AWS account and region
(`aws sts get-caller-identity` if you need to confirm which). The eventual multi-account split
hardens this boundary with IAM;
until then it is held by convention — which is exactly why it must be written down.

## Open question — a second consumer

The `Environment` type is a closed three-value enum, not parameterized per consumer. One consumer
in `production` works today because there is exactly one. When a second real consumer adopts the
SDK, it needs its own identity — either a per-agent resource-naming convention inside
`production`/`staging`, or per-consumer environments/accounts. Decide *then*, but know the enum is
the constraint (tracked in sa#111's discussion; related: the consumer still resolves the platform's
`/safe-agents/{environment}/...` SSM paths, so "its own floor" is currently the same CDK app).

## Checklist before any live platform run

1. Target `development`, always, unless a consumer has explicitly agreed otherwise.
2. Before a teardown, confirm no parallel session or consumer run is in flight in that
   environment (shared-account hazard).
3. Never assume "currently up" means "will still be up in an hour" — `development` offers no
   such guarantee, by design.
