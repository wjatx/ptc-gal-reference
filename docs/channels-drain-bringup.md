# Channels-drain bringup runbook

Bringing the sa#155/sa#166 drain workers up on the deployed channels airlock: the drain ECR repo,
the two consumer drain images (base + a consumer layer that bakes an AgentManifest + Receiver), the
broker read-state seed (envelope → grants → **connector secrets**) for each, the tag-gated deploys,
and the live smokes. Companion to `docs/channels-airlock-bringup.md` (the inbound half) and
`channels/DRAIN.md` §"Reference binding"; the broker analog is `docs/broker-service-bringup.md`.

There are TWO drains, each with its own queue and its own audit-chain prefix (a
drain's S3 audit sink resumes a hash chain by prefix, and its Lambda is reservedConcurrency:1, so
two drains cannot share a queue or a prefix):

- **webhook-peer drain** (principal `example-agent`) reads the EXISTING `channel-accepted` queue
  that the airlock feeds — so the airlock→queue→drain→ledger path now closes END-TO-END for this
  consumer. This is the worked example below (`examples/webhook_peer/`).
- **missileer drain** (principal `missileer-watch`, the abstain-safe archetype) reads its OWN
  dedicated queue, `channel-accepted-missileer`, fed directly by its smoke (no airlock feeds it).
  See §"The missileer drain" for what differs.

All commands from the repo root unless noted. `us-east-1`, `development`.

> **Environment ownership.** This targets `development`, an ephemeral floor. A durable
> environment may be carrying a live consumer: never deploy over one without checking who depends
> on it (`docs/environments.md`).

## 0. Prereqs

- `SafeAgents-State-development` deployed (the drain imports its exports: grants/counters/intents
  tables, the audit bucket, the ledger bucket + its CMK, the broker-hmac-key secret).
- The `SafeAgents-Channels-development` stack deployed with the drain wiring (v0.12.0+). If the
  stack predates the drain wiring, its `channels-drain` ECR repo does not exist yet — the first
  `cdk deploy` below (no drain context) materializes it. Confirm with
  `aws ecr describe-repositories --repository-names safe-agents-development-channels-drain`.
- podman, arm64-capable (the function is arm64).

> **Airlock-preserving context (this bites).** The drain lives in the SAME stack as the airlock.
> `channelsAirlockImageTag` **defaults to `latest`** — a bare `cdk deploy` would revert the live
> screened airlock (which runs `screened-2`) to `latest` and strip its Bedrock screen grant. EVERY
> `cdk deploy` of this stack must re-pass the airlock's live context:
> `-c channelsAirlockImageTag=<live tag> -c channelsManifestPath=/var/task/channels-manifest.yaml
> -c channelsScreenModelArns=<the live screen ARNs>`. Recover the live tag from
> `aws lambda get-function --function-name safe-agents-development-airlock --query Code.ImageUri`
> and the screen ARNs from the airlock role's `bedrock:InvokeModel` statement. Always `cdk diff`
> first and confirm the ONLY airlock delta is none.

## 1. Ensure the drain ECR repo exists (phase 1)

The `DockerImageFunction` cannot be created before its image exists. The drain repo is created
unconditionally (even with `channelsDrainImageTag` unset), so a deploy WITHOUT drain context lays
down the repo while leaving the airlock and drain function untouched:

```
cd infra && npx cdk deploy SafeAgents-Channels-development \
  -c environment=development \
  -c channelsAirlockImageTag=screened-2 \
  -c channelsManifestPath=/var/task/channels-manifest.yaml \
  -c channelsScreenModelArns=<live screen ARNs, comma-separated> \
  --require-approval never --exclusively
```

## 2. Build and push the consumer drain image

The base image is the handler + `safe_agents` (`safe_agents/channels/drain/Containerfile`); the
consumer layer COPYs in the AgentManifest + Receiver package and sets the drain env contract. The
receiver is named by dotted path, so the consumer package must land at an importable path — hence
the **repo-root build context** for the consumer layer (unlike the airlock consumer's dir context).
This is shared across drains — build the base once, then layer each consumer on top:

```
ECR_URI=$(aws cloudformation list-exports \
  --query "Exports[?Name=='safe-agents-development-drain-ecr-uri'].Value" --output text)
aws ecr get-login-password | podman login --username AWS --password-stdin "${ECR_URI%%/*}"

podman build --platform linux/arm64 \
  -t safe-agents-channels-drain:dev \
  -f safe_agents/channels/drain/Containerfile .

TAG=drain-$(git rev-parse --short HEAD)-$(date +%Y%m%d%H%M)
podman build --platform linux/arm64 \
  --build-arg DRAIN_BASE_IMAGE=safe-agents-channels-drain:dev \
  -t "$ECR_URI:$TAG" \
  -f examples/webhook_peer/Containerfile.drain .

podman push "$ECR_URI:$TAG"
```

**Image-tag discipline:** CloudFormation only updates the function when its ImageUri *changes* —
push each new image under a fresh tag and deploy with `-c channelsDrainImageTag=<tag>`. (The
missileer drain image is built the same way from `examples/missileer/Containerfile.drain`, under
its own tag — see §"The missileer drain".)

## 3. Seed the consumer's broker read-state

The drain runs the production broker posture: `BROKER_ENVELOPE_LOAD=store`, `BROKER_GRANT_LOAD=read`
— it only READS its envelope/grants, never self-seeds. Seed order is **envelope → grants →
connector secrets** (grants stamp under the store envelope's hash, so the envelope must exist
first). Point `BROKER_MANIFEST` at the consumer manifest so the seed derives its principal +
classes:

```
export AWS_DEFAULT_REGION=us-east-1
export BROKER_GRANTS_TABLE=safe-agents-development-grants
export BROKER_MANIFEST=examples/webhook_peer/drain-manifest.yaml

# envelope (writes the ENVELOPE# item, keyed by principal)
BROKER_ENVELOPE_MANIFEST=examples/webhook_peer/drain-manifest.yaml \
  python -m safe_agents.broker.prototype.seed_envelope

# grants (stamped under the STORE envelope's hash; needs the real broker HMAC key)
BROKER_ENVELOPE_LOAD=store \
BROKER_HMAC_KEY=$(aws secretsmanager get-secret-value \
    --secret-id safe-agents/development/broker-hmac-key --query SecretString --output text) \
  python -m safe_agents.broker.prototype.seed_grants
```

Each drain seeds its OWN envelope/grants under its OWN principal — missileer needs the same two
commands run against `examples/missileer/manifest.yaml` (see §"The missileer drain").

### Connector secrets (the step that is easy to miss)

The Doer fetches a credential for **every** connector call — including connectors that need no
external credential. Each granted connector therefore needs a secret at
`safe-agents/development/connectors/<name>` (the drain role's IAM grant is scoped to `connectors/*`
under this env). webhook-peer's receiver only calls `ledger.append`, so only the `ledger` connector
secret is required for the smoke — and the base `LedgerConnector` reads its credential as the
destination JSON (`{"bucket": ..., "prefix": ...}`), so it is not a throwaway.

webhook-peer's drain manifest redirects `ledger` to its OWN Secrets Manager leaf via
`connector_secrets: {ledger: "ledger-example"}`, so it does not collide with missileer's shared
`connectors/ledger`:

```
aws secretsmanager create-secret \
  --name safe-agents/development/connectors/ledger-example \
  --secret-string '{"bucket":"safe-agents-development-ledger","prefix":"webhook-peer/"}'
```

webhook-peer's ledger records land at `webhook-peer/example-agent/deltas/evt-<digest>.jsonl`
(credential prefix `webhook-peer/` + agent segment `example-agent`); missileer keeps
`missileer/missileer-watch/deltas/...` under its own `connectors/ledger` secret (see §"The
missileer drain" for that seed).

(A consumer whose receiver also calls `notify.send` / `search.query` needs those connector secrets
too. `notify` is already seeded on the dev floor.)

## 4. Deploy the drain (phase 2)

```
cd infra && npx cdk deploy SafeAgents-Channels-development \
  -c environment=development \
  -c channelsAirlockImageTag=screened-2 \
  -c channelsManifestPath=/var/task/channels-manifest.yaml \
  -c channelsScreenModelArns=<live screen ARNs> \
  -c channelsDrainImageTag=$TAG \
  -c channelsDrainManifestPath=/var/task/examples/webhook_peer/drain-manifest.yaml \
  -c channelsDrainReceiver=examples.webhook_peer.inbound_log_receiver:InboundLogReceiver \
  --require-approval never --exclusively
```

Synth fails closed on incomplete drain context or `channelsDeployFunction=false` — by design.
Verify: event-source mapping `Enabled` (batchSize 1, `ReportBatchItemFailures`), reserved
concurrency 1, `BROKER_AUDIT_PREFIX=audit-drain/`, `BROKER_HMAC_KEY_SECRET_ARN` present (key fetched
at cold start, never in env), `BROKER_ENVELOPE_LOAD=store` / `BROKER_GRANT_LOAD=read`. Log group
`/safe-agents/development/channels-drain`.

To ALSO deploy the missileer drain in the same stack update, add its context params on the same
`cdk deploy` invocation — see §"The missileer drain" for the full command.

## 5. Verify (live smoke)

```
DRAIN_LIVE_SMOKE=1 python -m pytest safe_agents/channels/tests/test_drain_live.py -v
```

Since sa#166 this smoke targets the missileer drain: it injects directly onto
`channel-accepted-missileer` (missileer has no airlock feed) and reads the
`/channels-drain-missileer` log group. It asserts the happy path (ingest-before-act, one ledger
object, PII-safe), the D7 wrong-principal terminal drop, and D4 idempotency.

The webhook-peer drain's end-to-end path is proven instead through the airlock smoke:
`AIRLOCK_LIVE_SMOKE=1 python -m pytest safe_agents/channels/tests/test_airlock_live.py -v` POSTs to
the airlock and asserts both the airlock's `channel_accepted` log and the drain-side effect — one
`inbound_observed` ledger object written by `InboundLogReceiver`. Watch
`/safe-agents/development/channels-drain` during the first hit — the cold start loads the
envelope/grant store, fetches the HMAC key, and resumes the `audit-drain/` hash chain.

## The missileer drain

missileer (`examples/missileer/`, the abstain-safe archetype, principal `missileer-watch`) is not
reachable through the airlock — the airlock only stamps webhook-peer's principal `example-agent`.
It keeps its OWN queue, `channel-accepted-missileer` (CFN exports
`channel-accepted-missileer-queue-url` / `-arn`), fed directly by its smoke, via a parallel set of
context params:

```
TAG=drain-missileer-$(git rev-parse --short HEAD)-$(date +%Y%m%d%H%M)
podman build --platform linux/arm64 \
  --build-arg DRAIN_BASE_IMAGE=safe-agents-channels-drain:dev \
  -t "$ECR_URI:$TAG" \
  -f examples/missileer/Containerfile.drain .
podman push "$ECR_URI:$TAG"

export BROKER_MANIFEST=examples/missileer/manifest.yaml
BROKER_ENVELOPE_MANIFEST=examples/missileer/manifest.yaml \
  python -m safe_agents.broker.prototype.seed_envelope
BROKER_ENVELOPE_LOAD=store \
BROKER_HMAC_KEY=$(aws secretsmanager get-secret-value \
    --secret-id safe-agents/development/broker-hmac-key --query SecretString --output text) \
  python -m safe_agents.broker.prototype.seed_grants

aws secretsmanager create-secret \
  --name safe-agents/development/connectors/ledger \
  --secret-string '{"bucket":"safe-agents-development-ledger","prefix":"missileer/"}'

cd infra && npx cdk deploy SafeAgents-Channels-development \
  -c environment=development \
  -c channelsAirlockImageTag=screened-2 \
  -c channelsManifestPath=/var/task/channels-manifest.yaml \
  -c channelsScreenModelArns=<live screen ARNs> \
  -c channelsDrainImageTag=$TAG \
  -c channelsDrainManifestPath=/var/task/examples/webhook_peer/drain-manifest.yaml \
  -c channelsDrainReceiver=examples.webhook_peer.inbound_log_receiver:InboundLogReceiver \
  -c channelsMissileerDrainImageTag=$TAG \
  -c channelsMissileerDrainManifestPath=/var/task/examples/missileer/manifest.yaml \
  -c channelsMissileerDrainReceiver=examples.missileer.duty_log_receiver:DutyLogReceiver \
  --require-approval never --exclusively
```

Gated on `channelsMissileerDrainImageTag`: unset, neither the missileer queue nor its drain
function is created (phased, like the existing drain gate). Its log group is
`/safe-agents/development/channels-drain-missileer`, its audit prefix `audit-drain-missileer/` —
distinct from webhook-peer's `audit-drain/` so the two hash chains never interleave. missileer's
`search` connector maps via the manifest's `connector_secrets` to the leaf `track-feed-token`,
resolved as `safe-agents/development/connectors/track-feed-token` (sa#164).

## Operational boundaries (by design; know them)

- **Each consumer gets its own queue and its own audit prefix.** The airlock feeds webhook-peer's
  drain end-to-end through the shared `channel-accepted` queue (both stamp/expect principal
  `example-agent`), so the full POST→queue→drain→ledger path closes for that consumer
  (`test_airlock_live.py`). missileer keeps a dedicated queue, `channel-accepted-missileer`, fed
  directly by its own smoke (`test_drain_live.py`) — nothing in the base requires every drain to sit
  behind the airlock; a consumer with no inbound channel exposure is a legitimate shape.
- **Taint differs by receiver archetype.** webhook-peer's receiver is the PEER-AGENT INBOUND
  archetype: its `input_trust_map` trusts `peer:` / `channel:` prefixes, so an accepted peer
  envelope drains UNTAINTED. missileer trusts only `internal:` sources and every accepted envelope
  carries a `channel:webhook` stamp hop, so its `ingest_chain` always taints. Under abstain polarity
  `ledger.append` (an append-only observation) stays allowed regardless of taint — an effecting op
  would be *absent* from the served registry, not merely denied.
- **No DLQ (both queues).** Neither accepted queue has a dead-letter queue: TERMINAL failures
  (malformed, principal mismatch, expired) are logged `drain_terminal_drop` and dropped
  (redelivering a permanently-bad record would poison-loop for the retention period); only
  TRANSIENT failures (receiver/runtime error) are reported for redelivery. A transient failure heals
  on redelivery once its cause is fixed — e.g. a missing connector secret errors
  `drain_record_error` until the secret is seeded, then the redelivered message completes.
- **Reserved concurrency 1 (each drain, independently).** Exactly one runtime per drain resumes its
  own audit prefix's hash chain at a time; two concurrent resumers on the same prefix would fork it.
  This is also *why* the two drains cannot share a queue or a prefix: one queue feeding two
  concurrency-1 functions would still be two independent chains racing the same records. The
  tamper-evident chain links across invocations (`prevHash` of record N = `hash` of record N-1),
  verified live for both `audit-drain/` and `audit-drain-missileer/`.
