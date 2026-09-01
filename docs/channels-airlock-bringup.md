# Channels-airlock bringup runbook

Bringing the sa#152 channels airlock (`SafeAgents-Channels-{env}`) up from nothing: the two-phase
deploy, the consumer image layer, the secret seed, and the screened variant. Companion to
`channels/README.md` §"The deployed binding"; the broker analog is `docs/broker-service-bringup.md`.

All commands from the repo root unless noted. `us-east-1`, `development`.

> **Environment ownership.** This runbook targets `development`, an ephemeral floor. The same
> sequence works for a durable environment's first bringup, but a durable environment may be
> carrying a live consumer: never deploy over one without checking who depends on it
> (`docs/environments.md`).

## 0. Prereqs

- `SafeAgents-State-development` deployed (the airlock imports its exports: the `channel-dedupe`
  table, the tables CMK, the audit bucket + key). Network and Identity are NOT dependencies — the
  airlock Lambda runs outside the VPC and owns its execution role.
- podman, arm64-capable (the function is arm64).

## 1. Phase-1 deploy: substrate without the function

A `DockerImageFunction` cannot be created before its image exists (the Lambda-from-ECR analog of
the broker's `brokerDesiredCount=0` first deploy). The `channelsDeployFunction=false` context lays
down the ECR repo, the accepted-events queue, and the webhook secret, skipping role/function/API:

```
cd infra && npx cdk deploy SafeAgents-Channels-development \
  -c environment=development -c channelsDeployFunction=false --require-approval never
```

## 2. Build and push the consumer image

The base image is the handler + `safe_agents`; the consumer layer COPYs in the `ChannelsManifest`
(the entire per-consumer surface — the base image alone has an empty trust map and drops
everything). Using the honest example consumer:

```
ECR_URI=$(aws cloudformation list-exports \
  --query "Exports[?Name=='safe-agents-development-airlock-ecr-uri'].Value" --output text)
aws ecr get-login-password | podman login --username AWS --password-stdin "${ECR_URI%%/*}"

podman build --platform linux/arm64 \
  -f safe_agents/channels/airlock/Containerfile -t safe-agents-channels-airlock:dev .

podman build --platform linux/arm64 \
  --build-arg AIRLOCK_BASE_IMAGE=safe-agents-channels-airlock:dev \
  -t "$ECR_URI:latest" \
  -f examples/webhook_peer/Containerfile.airlock examples/webhook_peer

podman push "$ECR_URI:latest"
```

**Image-tag discipline (why it bites):** CloudFormation only updates the function when its
ImageUri *changes*. Re-pushing `:latest` with new content does NOT redeploy the code — push each
new image under a fresh tag and deploy with `-c channelsAirlockImageTag=<tag>`.

## 3. Seed the webhook secret

The stack creates the secret with a random placeholder; the real shared token is seeded out of
band (the raw string, not JSON — the handler reads `SecretString` verbatim):

```
SECRET_ARN=$(aws cloudformation list-exports \
  --query "Exports[?Name=='safe-agents-development-channels-webhook-secret-arn'].Value" --output text)
aws secretsmanager put-secret-value --secret-id "$SECRET_ARN" \
  --secret-string "$(openssl rand -hex 32)"
```

The peer that will POST to the airlock gets this token; it rides the manifest-configured header
(default `x-airlock-token`). The Lambda caches it per container — after rotating, force new
containers (any function-config update, or wait out the idle recycle).

## 4. Phase-2 deploy: the function and the API

```
cd infra && npx cdk deploy SafeAgents-Channels-development \
  -c environment=development \
  -c channelsManifestPath=/var/task/channels-manifest.yaml --require-approval never
```

`channelsManifestPath` mirrors the broker's `brokerManifestPath`: it points at the manifest INSIDE
the consumer image layer. Unset, the function runs the empty manifest and drops every sender —
safe, and a useful smoke of the base image alone.

## 5. Verify

```
AIRLOCK_LIVE_SMOKE=1 python -m pytest safe_agents/channels/tests/test_airlock_live.py -v
```

The opt-in live smoke resolves everything from the stack exports and drives the deployed endpoint
through the gate matrix (bad token / unmapped / expired / valid / replay), drains the accepted
queue, and runs the `ingest_chain` bridge both ways. Drop records land PII-safe in the audit
bucket under `channels/drops/`.

Since sa#166 the webhook-peer drain (`docs/channels-drain-bringup.md`) reads this same
`channel-accepted` queue, so this smoke also asserts the END-TO-END path: the airlock's
`channel_accepted` log AND the drain-side effect — one `inbound_observed` ledger object written by
`InboundLogReceiver`. If the drain isn't deployed and seeded yet, only the airlock half of the
assertion is meaningful — bring the drain up first (see that runbook, including its
`ledger-example` connector secret seed).

### 5a. Assert the deploy binding (#205 — run immediately after ANY channels deploy)

```
AIRLOCK_CONFIG_ASSERT=1 \
AIRLOCK_EXPECTED_MANIFEST=<the channelsManifestPath you deployed> \
AIRLOCK_EXPECTED_DRAIN_MANIFEST=<channelsDrainManifestPath, when the drain is deployed> \
AIRLOCK_EXPECTED_DRAIN_RECEIVER=<channelsDrainReceiver, when the drain is deployed> \
python -m pytest safe_agents/channels/tests/test_airlock_config_live.py -v
```

This is the mechanical check that the deployed function configuration matches what you
*intended* to deploy — the fix for deploy-time values (manifest path, drain receiver) being
improvised instead of asserted. It calls `lambda:GetFunctionConfiguration` on the airlock
(and the drain, when the `channels-drain-function-name` export exists) and asserts:

- `CHANNELS_MANIFEST` equals the **operator-declared** `AIRLOCK_EXPECTED_MANIFEST` — no
  default: an unset expectation REFUSES loudly (it never accepts whatever was deployed).
  Same doctrine for `CHANNELS_DRAIN_MANIFEST` / `CHANNELS_DRAIN_RECEIVER` via the
  `AIRLOCK_EXPECTED_DRAIN_*` vars whenever the drain is deployed.
- A **deliberately-manifestless** deploy (no `channelsManifestPath` context — the stack omits
  `CHANNELS_MANIFEST` entirely and the empty manifest drops everything) is declared with the
  literal sentinel value `@absent` (e.g. `AIRLOCK_EXPECTED_MANIFEST=@absent`); the check then
  asserts the env var is genuinely **absent** from the function config — a present var (even
  empty) fails. The same sentinel works for the `AIRLOCK_EXPECTED_DRAIN_*` vars. Absence must
  be named: leaving the expectation unset still refuses, it never infers absence.
- The mechanical bindings (`CHANNELS_ACCEPTED_QUEUE_URL`, `CHANNELS_DEDUPE_TABLE`,
  `CHANNELS_WEBHOOK_SECRET_ARN`) equal the corresponding CloudFormation exports, so the
  function env cannot drift from the stack wiring.

Failures report each key's actual-vs-expected. `AIRLOCK_ENV` selects the environment
(default `development`), same as the smoke.

## 6. Enabling the reference screen (optional; ships OFF)

Enabling the Bedrock classifier screen is config only — no base code changes:

1. **Consumer manifest** with a `screen:` block (see
   `examples/webhook_peer/channels-manifest-screened.yaml`, which also turns on the verdict sink —
   the observability valve for an enabled screen). Build the consumer layer with
   `--build-arg MANIFEST_FILE=channels-manifest-screened.yaml`, push under a NEW tag.
2. **Deploy-time grant.** The role carries no bedrock permission by default (an OFF control's
   authority must not sit in the role). Declare the ARNs the screen may invoke:

   ```
   npx cdk deploy SafeAgents-Channels-development -c environment=development \
     -c channelsManifestPath=/var/task/channels-manifest.yaml \
     -c channelsAirlockImageTag=<new tag> \
     -c channelsScreenModelArns=<profile-arn>,<foundation-model-arns...> --require-approval never
   ```

   **Why it bites:** a cross-region inference profile needs `bedrock:InvokeModel` on the profile
   ARN **plus** the foundation-model ARN in *every* region it may route to (e.g. us-east-1 /
   us-east-2 / us-west-2) — the profile alone throws AccessDenied on first route-away.

   **Model portability:** the screen forces its answer through Converse tool use
   (`toolChoice: {tool: ...}`), which not every Converse model family supports. A model without
   forced tool choice fails the call → the seam refuses `screen_error` — fail-closed, correct,
   and 100% of traffic drops. Verify the model supports forced tool choice before wiring it.
3. **Verify:** `AIRLOCK_LIVE_SMOKE_SCREENED=1 python -m pytest
   safe_agents/channels/tests/test_airlock_live_screened.py -v` — benign passes, injection-shaped
   refuses with the `injection_suspected` machine code, the verdict sink records every invocation,
   and a replay of a refused message never re-runs the screen.

## Operational boundaries (by design; know them)

- **200-always.** Drops are silent to the sender; a 5xx would make the provider retry, the retry
  would dedupe, and the record would strand. Consequence: misconfiguration (missing env var,
  Secrets Manager outage) is also silent to callers — the airlock answers 200 while dropping
  everything, visible only in the logs. The stack now ships the alarms for this (sa#153): metric
  filters on the `handler_error` (hard failure — the handler threw, the message dropped) and
  `screen_error` (the classifier screen failing closed — 100% drop when persistent)
  structured-log events, each alarming on first occurrence in a 5-minute window into the
  `safe-agents-{env}-channels-airlock-alerts` SNS topic. Subscribing that topic (email, a
  Telegram/Slack bridge, ...) is a per-environment ops step — an unsubscribed topic alarms into
  the void. **Still recommended and still manual:** a post-deploy canary request.
- **At-most-once at the handoff.** The dedupe key commits before the SQS send; if the send fails,
  the 200 has been earned, the replay dedupes, and the message is lost to the queue. This is the
  chosen polarity (never double-emit); the downstream drain must be idempotent regardless.
- **Concurrent duplicates.** Two simultaneous copies of one message can both pass the
  check-then-add dedupe window and both enqueue — same downstream-idempotency requirement.
