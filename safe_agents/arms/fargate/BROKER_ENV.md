# Broker env contract — AWS Fargate arm (sa#36)

The broker image is **identical** on the local/Mac arm and on AWS Fargate. Which
backends are live is decided purely by environment variables read in
`broker/prototype/broker_server.py::build_runtime()`. There are three independent
switches — **stores**, **audit**, **secrets** — each defaulting to an AWS-free
in-memory/local backend, so an unset env runs the safe local path.

This file is the contract the Fargate **task definition** must satisfy for AWS mode.
Phases B/C (task def + deploy) build against it.

## Required environment for AWS mode

| Var | Value (example) | Meaning |
|---|---|---|
| `BROKER_STORE` | `dynamo` | Selects the real DynamoDB stores. CLOSED set: `memory` (default) \| `dynamo` \| `sqlite` (the durable local arm — see below); an unrecognized value refuses at boot. Same code as the local arm; with `AWS_ENDPOINT_URL_DYNAMODB` unset, boto3 talks to the real service. |
| `BROKER_GRANTS_TABLE` | `safe-agents-grants` | DynamoDB table for the grant store (`DynamoDBGrantStore`). |
| `BROKER_COUNTERS_TABLE` | `safe-agents-counters` | DynamoDB table for `DynamoStore` (counters + idempotency + ledger). |
| `BROKER_INTENTS_TABLE` | `safe-agents-intents` | DynamoDB table for the approval/intent store (`DynamoIntentStore`). |
| `BROKER_AUDIT_BUCKET` | `safe-agents-audit-prod` | S3 bucket for the WORM audit tape; selects `S3ObjectLockSink`. Object Lock is **GOVERNANCE** mode with a ~7y default retention in durable environments and **no default retention on `development`** — so WORM is a durable-env property, and an admin with `s3:BypassGovernanceRetention` can still delete. See `broker/audit/_s3_sink.py`. |
| `BROKER_AUDIT_PREFIX` | `audit/` | Key prefix for audit objects. Optional; defaults to `audit/`. |
| `BROKER_SECRETS` | `secretsmanager` | Selects AWS Secrets Manager (`LazyBotoSecretsProvider`) as the credential backend. CLOSED set since #248: `secretsmanager` \| `dir` (one file per secret leaf under `BROKER_SECRETS_DIR` — the container arm) \| `file` (0600 JSON blob at `BROKER_SECRETS_FILE`) \| `fake`; an unrecognized value **refuses at boot** rather than falling through to the file provider or to fake credentials. Unset keeps the pre-#248 implicit resolution — the path variable selects the arm. |
| `BROKER_SECRETS_DIR` | _(unset on AWS)_ | Mount root for the `dir` arm: one file per secret leaf, the shape a Kubernetes/OpenShift `Secret`, a CSI Secrets Store volume, Podman `/run/secrets` and systemd credentials all project. Read-through (never cached) so a rotated projection is seen; one trailing newline is stripped. Ignores `BROKER_SECRET_PREFIX` — the mount root plays the prefix's role. |
| `BROKER_SECRET_PREFIX` | `safe-agents` | Optional. Maps a bare connector name to its secret id: `github` → `<prefix>/connectors/github`, matching the brokerRole IAM grant on `*/connectors/*`. Omit only if secret ids are stored flat (bare connector name). |
| `BROKER_HMAC_KEY` | _(from Secrets Manager)_ | Key for grant tamper-evidence. MUST be injected from Secrets Manager via the task definition's `secrets:` block — never a literal in the env. The same key must write and read grants. |
| `BROKER_GRANT_LOAD` | `read` | Grant-load mode: `seed` (default; local arm — writes then reads each grant) \| `read` (AWS brokerRole — READ-ONLY, reads pre-seeded grants) \| `skip` (load nothing, empty registry — construction smoke). **AWS uses `read`.** `BROKER_SKIP_GRANT_LOAD=1` remains a back-compat alias for `skip`. |
| `BROKER_HOST` | `0.0.0.0` | Bind address so the tool-call API is reachable inside the task's network namespace. |
| `AWS_DEFAULT_REGION` | `us-east-1` | Region for the boto3 Secrets Manager / DynamoDB / S3 clients. |

`BROKER_PORT` (default `8080`) is optional. Per-store table vars fall back to a single
`BROKER_TABLE` if set — AWS mode should set the three explicitly.

## How a secret name resolves

The Doer fetches a connector's credential by the **tool name** (e.g. `github`). On AWS:

```
"github"  --_PrefixedSecrets-->  "<BROKER_SECRET_PREFIX>/connectors/github"
          --LazyBotoSecretsProvider-->  GetSecretValue(SecretId=that)
```

`LazyBotoSecretsProvider.fetch_secret(name)` passes `name` straight to
`GetSecretValue(SecretId=name)` — it does **no** prefixing itself, so the secret id
must either be the full id (use `BROKER_SECRET_PREFIX`) or the bare connector name.
The calendar/payments/crm StubConnectors fall back to throwaway dev values (they ignore
their credential), so only `github` need exist in Secrets Manager.

## What touches AWS at build / startup

Backends are lazily wired — constructing the runtime does **not** call AWS — with one
exception: grant loading (`_load_grants`), which in `dynamo` mode hits the **grant table**.
What it does there is set by `BROKER_GRANT_LOAD`:

- **`seed`** (local arm) — *writes* then reads each granted action class. brokerRole
  cannot do this on AWS: it has grant **read only** (grant writes are `promotionRole`'s
  job — maker-checker), so a `brokerRole` run in `seed` mode would crash loudly at
  `put_grant` (AccessDenied) during startup.
- **`read`** (AWS, the configured mode) — *reads only*. The grants must already be in the
  table, seeded **out-of-band** by `python -m safe_agents.broker.prototype.seed_grants` run with
  credentials that can write the grants table (admin or the promotion path — **not**
  brokerRole), using the **same** `BROKER_HMAC_KEY` the broker reads with (otherwise every
  grant quarantines on read). A class whose grant is absent or quarantined is omitted with
  a loud WARNING and the PIP denies it (fail-closed). **Seed first, then start the broker.**
- **`skip`** — seeds/reads nothing (registry empty → the PIP denies everything,
  fail-closed). For proving AWS-mode wiring constructs/boots without touching the grant
  table (CI smoke / a reachability check); never set on a real serving run.
  `BROKER_SKIP_GRANT_LOAD=1` is a back-compat alias for this mode.

Also: on a DURABLE arm (`BROKER_STORE=dynamo` or `sqlite`), leaving `BROKER_AUDIT_*` and
`BROKER_SECRETS` unset would yield an in-memory audit sink + fake credentials (a real
store that loses its tape on restart and serves a fake connector credential). Since #205
this **REFUSES at boot** (F3, `boot_config.require_named_real_backends`) — it was a
warn-and-continue before. The task definition must set all three backends together.

`BROKER_STORE=sqlite` is the durable LOCAL arm (the product wrapper's Phase 1) — one named `broker.db`
(`BROKER_SQLITE_PATH`, named-or-refuse) behind the same store contracts, for a Mac with
no AWS account. It is durable, so it takes the SAME F1–F3 named-config refusals as
`dynamo`; additionally `BROKER_GRANT_LOAD=seed` **refuses** on it (F5), because
seed-at-boot blind-upserts grants into a durable trust store and sqlite has no IAM
backstop confining that to a throwaway local table the way `brokerRole`'s read-only
grants policy does on AWS.

S3 audit resume IS implemented (sa#104): `S3ObjectLockSink.resuming()` reads the max
existing `audit/*.json` key + its record hash at startup, so a restarted long-lived
broker continues the same contiguous `verify_chain`-valid tape instead of resetting
`seq=0` and colliding with existing objects under Object Lock.
