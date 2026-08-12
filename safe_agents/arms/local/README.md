# Local / Mac arm (sa#39) — confined agent + broker box + DynamoDB Local

A working prototype of the **local/edge arm** in the **#98 separate-broker topology**, realized
locally as Podman containers on a private network, with the broker backed by **DynamoDB Local**
(the same `DynamoStore` code that runs on AWS):

```
  dynamodb-local           — DynamoDB Local: the broker's store backend (real conditional writes)
  broker box  (sa-broker)  — container: :8443 model-proxy + :8080 tool-call API; stores -> DynamoDB
  agent box   (the agent)  — container: CONFINED, only egress is the broker box; runs claude -p
```

> Running the broker against **DynamoDB Local** (`STORE=dynamo`, the default) immediately caught
> two real bugs in the prod `DynamoStore` that the in-memory tests could never exercise — arithmetic
> (`+`) and `if_not_exists` in a `ConditionExpression`, both forbidden by DynamoDB. That is the
> portability payoff: the local arm runs the exact code that ships, so the atomic counter + the
> idempotency dedup are genuinely tested. `STORE=memory` falls back to in-process fakes.

This validates three things at once:
- **The local arm's confinement (#39).** A container is a netns + fs/pid isolation, so it is the
  local equivalent of the RHEL/EC2 `agent-ns`. The agent container blackholes its default route
  and keeps only a route to the broker — a clean network boundary (no `host.containers.internal`
  hack), the honest local mirror of "agent box can only reach the broker box."
- **The #98 separate-broker topology.** Two containers on a private network = two boxes. On AWS
  this becomes two EC2 instances with the `brokerRole`/`agentRole` split; here it's two containers
  in the podman VM. The broker image is the same shape the **Fargate arm (#36)** needs (broker
  sidecar container), so the artifact transfers.
- **Both broker surfaces.** The confined agent reaches the broker for **model inference** (`:8443`,
  CONNECT proxy) **and** **brokered tool calls** (`:8080`, the `BrokerRuntime`) — the agent asks,
  the broker decides + injects the credential + audits, and returns a result with **no credential**.

## Run it

```sh
safe_agents/arms/local/run-local.sh
```

(Builds both images if needed, fetches the oauth token, creates the private network, starts the
broker box, polls its `:8080` tool-call API until ready, runs the confined agent box, tears
everything down on exit.)

The broker's default grants are a consumer agent's (`alpaca.read` / `notify.send`), whose
credentials never exist on this host — so `run-local.sh` sets `BROKER_GRANT_CLASSES=github.whoami`,
granting exactly the one class whose credential the harness provisions (the Keychain GitHub
token). Every step is asserted and **the script exits non-zero** if any of: a confinement
assertion fails, a brokered-call outcome doesn't match, or `verify_chain` fails on the audit tape.

Expected output:

```
[local] broker box at 10.89.x.y  (:8443 model-proxy, :8080 tool-call API)
=== smoke-egress (container == local netns; broker=10.89.x.y) ===
PASS: connector unreachable
PASS: broker reachable
PASS: model unreachable direct
PASS: model reachable via broker proxy
smoke-egress: all assertions passed
=== real claude -p through the broker (:8443, as the unprivileged agent) ===
LOCAL_MAC_CONFINED_OK
PASS: claude answered through the broker proxy
=== brokered github.whoami (:8080, the REAL read-only connector) ===
--- call 1 (expect allow + login, executed fresh) ---
{"decision_kind": "allow", "result": {"login": "..."}, "idempotent": false, ...}
PASS: call 1 allowed
PASS: call 1 returned the real GitHub login
PASS: call 1 executed fresh (not a replay)
--- call 2, same idempotency_key (expect idempotent=true, no re-execute) ---
{"decision_kind": "allow", "result": {"login": "..."}, "idempotent": true, ...}
PASS: call 2 replayed idempotently
=== brokered alpaca.read (:8080, an UNGRANTED class — expect deny) ===
{"decision_kind": "deny", ..., "reason": "tool not granted to this principal"}
PASS: ungranted alpaca.read denied (fail-closed)
confine-and-run: ALL ASSERTIONS PASSED
...
  verify_chain: OK over 2 record(s) (decisions: ['allow', 'deny'])
[local] RESULT: OK — confinement, brokered-call outcomes, and the audit chain all verified
```

## Pieces

| File | Role |
|------|------|
| `Containerfile` | The **agent box** image: node + the Claude CLI + iproute2; the unprivileged `agent` user runs `claude`. |
| `Containerfile.broker` | The **broker box** image: python + the `broker` package + the model-proxy stub; serves both surfaces. |
| `broker-entrypoint.sh` | Broker box entrypoint: runs `:8443` model-proxy (bg) + `:8080` tool-call API (`broker.prototype.broker_server`). |
| `confine-and-run.sh` | Runs **inside** the agent box (`--cap-add NET_ADMIN`): blackhole default + a route to the broker only; then asserts smoke-egress, `claude -p`, an allowed + idempotently-replayed `github.whoami`, and a fail-closed deny on ungranted `alpaca.read`. Exits non-zero on any failure. |
| `run-local.sh` | Host orchestrator: builds, networks, starts the broker box (polls `:8080` readiness), runs the confined agent box, verifies the audit chain, cleans up. Exits non-zero if the agent's assertions or `verify_chain` fail. |

The model-proxy is `safe_agents/arms/ec2/bootstrap/scripts/model-proxy-stub.py` — it carries the
non-blocking-`sendall` tunnel fix from the EC2 capstone (without it `claude` resets through the
proxy). The tool-call API is the broker prototype (`broker/prototype/`) — plain JSON/HTTP for now.

## Confinement note

On a private podman network both containers share a subnet; the agent box drops its default route
**and** its broad subnet route, keeping only a `/32` to the broker box, then blackholes the default
— so its sole reachable peer is the broker. The smoke-egress assertions prove both layers: the
broker's proxy allowlist refuses non-model hosts (telegram/Datadog → 403) **and** the blackhole
blocks any direct route.

## Nothing artificial — what's real now

Every component that was a fake/stub is now a real implementation (verified end-to-end in the live
run; the brokered `github.whoami` returns the real GitHub login, confined agent never sees the token):

- **Stores → DynamoDB** (DynamoDB Local): `DynamoStore` / `DynamoIntentStore` / `DynamoDBGrantStore`
  — real grants (HMAC-signed), counters, idempotency, ledger; same code as AWS.
- **PIP → real**: reads grant presence/level from the grant store and the cap-budget fact from the
  real counter (no fixed `Facts`).
- **Secrets → real**: `LocalFileSecretsProvider` reads a 0600 file the host populates from the
  **macOS Keychain** (`security find-generic-password`); the broker box mounts it `:ro`.
- **Audit → real**: hash-chained `FileAuditSink` to a local file; `run-local.sh` runs `verify_chain`.
- **Connector → real**: `GitHubConnector` (`github.whoami` → `GET /user` with the broker-injected
  token); the agent gets only `{login}` and can't reach `api.github.com` directly.

## Deferred (remaining for #39 + #98)

- **launchd** schedule driver + local SQLite/JSONL run-record fallback (the agent's element-5
  run-record; documented not-tamper-evident gap until an off-device audit sync exists).
- **Audit-on-connector-failure** + thread-safe sink (see the filed broker-hardening follow-up) — a
  failed real connector call should emit `outcome="failed"` and return a clean deny, not a 500.
- The **two-box AWS deploy** (brokerRole/agentRole on separate EC2 boxes, real DynamoDB + an
  S3-Object-Lock audit sink) is the live G9 for #98 — this local arm is its high-fidelity reference.
