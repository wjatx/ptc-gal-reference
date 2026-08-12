# Consumer image contract — Fargate arm (sa#116)

This is the contract between the Fargate arm's **task definition** (registered by
`safe_agents/arms/fargate/provision.py::fargate_provision`) and **any consumer-built agent
image** that runs on it. Until now the smoke image
(`safe_agents/arms/fargate/Containerfile.agent` + `run.sh`) has been the only image, and its
runner doubled as the implicit contract; this document makes the contract explicit. The smoke
image remains the **reference implementation**; this document is **normative**.

A consumer image that satisfies every MUST below can be pushed to the environment's agent ECR
repo and run by `fargate_provision` / `fargate_run_once` unchanged — the platform never needs
to know what the agent does, only that it honors the contract.

## The injected env contract

The task definition sets exactly these plain env vars, plus one injected secret. The names are
**load-bearing** — `build_container_environment()` in `provision.py` and the image's entrypoint
are separately built halves of one contract; renaming either side breaks the pair.

| Var | Value | Meaning |
|---|---|---|
| `SA_BROKER_DNS` | `broker.safe-agents.local` (the `broker-service-dns` infra export) | Broker CloudMap DNS — the agent's only network peer. |
| `SA_MODEL_PROXY_PORT` | `8443` | Broker model-inference proxy port. |
| `SA_TOOL_API_PORT` | `8080` | Broker tool-call API port. |
| `AGENT_RUNS_TABLE` | `agent-runs-table-name` infra export | DynamoDB table for the run record. |
| `AGENT_NAME` | the agent's manifest name | Run-record partition key. |
| `RUN_ID` | `placeholder-overridden-per-run` in the task def; **overridden per run** | Run-record sort key. Each actual run (scheduled target or `fargate_run_once`) overrides it via `containerOverrides`; the sentinel makes an un-overridden run obvious in the audit. |
| `AWS_DEFAULT_REGION` | task region | Region for the in-container AWS SDK (the run-record write). |
| `CLAUDE_CODE_OAUTH_TOKEN` | **secret** — injected via the task-def `secrets:` block from `safe-agents/{env}/agents/{agent}/oauth-token` in Secrets Manager | Model token. Never appears as plain env in the task definition. |

A `RunTask` (`fargate_run_once(..., extra_env=...)`) may add per-run env via
`containerOverrides` — the smoke image defines `SA_SMOKE_TOOL` / `SA_SMOKE_OP` /
`SA_SMOKE_ARGS_JSON` / `SA_SMOKE_EXPECT` this way. A consumer image may define its own
override knobs; `RUN_ID` is owned by the run mechanism and cannot be overridden through
`extra_env`.

## Entrypoint obligations

Numbered and normative. The smoke runner (`run.sh`) implements every one; its header comment
labels them (a)–(f).

1. **Confinement env.** The entrypoint MUST export
   `HTTPS_PROXY=http://${SA_BROKER_DNS}:${SA_MODEL_PROXY_PORT}` (and `HTTP_PROXY` likewise),
   with `NO_PROXY=${SA_BROKER_DNS}` so the broker host itself — the tool API and any
   reachability probe of the proxy — is hit direct, not proxied through itself. The task runs
   in a PRIVATE_ISOLATED subnet: **confinement is by network topology, not by anything the
   image does**. The image MUST NOT attempt route surgery (no `iproute2`, no blackhole routes —
   contrast the local arm's `confine-and-run.sh`) and MUST NOT expect any egress other than the
   broker. There is no NAT and no internet route; anything else simply has no route.

2. **All model traffic through the proxy.** `claude -p` (or any model client) inherits
   `HTTPS_PROXY` and reaches `api.anthropic.com` only via the broker model-proxy allowlist.
   There is no direct path to the model API, and the image MUST NOT try to create one.

3. **All tool/connector calls through the broker tool API.** Every connector action is a
   `POST http://${SA_BROKER_DNS}:${SA_TOOL_API_PORT}/call` with body
   `{"tool": ..., "op": ..., "args": {...}, "idempotency_key": ...}`. The agent process holds
   **no connector credential, ever** — the broker injects the credential, calls the connector,
   audits, and returns a decision + result with no credential in it. A decision other than
   `allow`/`transform` is a hard stop for that call, not something to retry around: the broker
   said no (or wants approval), and hammering the same call is envelope probing, not resilience.

4. **AWS-service calls bypass the proxy.** DynamoDB (the run record) is reached directly via
   the VPC gateway endpoint, NOT through the broker. The entrypoint MUST strip the proxy env
   for AWS API calls — `env -u HTTPS_PROXY -u HTTP_PROXY aws dynamodb put-item ...` — or the
   SDK routes them to the broker model-proxy (whose allowlist is `api.anthropic.com` only) and
   fails with a proxy-connect error.

5. **Run record.** The entrypoint MUST write exactly one item to `AGENT_RUNS_TABLE` per run:

   | Attribute | Type | Value |
   |---|---|---|
   | `agentId` | S | `AGENT_NAME` (partition key) |
   | `runId` | S | `RUN_ID` (sort key) |
   | `status` | S | `ok` \| `fail` — plus consumer-defined values (e.g. `skipped-*`) if the run legitimately no-ops |
   | `arm` | S | `fargate` |
   | `ts` | S | ISO-8601 UTC (`date -u +%Y-%m-%dT%H:%M:%SZ`) |
   | `results` | S | short human-readable summary of what the run did |

   The write is **best-effort**: the run MUST NOT fail *because* the run-record write failed,
   but the failure MUST be logged loudly (the watcher and observability read these records —
   a silent drop hides a run).

6. **Exit semantics.** Exit `0` only on a verified-successful run; nonzero otherwise. The
   entrypoint MUST print a single machine-greppable final verdict line — the smoke image uses
   `FARGATE_CAPSTONE: PASS` / `FARGATE_CAPSTONE: FAIL`; a consumer picks its own stable token
   and keeps it stable (the deploy driver and log alarms grep for it).

7. **Logging.** stdout/stderr go to the awslogs driver (the task def sets `logDriver: awslogs`
   with a per-agent log group). The entrypoint SHOULD be wrapped in `stdbuf -oL -eL` for
   line-buffering: Fargate's awslogs driver can drop the final block-buffered flush when the
   container exits, leaving an empty log stream for a short run.

8. **Unprivileged user.** The image MUST run as a non-root user (`USER agent` in the smoke
   image). The agent holds no connector credentials and its confinement is topological — it
   never needs root, so it never gets it.

9. **Self-contained.** The image MUST bundle everything the run needs: agent code,
   prompts/strategy files, a pinned SDK if used. Nothing is fetched at runtime — the isolated
   subnet gives it no route to fetch anything over anyway. The EC2 arm's S3 code-bundle pull
   does not exist here.

## Image / packaging obligations

- **arm64.** The task definition registers `runtimePlatform` `ARM64`/`LINUX`, with
  cpu `256` / memory `512` by default. Build (or cross-build) the image for arm64.
- **Push target.** The environment's agent ECR repo (`ecr-agent-repo-uri` infra export); the
  task definition images **`:latest`** from that repo.
- **Known limitation (sa#116b).** The agent ECR repo is currently shared per environment — a
  second consumer pushing `:latest` clobbers the first. Per-agent tags/repos are an open
  question tracked in sa#116 / `docs/environments.md`; until it resolves, one consumer image
  per environment.

## Decoupling

A consumer image MUST NOT bake in platform-repo paths (no `COPY` from a safe-agents checkout,
no imports that assume the monorepo layout). If it uses the SDK, it consumes it as a
version-pinned package — see `docs/consuming-the-sdk.md`.

## Reference implementation

`safe_agents/arms/fargate/Containerfile.agent` + `run.sh` — the smoke capstone. Normative for
every obligation above, but it is a *smoke* image, not a template to copy wholesale: its
(b)/(c)/(d) steps (the four egress assertions, the token-echo `claude -p`, the parameterized
brokered read) are confinement *proofs*; a real consumer replaces them with its actual
workload while keeping the (a)/(e)/(f) frame — proxy env in, run record and verdict out. The
first real consumer implementation lands in a consumer agent's own repo.
