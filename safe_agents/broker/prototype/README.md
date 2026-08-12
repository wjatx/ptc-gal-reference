# Broker local-Mac prototype (sa#98)

A dependency-light, stdlib-only HTTP wrapper around the tested broker **library** so the
agent↔broker **tool-call round-trip** can be run and felt on a Mac — *before* committing to
the AWS deploy. The point is to settle the **protocol**, the request/response **marshaling**,
and the **PIP** shape, and to see what falls out, with no AWS in the way.

## Run it

From the repo root, with the SDK installed (`pip install -e .` — pulls pydantic):

```sh
# terminal 1 — the broker
python -m safe_agents.broker.prototype.broker_server

# terminal 2 — a fake confined agent driving the round-trip
python -m safe_agents.broker.prototype.fake_agent
```

(Override `BROKER_HOST`/`BROKER_PORT` on the server, `BROKER_URL` on the agent.)

## What you'll see (and what it proves)

- **Capability-scoped registry** — the agent can only *see* ops that are both in the static
  manifest **and** granted (registry = manifest ∩ grants); an ungranted op is *removed*, not
  merely refused.
- **allow** — `calendar.create_event` executes a stub connector with a broker-injected
  credential and returns the result. The credential never appears in the response.
- **idempotent replay** — the same `idempotency_key` returns the prior outcome without
  re-running the connector.
- **require_approval** — `payments.transfer` (external + irreversible) freezes an Intent and
  returns an `intent_id`; the connector is **not** executed.
- **deny** — an ungranted op is refused.
- **audit tape** — the broker appends a hash-chained record per turn (shown via a
  prototype-only `/audit` debug endpoint; production keeps the tape broker-private).

The agent surface carries `decision_kind / result / idempotent / intent_id / reason` — and
**never** a credential, a connector handle, or the audit sink. That confinement is the whole
point.

## Protocol (prototype) — the thing we're deciding

```
GET  /registry  -> [{"tool","op"}, ...]
POST /call      {"tool","op","args","idempotency_key"} -> {decision_kind,result,idempotent,intent_id,reason}
GET  /audit     -> [{"seq","decision","outcome"}, ...]   PROTOTYPE-ONLY debug view
```

Plain JSON-over-HTTP is used here because it's the simplest thing that makes the round-trip
real. The open question this prototype exists to answer: **does MCP/FastMCP (the house
standard) earn its weight over plain HTTP for this surface, or is HTTP enough?** Run it,
extend it, and let the friction decide.

## What is deliberately NOT here (deferred to the real build)

- **No model-inference proxy.** The `:8443` CONNECT proxy is already solved
  (`model-proxy-stub.py`, #97). This prototype is only the *tool-call* surface.
- **In-memory everything.** `InMemoryStore` / `InMemoryIntentStore` / `InMemorySink` /
  `FakeSecretsProvider` / `StubConnector` — no DynamoDB, S3, or Secrets Manager. The **real
  PIP** reads grant state, atomic counters, and budgets from DynamoDB; here it returns fixed
  `Facts`. Wiring those is the AWS step.
- **One process, no IAM split.** On AWS the broker runs on a **separate small EC2 box** under
  `brokerRole` (the agent box is `agentRole`) — that two-box split is the design decision on
  #98 (it dissolves the two-identities-on-one-box problem and lets the agent box be
  SG-confined again, since it no longer needs NAT). This prototype runs the broker in one
  local process to focus on the software unknowns.

## Next steps (the path on #98)

1. **(here)** local prototype → settle protocol + marshaling + PIP shape.
2. real PIP against DynamoDB; a couple of real connectors; graceful WAL-replay-on-restart.
3. two-box AWS deploy: broker box (`brokerRole`, NAT, the `:8080` + `:8443` surfaces) + agent
   box (`agentRole`, isolated subnet, SG egress to the broker SG only); agent finds the broker
   via an SSM param (`/safe-agents/{env}/broker-endpoint`). Prove the live round-trip = G9.
