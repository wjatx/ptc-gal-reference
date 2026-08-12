# Turn identity — why the broker owns the turn boundary (sa#136)

**Status: decided and built.** This records the design fork resolved for taint-completeness Phase 1
(sa#136) and the mechanism that landed, so the next reader understands *why* turn identity is
broker-owned rather than agent- or request-derived.

## The problem it fixes

sa#134 made a successful `external` + `effect=read` connector call taint its own `TurnContext` (the
self-ingest hook in `runtime/pep.py::_executor`), so a subsequent tainted external write in the same
turn escalates to `require_approval`. But that guarantee was **production-inert across `/call`**: the
PEP minted a fresh `TurnContext` per request, keyed to `turn_id = request.idempotency_key or uuid`.
Two holes followed:

1. **Taint was discarded per call.** The self-ingested taint died when the HTTP response returned, so
   a read in call 1 never reached a write in call 2.
2. **The agent chose the turn id.** Even had we persisted the context by `turn_id`, the agent supplies
   that id (via `idempotency_key` in the POST body). Per `memory/TAINT.md` Rule 2, an agent could
   declare a fresh turn after every read to shed taint before a write — laundering untrusted content
   into a "clean" premise by going *around* the airlock in time.

The turn boundary being **agent-chosen** is the root defect. Whoever owns the turn boundary owns
whether taint can be laundered.

## The fork

Two ways to take the boundary away from the agent:

- **Broker-held session** — the runtime holds one `TurnContext` for its principal, with
  broker-controlled rollover.
- **Harness-authenticated turn header** — a trusted harness signs a turn token (e.g. HMAC) the agent
  process cannot forge; the broker validates it and delineates turns from it.

## Why broker-held session

The deciding fact: **the runtime is already single-principal.** `BrokerRuntime._principal` is fixed at
construction from the `AgentManifest`, never read from the request body — the broker already knows
*who* without trusting the agent. So it needs to own only *when a turn rolls over*, and it can do that
with its own held state; no new protocol is required.

The harness-authenticated header is the right model when **one broker connection multiplexes many
principals** and needs a trusted outer process to delineate per-principal turns. That is not the shape
here (one runtime, one principal), so a signing handshake with a harness↔broker shared secret would be
machinery the prototype does not yet need. It stays the documented alternative for the day the broker
serves many principals over one channel.

Decoupling was explicit: **turn identity** is now broker-minted (`turn:<uuid>` in `_session_turn`);
**`idempotency_key`** stays exactly what it was — the `enforce()` dedup/replay key — and no longer
influences turn identity anywhere. Identity and dedup were conflated in one field; sa#136 splits them.

## What landed

In `safe_agents/broker/runtime/pep.py`:

- `BrokerRuntime` holds `self._current_turn: TurnContext | None`. `_session_turn()` lazily creates it
  with a broker-minted id and returns the same instance thereafter.
- `handle_request` uses `turn_context if turn_context is not None else self._session_turn()`. Over
  HTTP the agent passes no `turn_context` (see `prototype/broker_server.py::do_POST`), so it always
  gets the broker-held session turn; taint accumulates across every `/call`. Tests may thread an
  explicit `turn_context` to drive one turn deterministically.
- `new_turn()` rolls the boundary (discards accumulated taint) and is **broker/harness-owned**: it is
  wired to no HTTP route (`broker_server.py` serves only `/registry` and `/call`), so the agent —
  which reaches the runtime only across that surface — cannot invoke it. Only the trusted loop driver
  that owns the runtime object, or a human-side reset, may roll a turn.

The agent therefore supplies **neither the turn id nor the rollover signal**. Clearing taint is a
broker-side event only (a `new_turn()` call, or session expiry / process restart) — never anything the
agent controls, exactly as `memory/TAINT.md` requires.

## Rollover policy (the conservative default)

The prototype does not call `new_turn()` from the HTTP surface, so a turn persists for the runtime's
lifetime: once any external read taints the turn, every later external write needs approval until a
broker-side roll or a restart. That is the safe floor — a compromised agent that has ingested
untrusted content cannot autonomously write again without a trusted actor intervening. A real
deployment's loop driver decides when a genuinely new episode begins and calls `new_turn()`; that
policy is harness/consumer concern, not a base invariant.

## Known boundaries (Phase 1 is the mechanism, not the whole surface)

- **No production caller of `new_turn()` yet.** The prototype never rolls the turn, so once any
  external read taints the session every later external write escalates for the life of the process
  (see "Rollover policy"). That is the safe direction; closing it means the trusted loop driver calls
  `new_turn()` at real episode boundaries — future work, not this phase.
- **One shared turn is not thread-safe, and sharing is per-process, not per-session.** The runtime
  serializes calls per principal by assumption; it holds no lock. Under `ThreadingHTTPServer` two
  concurrent `/call`s could race the `_session_turn` check-then-set (dropping one's taint — a
  **fail-open** direction) or snapshot taint before a sibling's read self-ingests it. The single-agent
  prototype issues calls sequentially, so this is latent, not live. A broker that multiplexes
  concurrent or genuinely distinct sessions needs **per-session turn isolation** — which is the same
  design surface as the harness-authenticated-turn header above (a signed turn id keys a per-session
  context). Deliberately not half-fixed with a partial mint-lock, which would leave the
  taint-mutation TOCTOU open while looking safe.

## Acceptance predicate

`safe_agents/broker/tests/test_turn_identity.py` (cross-`/call`, no threaded context):

1. read in call 1 → tainted write in call 2 → `require_approval`;
2. distinct `idempotency_key`s on the two calls still escalate (identity is decoupled from the key);
3. `new_turn()` clears taint (a later identical write is allowed) — rollover is real but broker-owned;
4. control: two untainted writes across calls stay allowed (isolating taint, not the shared turn, as
   the cause in predicate 1).

Idempotency/replay is unchanged: `enforce()` still dedups on `request.idempotency_key`
(`test_runtime.py::test_idempotent_replay`).
