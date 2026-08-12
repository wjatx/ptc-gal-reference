# GATEWAY.md — the broker as one MCP server

**Status:** contract + reference implementation, written 2026-07-26 (#283). Code:
`safe_agents/broker/gateway/`. Sibling to [`MCP-HOST.md`](MCP-HOST.md), which governs the broker as
an MCP *client*; this governs the broker as an MCP *server*.

## What this is

The broker's **second mouth**. The first is the JSON-over-HTTP `/call` handler in
`prototype/broker_server.py`. This one speaks MCP over stdio, so a wrapped agent sees exactly ONE
MCP server whose tools are the ops the broker will serve it. Every call goes through the full
per-call path — PDP decision, taint, budgets, audit — because it goes through `handle_request` like
every other caller.

A mouth **carries** calls. It never decides one. If a policy decision appears in this package, it
is in the wrong place.

Built base-side [ruling: maintainer, 2026-07-25]: a gateway implemented inside a wrapper's own
package would be a second broker mouth living outside the broker, cutting against "the broker is the
one deliberately non-swappable implementation" (`docs/contract-vs-reference.md`). A wrapper
configures and launches this gateway; it does not implement it.

## Shape

Two modules, split the way the client side already splits:

| Module | Tier | Owns |
|---|---|---|
| `gateway/surface.py` | contract | What is advertised and what is answered. **SDK-free** — testable with the optional `mcp` extra absent. |
| `gateway/server.py` | reference | The thin `mcp` SDK binding: two handlers and a stdio runner. Lazy import. |
| `gateway/__main__.py` | reference | `python -m safe_agents.broker.gateway` — what a harness spawns. |

## Clauses

| # | Clause |
|---|---|
| **G1** | **The mouth carries, never decides.** Every advertised tool call reaches `BrokerRuntime.handle_request`. The gateway holds no connector, no credential and no reference it could execute through — it can only ask, exactly like the agent on the other side of it. |
| **G2** | **Listing is granted-only, and listing is not authority.** `tools/list` reports `served_registry()` — the ops this principal was granted. An ungranted op is *absent*, not refused ("removal, not refusal"). But absence is a display property: nothing stops a client asking for a name that was never listed. |
| **G3** | **An unrecognized tool name is routed, not answered.** Because of G2, the mouth hands any name it does not recognize to the broker rather than refusing it locally — so the refusal is the broker's, and lands on the audit tape. A gateway that short-circuited unknown names would be deciding, and would rob the tape of exactly the events most worth having on it. The sole exception is a name with no separator at all, which yields no coordinate to route. |
| **G4** | **A refused call is an error, and a held call is not a success.** Deny, abstain and `require_approval` all return `isError=true`. An approval hold has not executed; reporting it as success would be a lie in the flattering direction (`docs/posture-ladder.md`). The broker's own reason string is passed through verbatim — it is what the audit record says. |
| **G5** | **Descriptions are broker-authored.** The advertised description is composed from the consumer's own `ToolOp` classification, never from anything a tool server said. A description is model-facing steering and therefore injection surface (M2, and why an admission diff renders description deltas verbatim); sourcing it from our own manifest means there is nothing to launder. |
| **G6** | **The advertised input schema is a placeholder, and is never enforced client-side.** Handlers register with `validate_input=False`. A schema the gateway invented must not cause a client to refuse a valid call locally — that is enforcement in the wrong place by the wrong component, and the refusal would never reach the broker or the tape. |
| **G7** | **The coordinate↔wire-name map is data.** `(tool, op)` advertises as `tool__op` and the mapping is held as a dict, never re-parsed out of the wire name. Two coordinates that would flatten to the same name **refuse at list time** rather than one silently shadowing the other. |
| **G8** | **stdout belongs to the protocol.** MCP over stdio frames JSON-RPC on stdout; diagnostics go to stderr. Verified, not assumed: with `build_runtime`'s backend banner left on stdout, a real client dies on `Invalid JSON ... input_value='[broker] envelope load mode: manifest'`. |
| **G9** | **One marshal.** Connector results are marshalled by `broker/marshal.py`, the dependency-free leaf homed once for exactly this reason. This is its third caller after the HTTP boundary and `enforce()`; a per-transport copy is the "a seam is proven per transport" lesson charging interest again. |
| **G10** | **No second config surface.** The gateway takes its manifest and backends from the same environment the HTTP mouth uses. On a durable store arm an unnamed `BROKER_MANIFEST` refuses rather than defaulting to the example manifest (#197/#199, `docs/config-provenance.md`). |

## Known limits — v1

Named here rather than left to be discovered, because a gateway that looks finished is the thing
this repo's posture doctrine is most wary of.

**Advertised schemas are placeholders (G6).** `served_registry()` returns `ToolOp` classifications,
which carry no argument schema; the ratified schemas live in registry rows that `build_runtime`
does not hand back. So a wrapped agent gets no argument guidance from the gateway. Closing this
needs a decision about the public surface — tracked as the **#266** surface finding, deliberately
not widened ad hoc mid-build.

**~~An unclassified coordinate is refused without an audit record.~~ FIXED — #281, 2026-07-27.**
This limit was found by the live drill below and closed the same day. Kept here rather than deleted
because the *reason* it existed is the durable part.

Driving the spawned gateway against `examples/alpaca_paper_drill/`, `alpaca__place_stock_order` came
back `isError=true` over the wire and the resulting `BROKER_AUDIT_PATH` chain held **one** record —
the read — and nothing for the refusal. Which posture produced which mattered: the manifest whose
dangerous op is deliberately ABSENT (the missileer archetype, `examples/restricted_mcp_server/`) got
the *unrecorded* refusal, while a manifest that classifies-but-withholds got the recorded one. **The
stronger refusal left the weaker tape**, which is why this was a posture/contract disagreement
rather than a cosmetic gap.

Both halves are now recorded, per **MCP-HOST.md M26**: a coordinate absent from `tool_ops` audits as
`deny`/`denied`, and a call refused by two-key admission audits as `outcome="refused"` — distinct
from `failed`, which means the effect was attempted and broke.

**Drift is checked at connect, not per call.** The gateway is long-lived, which makes connect-time-
only drift checking a hole here specifically — **#227**.

**stdio only.** The HTTP mouth and the CLI call seam are **#285**. Resources and prompts are
**#222** (decision only).

**Nothing is confined.** The gateway runs as the same OS user as the agent it serves, and MCP-stdio
children run unconfined (**#269**). This is rung 1 (`docs/posture-ladder.md`); a gateway does not
move the rung, because a rung is about where the boundary is.

## Relationships

- [`MCP-HOST.md`](MCP-HOST.md) — the broker as MCP *client*; M1–M25, including the two-key admission
  the gateway's served set ultimately rests on. M25 (a remote server's credential is broker-resolved
  per connect) is a *client-side* clause like M17–M20: it governs the session the broker opens
  OUTWARD to a vendor, not the one a harness opens inward to the gateway.
- `docs/posture-ladder.md` — the vocabulary the limits above are stated in.
- `docs/contract-vs-reference.md` — why `surface.py` is contract and `server.py` is reference.
- `examples/embedded_agent/` — the consumer the conformance suites compose their runtime from.
