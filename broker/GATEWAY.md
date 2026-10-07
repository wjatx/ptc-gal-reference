# GATEWAY.md — the broker as one MCP server

**Status:** contract + reference implementation, written 2026-07-26; the network transport
(G11 to G20) and the tool-event mouth (G21 to G29) added 2026-10-06. Code: `safe_agents/broker/gateway/`. Sibling to [`MCP-HOST.md`](MCP-HOST.md), which governs the broker as
an MCP *client*; this governs the broker as an MCP *server*.

## What this is

The broker's **second mouth**. The first is the JSON-over-HTTP `/call` handler in
`prototype/broker_server.py`. This one speaks MCP, so a wrapped agent sees exactly ONE
MCP server whose tools are the ops the broker will serve it. It is served over two transports:
stdio, for a harness that spawns the gateway as its child, and streamable HTTP, for an agent that
cannot be the gateway's parent because a boundary sits between them. "The HTTP mouth" in this
repository already names `/call`, so the second transport is called the **network MCP mouth**. Every call goes through the full
per-call path — PDP decision, taint, budgets, audit — because it goes through `handle_request` like
every other caller.

A mouth **carries** calls. It never decides one. If a policy decision appears in this package, it
is in the wrong place.

Beside the MCP surface, the gateway can open a third mouth that carries no calls at all: the
**tool-event mouth**, where a harness's hooks report the calls its own tools made, after they ran
(G21 to G29). It observes. It is not an MCP transport and it serves no tools.

Built base-side [ruling: maintainer, 2026-07-25]: a gateway implemented inside a wrapper's own
package would be a second broker mouth living outside the broker, cutting against "the broker is the
one deliberately non-swappable implementation" (`docs/contract-vs-reference.md`). A wrapper
configures and launches this gateway; it does not implement it.

## Shape

Split the way the client side already splits, with everything that can be stated without the
SDK kept out of the one module that imports it:

| Module | Tier | Owns |
|---|---|---|
| `gateway/surface.py` | contract | What is advertised and what is answered. **SDK-free** — testable with the optional `mcp` extra absent. |
| `gateway/authn.py` | contract | Who may speak on the network MCP mouth: the closed authenticator catalog, the launch-token check, and the ledger that bounds how refusals reach the tape. **Standard library only.** |
| `gateway/network.py` | contract | The network MCP mouth minus the SDK: the guard in front of every request, the one route, the serialization of calls into the runtime, and the launch settings. **SDK-free**, plain ASGI. |
| `gateway/events.py` | contract | The tool-event mouth minus the HTTP server: its one route, the report's parsing and bound, and its launch settings. **SDK-free**, plain ASGI. Its vocabulary lives with the runtime, in `runtime/observed.py`, standard library only. |
| `gateway/server.py` | reference | The thin `mcp` SDK binding: two handlers, a stdio runner and a streamable HTTP runner over the same `Server`. Also the one HTTP serve loop both HTTP mouths run on, and the runner that serves every mouth in the process on one event loop. Lazy import. |
| `gateway/__main__.py` | reference | `python -m safe_agents.broker.gateway` — what a harness spawns, or what a launcher starts beside a sandbox. |

The clients that ask this gateway are not part of it. They are published as
`safe_agents.broker.client`, the tier of what a consumer asks with: `GatewayClient` for stdio and
`NetworkGatewayClient` for the network MCP mouth, both standard library only. They live outside
`gateway/` so that importing them loads none of the modules above, and none of the runtime behind
them (`docs/consuming-the-sdk.md` §2).

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
| **G10** | **No second config surface.** The gateway takes its manifest and backends from the same environment the HTTP mouth uses. On a durable store arm an unnamed `BROKER_MANIFEST` refuses rather than defaulting to the example manifest (`docs/config-provenance.md`). |

### The network MCP mouth

G1 to G10 hold on both transports. G11 to G20 are what a socket adds. They follow the design ruling
recorded on #161 [ruling: maintainer, 2026-10-06].

| # | Clause |
|---|---|
| **G11** | **One surface, one binding, two transports.** The MCP surface is served over two transports, and only two. The network MCP mouth serves the same `GatewaySurface` through the same SDK `Server` and the same two handlers as stdio. The tool-event mouth (G21) is a listener of another kind, carrying no MCP and no tool call, and is not a third transport of this surface. It has no handler and no result conversion of its own, so a `GatewayResult` becomes a wire result in exactly one place and a change there (#156) lands on both transports. A second conversion would be G9's per-transport copy under another name. |
| **G12** | **No frame before authentication.** Every request is authenticated before anything behind the guard runs: before routing, before the session lookup, before the SDK reads a byte of the body. That covers `initialize`, `tools/list`, `tools/call`, the event stream and session teardown alike, and every HTTP method, including the ones no MCP client sends: an `OPTIONS` preflight or a `HEAD` probe is a request like any other, and an `OPTIONS` let past the guard is answered by the SDK with a JSON-RPC frame and a new session id. `handle_request` is never reached for a request that has not passed. Authentication is per request and never per session. A session id is something the caller sends, and nothing the caller sends stands in for the credential. A refused request gets one fixed `401` that does not say which check failed and is not a JSON-RPC frame. |
| **G13** | **The authenticator is a closed catalog, selected by name.** `BROKER_GATEWAY_AUTH` names a member of `MouthAuthenticator`, a base-owned enum, the way a connector's credential strategy is named from `AuthStrategy` (`CONNECTOR-AUTH.md`). It is never an import path, so no configuration surface can supply one (`docs/config-provenance.md`, decision test 1). **Unnamed refuses to start.** There is no unauthenticated default, on loopback or anywhere else: loopback is reachable by every local process, whichever user it runs as. |
| **G14** | **`launch_token`: a token bound at launch.** Whoever launches the gateway generates a secret, writes it to a file, names that file in `BROKER_GATEWAY_TOKEN_FILE`, and hands the same secret to the one agent it launches. The agent presents it as `Authorization: Bearer <token>` on every request. The mouth compares SHA-256 digests with a constant-time comparison and keeps the digest, not the token. The token reaches the gateway as a bare leaf from its launcher: by file, never as an environment value (every child the broker spawns for a connector would inherit it), and never from a manifest or a store. The file is refused if it is readable beyond its owner on a POSIX system, if the token is shorter than 32 characters, or if it contains a character a bearer credential cannot carry. A token in a URL query string is refused even beside a valid header, because URLs are what gets logged. |
| **G15** | **Two names are reserved.** `oauth_bearer` is the MCP specification's own authorization for HTTP transports (OAuth 2.1 bearer tokens). `mtls_workload_identity` is mutual TLS with workload identity. They are the arms for a gateway reached from another machine, and each needs an issuer the single-machine case does not have. Selecting either refuses to start, saying it is not implemented. |
| **G16** | **The caller never names the principal.** One runtime serves one principal, taken from its manifest, and that stays true here. The mouth does not learn who is calling. It decides whether this connection may speak as the runtime's one principal. No header, query parameter or body field names, widens or changes the principal, and the mouth lifts nothing out of a request into a field the broker would trust: it passes the tool name and the arguments, as sent. |
| **G17** | **A refused connection is recorded, and the refused party cannot flood the tape.** The mouth holds no audit sink (G1). It records through one runtime method, `BrokerRuntime.record_refused_connections`, which writes a `deny`/`denied` record under the runtime's own principal with the reserved coordinate `broker-mouth` / `network-mcp`. What reaches the tape is a count per cause from a closed vocabulary (`RefusalCause`); no header, token, address or other caller-chosen byte does. Every refusal is counted. At most one record is written per 60-second window: the first refusal after a quiet window is recorded at once, the rest of that window's refusals ride the next record as counts, and shutdown writes the tail. A recording that fails never admits the connection; the counts are kept and the write is retried at the next window. |
| **G18** | **Calls into the runtime are serialized, on the thread that built it.** The runtime is not thread-safe by design: two overlapping calls can drop one's taint or decide before a sibling's read has tainted the turn, and both fail open (`runtime/pep.py`, `_session_turn`; the reason `/call` is single-threaded). A sqlite store's connections also belong to the thread that opened them. So the event loop runs on the thread that built the runtime, the handlers enter the runtime synchronously on it, and `SerializedSurface` refuses, before the runtime, any call from another thread or any call that arrives while one is inside. While a call is inside, nothing else is served. Concurrency is not regained by threading; it needs per-session turn isolation in the PEP first (`docs/turn-identity.md`). |
| **G19** | **Launch settings come from the environment (G10).** `BROKER_GATEWAY_TRANSPORT` selects the MCP surface's transport from a closed set: unset or `stdio`, or `streamable-http`; anything else refuses. Whether the tool-event mouth opens beside it is a separate setting (G28). `BROKER_GATEWAY_HOST` is the bind address and defaults to `127.0.0.1`. `BROKER_GATEWAY_PORT` must be named; `0` takes a free port, reported on stderr. The network MCP mouth's path is `/mcp` and is not a setting. Every setting is checked, and the address is bound, before the runtime is built, so a mouth that refuses to start (an unnamed authenticator, an unusable token, an address it cannot bind, a port already taken) has touched no store. The address is announced on stderr once the runtime is built, and a stop signal is honoured from that announcement on: one `SIGTERM` or `SIGINT` stops every mouth the process opened by returning, so the last refusal counts are written (G17), including when it arrives before the server underneath has begun serving (G29). A bind to a non-loopback address is allowed, because an agent in a virtual machine or a container reaches the host across one, and is announced on stderr as carrying the token in the clear. |
| **G20** | **What a stranger can make the mouth write to stderr is bounded, and a request line is never written.** The HTTP server underneath the mouth logs a line for bytes it cannot parse and for an upgrade it does not serve. Both happen before the guard is asked anything, so a caller with no credential chooses how many are written, and a launcher that keeps the gateway's stderr in a file would be keeping a file that caller can grow. `DiagnosticBudget` admits at most 20 server diagnostics per 60-second window whatever they say, counts the rest, and reports the count on the first line of the next window or at shutdown. The server's access log is off: a request line carries the query string, which is where the credential G14 refuses would be. |

> **Implementation status:** NOT YET IMPLEMENTED in the reference implementation (tracking: not yet
> filed). The two reserved authenticators of G15, `oauth_bearer` and `mtls_workload_identity`, are
> names only. No code resolves, verifies or serves either one; naming one refuses at startup.

### The tool-event mouth

A coding harness has tools of its own: a shell, file reads and writes, a web fetch. Their calls
never become MCP calls, so G1 to G20 never see them, and a read made with one of them used to
leave the broker's turn clean. A harness's hooks can report each such call after it ran. G21 to
G29 are where that report arrives and what it may do. They follow the design ruling recorded on
#168 [ruling: maintainer, 2026-10-06].

| # | Clause |
|---|---|
| **G21** | **It observes, and decides nothing.** The tool-event mouth receives reports of calls that have already happened. It gates nothing and holds nothing back: a report reaches one runtime method, `BrokerRuntime.record_observed_event`, which writes one record and, when the reported tool brought content into the agent's context, taints the broker-held session turn (`TAINT.md` §2). How a harness's own tool would be given a `ToolOp`, and decided before it runs, is not answered here. Like G1, the mouth holds no sink, no connector and no credential. |
| **G22** | **A report is a claim, and its worst case is an approval.** It is made by a hook running as the same user as the agent, and the launch token it presents proves the reporter was handed the token, not that the call happened as described. Taint only accumulates, so a forged report can add taint and nothing else: its cost is approvals the agent's writes did not need. A report the harness never sends (a hook that does not fire, fails, or was overwritten) is the harness's own fail-open, and no mouth can fix it. The method never rolls the turn: `new_turn` stays off every mouth. |
| **G23** | **Closed vocabularies, and digests only.** A report carries `harness`, a short lowercase code (G17's alphabet); `tool_class`, one of `file-read`, `file-write`, `file-edit`, `shell`, `web-fetch`, `web-search`, `other`; `locality`, one of `project`, `home`, `outside`, `remote`, `unknown`; `subject_digest`, exactly `sha256:` and 64 lowercase hex digits; and optionally `result_digest` in the same form. No path, URL, command line or content is accepted in any field. The mouth checks the report before it enters the runtime, and the runtime checks every field again, since a mouth is not trusted to have checked. Anything else on the mouth's path (another method, a body that is not JSON or not an object, a missing, unknown or repeated key, a value outside its vocabulary, a body over 4096 bytes) gets one fixed `400` and writes nothing. The body is read up to the bound and no further. |
| **G24** | **The source id is built from codes, and only the consumer can trust it.** A report of `file-read`, `web-fetch` or `web-search` ingests `harness:<harness>/<tool_class>/<locality>` into the session turn; the other classes record and do not taint. The base trust map treats every `harness:` source as untrusted, as it does `connector:`, so the consumer's `Envelope.trusted_read_sources` is the only way a class is trusted, and it names a class at a locality without ever naming a path. A trusted source is recorded and not ingested. The ingest comes before the record, so a sink that fails leaves the turn tainted and the record missing, never the reverse. |
| **G25** | **One record, in a fixed shape.** Under the runtime's own principal and envelope hash: `tool` is the reserved coordinate `harness-tool`, `op` is the tool class, `decision` is `abstain` (the broker made no decision) and `outcome` is `observed` (`SCHEMAS.md` §5). `reason` reads `observed, not decided: <harness> <tool_class> (<locality>) reported by mouth tool-event`. `resultDigest` carries the result digest when one was reported. The arguments hashed into `argsDigest` are `{"harness", "locality", "subject"}`, the last being the subject digest, so a reader holding a candidate path can recompute it. `subject` is `sha256:` and the hex SHA-256 of the path's UTF-8 bytes, spelled as the harness's adapter spelled it (`runtime/observed.py`, `digest_subject`); `harness` and `locality` are named in the record's `reason`; and `argsDigest` is `sha256:` and the hex SHA-256 of that object as JSON with sorted keys and no whitespace (`audit.hash_args`). A path spelled differently does not match. |
| **G26** | **The same guard, authenticator and token as the network MCP mouth.** G12 to G15 hold here unchanged: every request is authenticated before it is routed or a byte of its body is read; the authenticator is named from the same closed catalog by the same `BROKER_GATEWAY_AUTH`, and the token is read from the same `BROKER_GATEWAY_TOKEN_FILE`; an unnamed authenticator with the mouth's port named refuses to start, on loopback as anywhere. Refusals are recorded as G17 says, under this mouth's own code, `tool-event`. What the server underneath may write to stderr is bounded as G20 says, by one budget shared with the network MCP mouth when both are open. |
| **G27** | **Reports enter the runtime as calls do (G18).** The mouth enters through the same `SerializedSurface` as the MCP surface in that process, on the thread that built the runtime, under the same two rules: no entry from another thread, none while another call is inside. |
| **G28** | **Launch settings come from the environment (G10).** `BROKER_EVENT_MOUTH_PORT` opens the mouth when named; `0` takes a free port. `BROKER_EVENT_MOUTH_HOST` is the bind address and defaults to `127.0.0.1`. A host or address file named without a port refuses to start. The path is `/events` and is not a setting. The address is checked and bound before the runtime is built, and announced on stderr as `[broker] tool-event mouth on http://HOST:PORT/events (authenticator: NAME)`, with the same warning as G19 for a bind beyond loopback. `BROKER_EVENT_MOUTH_ADDR_FILE`, when named, is where the gateway writes `host:port` and a newline at that moment, so a launcher that asked for port 0 can find the mouth: owner-only (`0600`), created or truncated, not followed through a symbolic link where the platform can refuse one. It holds no secret. A gateway that cannot write it stops before it serves. |
| **G29** | **A stdio gateway may open it, and one process stays one turn.** On either transport the mouth is its own listener, and the same handler serves it. A stdio gateway that also listens is still one process holding one runtime and one turn, which is the point: the turn lives in that process, and a report has to reach it. Every mouth the process opens runs on one event loop, on the thread that built the runtime. When any mouth returns the rest are stopped, so a stdio client closing its pipe closes the tool-event mouth too. One `SIGTERM` or `SIGINT` stops every mouth, each writes its refusal tail (G17), and the process leaves by returning, so connector children are reaped (`MCP-HOST.md` M20). Over stdio that is new: before this mouth existed a stdio gateway installed no handler, and `SIGTERM` ended it on the spot. |

## Known limits — v1

Named here rather than left to be discovered, because a gateway that looks finished is the thing
this repo's posture doctrine is most wary of.

**Advertised schemas are placeholders (G6).** `served_registry()` returns `ToolOp` classifications,
which carry no argument schema; the ratified schemas live in registry rows that `build_runtime`
does not hand back. So a wrapped agent gets no argument guidance from the gateway. Closing this
needs a decision about the public surface — an open public-surface finding, deliberately
not widened ad hoc mid-build.

**~~An unclassified coordinate is refused without an audit record.~~ FIXED 2026-07-27.**
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
only drift checking a hole here specifically — **#92**.

**The launch token is a bearer secret, and the agent holds it.** Anything that can read it can ask
as the gateway's principal. It buys the right to ask and nothing more: the broker still decides
every call, and a compromised agent with the token is exactly the compromised agent the broker was
already built to face. Its exposure is bounded only by whatever boundary the agent sits in. It does
not identify a caller, it does not distinguish two processes that both hold it, and it is not
rotated while the gateway runs.

**The network MCP mouth speaks plain HTTP.** There is no TLS. On loopback the token never leaves
the machine. On any other bind address it crosses that network in the clear and is only as private
as that network is; the launcher says so on stderr. The two reserved authenticators (G15) are the
arms for a gateway reached from another machine, and neither is built.

**A refusal record is coalesced, so it is late and it is a count.** G17 trades each later
refusal's own timestamp for a bound on tape growth. A refusal inside a window that is followed by
no further request waits for shutdown, and a process killed without the chance to shut down loses
the counts it had not yet written. Guessing is not rate-limited; the 32-character floor on the
token is what makes guessing hopeless.

**G17 and G20 bound a rate, not a total.** A caller with no credential who sends one bad request a
minute adds one bounded record to the tape per window for as long as it keeps going, and up to the
window's budget of lines to stderr. Neither grows with the number of attempts inside a window.
Both still grow with time, and what stops that is whatever keeps strangers off the socket.

**G20 bounds what the HTTP server logs, not what the event loop logs.** `DiagnosticBudget` filters
the server's own logger. A process that has run out of file descriptors fails in the event loop's
accept, which reports each failure on a different logger with a traceback, and the budget does not
see those. A caller with no credential who can hold enough idle connections open to exhaust the
descriptor limit can therefore grow stderr past G20's bound. Found in review of this binding and
not closed: the bound holds for requests the server reads, and a connection limit in front of the
mouth is what holds it otherwise.

**The tool-event mouth sees what the harness reports, and nothing else.** A hook that does not
fire, a read that arrives as a shell command (`cat` is `shell`, which does not taint), and a tool
the adapter calls `other` all leave the turn as it was. The tool class and the locality are the
harness's adapter's classification, and the broker cannot check either: a read the adapter places
in `project` when it was `outside` is trusted wherever the consumer trusts `project`. Taint lands
when the report arrives, not when the read happened, so an agent that can issue a write between a
read and its hook's report has that window; whether one exists is the harness's to say.

**The turn is in-process.** A report taints the turn of the gateway process it reaches. A harness
whose hooks point at another gateway process, or a launcher that runs two, taints a turn no tool
call of this agent will ever be decided in. One gateway per agent session, its mouth's address
handed to that session's hooks, is the launcher's to arrange.

**Built-in tools are observed, not confined.** The mouth narrows the gap `docs/posture-ladder.md`
names at posture 1; it does not close it. Nothing gates a harness's own tool, and a harness that
stops reporting is ungoverned in exactly the way it was before this mouth existed. That gap closes
by containment.

**An unreachable gateway has no stated posture.** A network mouth makes this a live case in a way
a stdio child never was: the agent can be up while the gateway is not. What the agent should do
then depends on its polarity and is not decided here (**#106**).

**The CLI call seam** is an open item. Resources and prompts are **#89** (decision only).

**Nothing is confined by the gateway.** Launched over stdio, the gateway runs as the same OS user
as the agent it serves. That is posture 1 (`docs/posture-ladder.md`). The network MCP mouth lets
a boundary be put between the two, and does not put one there: a posture is about where the
boundary is, and the sandbox is whoever launches the agent's to supply. On either transport,
MCP-stdio children the broker spawns for connectors run unconfined (**#104**).

## Relationships

- [`MCP-HOST.md`](MCP-HOST.md) — the broker as MCP *client*; M1–M25, including the two-key admission
  the gateway's served set ultimately rests on. M25 (a remote server's credential is broker-resolved
  per connect) is a *client-side* clause like M17–M20: it governs the session the broker opens
  OUTWARD to a vendor, not the one a harness opens inward to the gateway.
- [`TAINT.md`](TAINT.md) — the floor the tool-event mouth feeds: the `harness:` source family
  beside `connector:`, and why a report can only add taint.
- `docs/posture-ladder.md` — the vocabulary the limits above are stated in.
- `docs/contract-vs-reference.md` — why `surface.py` is contract and `server.py` is reference.
- `examples/embedded_agent/` — the consumer the conformance suites compose their runtime from.
