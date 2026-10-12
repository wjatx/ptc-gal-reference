# GATEWAY.md — the broker as one MCP server

**Status:** contract + reference implementation, written 2026-07-26; the network transport
(G11 to G20) and the tool-event mouth (G21 to G29) added 2026-10-06; the decision mouth (G30 to G38)
added 2026-10-12. Code: `safe_agents/broker/gateway/`. Sibling to [`MCP-HOST.md`](MCP-HOST.md), which governs the broker as
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
(G21 to G29). It observes. It is not an MCP transport and it serves no tools. On the same listener
a second route, the **decision mouth**, is where a harness's hook asks before the harness runs one
of its own tools (G30 to G38). The runtime decides that call and the route carries back one of two
answers, `permit` or `refuse`. The harness enforces the answer; nothing here confines its tools.

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
| `gateway/events.py` | contract | The tool-event mouth minus the HTTP server: its two routes (`/events`, `/decide`), the parsing and bound of a report and of a decision request, the answer's shape, and the launch settings. **SDK-free**, plain ASGI. Its vocabulary lives with the runtime, in `runtime/observed.py` and `runtime/harness_decision.py`, standard library only. |
| `gateway/server.py` | reference | The thin `mcp` SDK binding: two handlers, a stdio runner and a streamable HTTP runner over the same `Server`. Also the one HTTP serve loop both HTTP mouths run on, and the runner that serves every mouth in the process on one event loop. Lazy import. |
| `gateway/sweep.py` | reference | The expiry sweep (#163) served beside the mouths on the same loop: it records holds that expired undecided, once at start and then once a minute, and writes audit records with no request in flight. |
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
| **G18** | **Calls into the runtime are serialized, on the thread that built it.** The runtime is not thread-safe by design: two overlapping calls can drop one's taint or decide before a sibling's read has tainted the turn, and both fail open (`runtime/pep.py`, `_session_turn`; the reason `/call` is single-threaded). A sqlite store's connections also belong to the thread that opened them. So the event loop runs on the thread that built the runtime, the handlers enter the runtime synchronously on it, and `SerializedSurface` refuses, before the runtime, any call from another thread or any call that arrives while one is inside. While a call is inside, nothing else is served. The expiry sweep (`gateway/sweep.py`, #163) enters the same way, through the same `SerializedSurface` on the same thread: a sweep that finds a call inside is refused like any other entry, logged, and retried at the next interval. Concurrency is not regained by threading; it needs per-session turn isolation in the PEP first (`docs/turn-identity.md`). |
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
| **G21** | **Its report route observes, and decides nothing.** `/events` receives reports of calls that have already happened. It gates nothing and holds nothing back: a report reaches one runtime method, `BrokerRuntime.record_observed_event`, which writes one record and, when the reported tool brought content into the agent's context, taints the broker-held session turn (`TAINT.md` §2). Deciding a harness's own tool call before it runs is the second route's, `/decide` (G30 to G38), and only for a call the harness's hook carries there. A harness's own tool call is given a `ToolOp` at the reserved coordinate `harness-tool`, op `<tool_class>/<locality>`, from the consumer's declaration in the image-baked manifest's `tool_ops` (`SCHEMAS.md` §2) [ruling: maintainer, 2026-10-12]. That coordinate is never advertised on the MCP surface, and a `tools/call` or `/call` that names it is refused and recorded as `deny`/`denied` before the manifest is consulted: a harness's call is never a tool the agent calls. Like G1, the mouth holds no sink, no connector and no credential. |
| **G22** | **A report is a claim, and its worst case is an approval.** It is made by a hook running as the same user as the agent, and the launch token it presents proves the reporter was handed the token, not that the call happened as described. Taint only accumulates, so a forged report can add taint and nothing else: its cost is approvals the agent's writes did not need. A report the harness never sends (a hook that does not fire, fails, or was overwritten) is the harness's own fail-open, and no mouth can fix it. The method never rolls the turn: `new_turn` stays off every mouth. |
| **G23** | **Two closed sets, one bounded code, and digests only.** A report carries `harness`, a code in a bounded alphabet (G17's: a lowercase letter, then up to 39 of lowercase letters, digits, `_` and `-`), which is NOT a closed set: any code so spelled is accepted, every one is untrusted, and only the consumer's `trusted_read_sources` gives a code any meaning (G24); `tool_class`, one of the closed set `file-read`, `file-write`, `file-edit`, `shell`, `web-fetch`, `web-search`, `other`; `locality`, one of the closed set `project`, `home`, `outside`, `remote`, `unknown`; `subject_digest`, exactly `sha256:` and 64 lowercase hex digits; and optionally `result_digest` and `call_digest` in the same form. `call_digest` is the harness's own id for the call, digested by the adapter, so a report pairs on the tape with the decision asked before the call ran, without a harness identifier in the clear. No path, URL, command line or content is accepted in any field. The mouth checks the report before it enters the runtime, and the runtime checks every field again, since a mouth is not trusted to have checked. Anything else on the mouth's path (another method, a body that is not JSON or not an object, a missing, unknown or repeated key, a value outside its vocabulary, a body over 4096 bytes) gets one fixed `400` and writes nothing. The body is read up to the bound and no further. |
| **G24** | **The source id is built from codes, and only the consumer can trust it.** A report of `file-read`, `web-fetch` or `web-search` ingests `harness:<harness>/<tool_class>/<locality>` into the session turn; the other classes record and do not taint. The base trust map treats every `harness:` source as untrusted, as it does `connector:`, so the consumer's `Envelope.trusted_read_sources` is the only way a class is trusted, and it names a class at a locality without ever naming a path. A trusted source is recorded and not ingested. The ingest comes before the record, so a sink that fails leaves the turn tainted and the record missing, never the reverse. |
| **G25** | **One record, in a fixed shape.** Under the runtime's own principal and envelope hash: `tool` is the reserved coordinate `harness-tool`, `op` is the tool class, `decision` is `abstain` (the broker made no decision) and `outcome` is `observed` (`SCHEMAS.md` §5). `reason` reads `observed, not decided: <harness> <tool_class> (<locality>) reported by mouth tool-event`. `resultDigest` carries the result digest when one was reported. The arguments hashed into `argsDigest` are `{"call", "harness", "locality", "subject"}`: `subject` is the subject digest, so a reader holding a candidate path can recompute it, and `call` is the reported call digest, or `null` when the report carried none, so the object has one shape either way. `subject` is `sha256:` and the hex SHA-256 of the path's UTF-8 bytes, spelled as the harness's adapter spelled it (`runtime/observed.py`, `digest_subject`); `harness` and `locality` are named in the record's `reason`; `call` is as reported; and `argsDigest` is `sha256:` and the hex SHA-256 of that object as JSON with sorted keys and no whitespace (`audit.hash_args`). A path spelled differently does not match. |
| **G26** | **The same guard, authenticator and token as the network MCP mouth.** G12 to G15 hold here unchanged: every request is authenticated before it is routed or a byte of its body is read; the authenticator is named from the same closed catalog by the same `BROKER_GATEWAY_AUTH`, and the token is read from the same `BROKER_GATEWAY_TOKEN_FILE`; an unnamed authenticator with the mouth's port named refuses to start, on loopback as anywhere. Refusals are recorded as G17 says, under this mouth's own code, `tool-event`. What the server underneath may write to stderr is bounded as G20 says, by one budget shared with the network MCP mouth when both are open. |
| **G27** | **Reports enter the runtime as calls do (G18).** The mouth enters through the same `SerializedSurface` as the MCP surface in that process, on the thread that built the runtime, under the same two rules: no entry from another thread, none while another call is inside. |
| **G28** | **Launch settings come from the environment (G10).** `BROKER_EVENT_MOUTH_PORT` opens the mouth when named; `0` takes a free port. `BROKER_EVENT_MOUTH_HOST` is the bind address and defaults to `127.0.0.1`. A host or address file named without a port refuses to start. The path is `/events` and is not a setting. The address is checked and bound before the runtime is built, and announced on stderr as `[broker] tool-event mouth on http://HOST:PORT/events (authenticator: NAME)`, with the same warning as G19 for a bind beyond loopback. `BROKER_EVENT_MOUTH_ADDR_FILE`, when named, is where the gateway writes `host:port` and a newline at that moment, so a launcher that asked for port 0 can find the mouth: owner-only (`0600`), created or truncated, not followed through a symbolic link where the platform can refuse one. It holds no secret. A gateway that cannot write it stops before it serves. |
| **G29** | **A stdio gateway may open it, and one process stays one turn.** On either transport the mouth is its own listener, and the same handler serves it. A stdio gateway that also listens is still one process holding one runtime and one turn, which is the point: the turn lives in that process, and a report has to reach it. Every mouth the process opens runs on one event loop, on the thread that built the runtime. When any mouth returns the rest are stopped, so a stdio client closing its pipe closes the tool-event mouth too. One `SIGTERM` or `SIGINT` stops every mouth, each writes its refusal tail (G17), and the process leaves by returning, so connector children are reaped (`MCP-HOST.md` M20). Over stdio that is new: before this mouth existed a stdio gateway installed no handler, and `SIGTERM` ended it on the spot. |

### The decision mouth

The tool-event mouth sees a harness's own tool call after it ran. A hook that fires before the
harness runs the call can ask instead, and G30 to G38 are where that request arrives, how it is
decided, and what goes back. They follow the second design ruling recorded on #168 [ruling:
maintainer, 2026-10-12]. The broker's answer is the only approval that call gets from this side.
The harness enforces it, and what the harness does with the answer, or with a call its hook never
carries, is outside these clauses.

| # | Clause |
|---|---|
| **G30** | **The call is classified at a reserved coordinate the consumer declares.** A decision request is decided as a `BrokeredCall` at tool `harness-tool`, op `<tool_class>/<locality>` (G21; `SCHEMAS.md` §2), whose `ToolOp` comes from the image-baked manifest's `tool_ops` and from nowhere else, activated by an ordinary grant on that action class. The base declares no facts for any class and no polarity. A request at a coordinate with no entry is refused and recorded as `deny`/`denied`, as an unclassified MCP coordinate is (M26). Locality is part of the coordinate, so a write inside the project and one outside it can carry different policy. Class and locality are the adapter's claims, which the broker cannot check, and the record's reason cites the coordinate, so a reader sees a declaration and not an observation. |
| **G31** | **The request carries G23's vocabulary and two more digests, and nothing else.** A `POST /decide` body is a JSON object with exactly six keys, all required: `harness`, `tool_class`, `locality` and `subject_digest` as G23 spells them; `input_digest`, the full tool input as the harness's adapter serialized it; and `call_digest`, the harness's own id for the call, so the decision and the report made after the call (G23) pair on the tape. Both are `sha256:` and 64 lowercase hex digits. No path, URL, command line or content is accepted in any field. The mouth checks the request and the runtime (`BrokerRuntime.decide_harness_call`) checks every field again. The decided call's args are `{"call", "harness", "input", "locality", "subject"}`, so `argsDigest` binds the input digest and a hold freezes it. |
| **G32** | **The answer is one of two words, and the mapping is the runtime's.** Every authenticated request on `/decide` gets `200` and a JSON object with exactly `answer`, `reason`, `intent_id` and `text`. `answer` is `permit` or `refuse`. The mapping from the PDP's five verbs is fixed in the runtime (`runtime/harness_decision.py`, `VERB_ANSWER`) and the mouth cannot vary it: `allow` permits, recorded as `allow`/`permitted` (`SCHEMAS.md` §5); `deny` refuses, recorded `deny`/`denied`; `abstain` refuses, recorded `abstain`/`denied` as every abstain is; `require_approval` refuses with the intent id, recorded as `held`; `transform` refuses, recorded as `deny` with a reason naming a configuration error, since the broker holds no safer op for a harness tool, and it is decided so before any counter is drawn. Only `allow` ever permits. |
| **G33** | **Decide, record, answer, and every failure refuses.** A permit is answered only after its `permitted` record is on the tape. An authenticated request the runtime cannot decide is answered `refuse`, never a bare `400` or `500`, because a harness reads those as no answer and by default proceeds. A request the mouth cannot read (another method on the path, a body over 4096 bytes, a body that is not such an object, a field outside its vocabulary) is refused and recorded once, as `deny`/`denied` under the reserved tool `broker-mouth` with op `tool-event` and args `{"cause"}`, the cause one of `bad-method`, `too-large`, `bad-body`, `bad-field`. A fault inside the runtime (a store, the sink, a record that fails to write, anything else) is logged, answered `refuse`, and recorded where the sink still takes it. Unauthenticated stays the fixed `401` (G26). |
| **G34** | **The same pipeline as a call, and no connector.** The request runs through the runtime's one enforcement pipeline: the manifest lookup, the PIP, the PDP, and `enforce()`, which revalidates against fresh facts, draws the per-op counter and journals the call in the write-ahead ledger. A permit draws the counter as an executed call does, so a breached cap refuses. Where an executed call reaches a connector, a permit writes its record and stops: the harness performs the call. `handle_request`, the entry every agent-facing caller takes, refuses the reserved coordinate (G21), so only this route reaches it. |
| **G35** | **A permitted read taints at the permit.** On a permit of `file-read`, `web-fetch` or `web-search`, the source `harness:<harness>/<tool_class>/<locality>` is ingested into the session turn after the decision is `allow` and before the record is written, so before the harness runs the read. A source the consumer's `trusted_read_sources` lists is not ingested (G24). A sink that fails leaves the turn tainted, the record missing and the answer `refuse`, never the reverse. For a call the hook carries, this closes the window between a read and its report. |
| **G36** | **A hold refuses now, and its approval permits the same call once.** A held call is frozen under an intent id derived from the principal, the coordinate's op and the input digest (`approval/queue_guard.py`, `harness_hold_intent_id`), so the request never names it and the broker finds it with one get by key on every intent store. A repeat of the request while the hold is pending coalesces onto it. Approving the intent (`approve_intent`) runs no connector and no `enforce()`: after the usual quarantine, foreign-principal and expiry checks it moves the intent to `approved`, stamps `approvedBy`, and writes no record. The next request from the same principal at the same coordinate with the same input digest, inside the intent's expiry, is evaluated again as every release is: fresh facts, the approval requirement satisfied, anything stricter still binding, a transform still refused. On `allow` it is permitted once, recorded `allow`/`permitted` with `intentId`, `storedCallDigest` recomputed from the stored bytes, and `approvedBy`, and the intent lands in `permitted`, which never claims the broker executed anything. A release the broker refuses lands the intent in `refused`, with its record carrying the same receipts. A request with another input digest neither releases nor consumes the approval. Once consumed, the same request is decided afresh. An approval found past the intent's expiry is moved to `expired`, its one record written (`approval lapsed unused`, with the approver named), and the request is decided afresh. |
| **G37** | **The broker checks a shown input when the approval surface supplies one.** The held input is on the reporter's side; the broker holds only its digest. `describe_intent` exposes that digest as `input_digest`, and `approve_intent` takes the digest of what a surface showed as `shown_input_digest`. When it is supplied and does not equal the held input digest read from the stored bytes, the approval is refused, recorded as `deny`/`denied` with the intent's receipts and the approver, and never applied: the intent stays pending. An intent that holds no input digest never matches one. The check binds only a surface that supplies `shown_input_digest`. The two approval surfaces this repository ships supply none: the release CLI shows the coordinate and the digests, and the owner channel shows the coordinate. Neither shows the held input, and an approval through either is accepted unchecked. A surface that renders the held input from the reporter's side is a consumer's to build. Bounded content for an owner who cannot read the reporter's side is left open [ruling: maintainer, 2026-10-12]. |
| **G38** | **The model-facing text is base-owned and closed, and the transport is the event mouth's.** A refusal's `text` is one of two fixed sentences, chosen by whether the call was held, followed by ` Reason: ` and the broker's reason. Refused: "Refused by policy. Do not attempt the same action another way. Tell the user what was refused, and continue with any part of the task this does not affect." Held: "Held for approval by policy (intent `<id>`). Do not attempt the same action another way. Tell the user it is waiting for approval; if it is approved, the same call will be allowed once." A permit's `text` is `null`. Nothing in the request or the manifest supplies or alters it, and it never names the command that releases a hold. `/decide` is served on the tool-event mouth's listener, behind the same guard, authenticator and launch token (G26), entering the runtime through the same `SerializedSurface` on the thread that built it (G27), with its refusals recorded under the same mouth code, `tool-event`. The path is not a setting, and the launch announcement names `/events` only. |

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
in `project` when it was `outside` is trusted wherever the consumer trusts `project`. For a read
the harness's pre-call hook carries to `/decide`, taint lands at the permit, before the read runs
(G35). For a read only reported afterwards, taint lands when the report arrives, not when the read
happened, so an agent that can issue a write between such a read and its report has that window;
whether one exists is the harness's to say.

**An authenticated reporter chooses about 700 bits of every record it causes.** The harness code
(up to 40 characters) and the two digests are the reporter's to pick, and nothing checks that a
digest is a digest of anything: roughly 200 bits from the code and 512 from the digests reach the
tape per report. What bounds it is holding the launch token, and the agent's user can read the
token file, so an agent running as that user can write to the tape through this mouth at will.
What it writes there can add taint and nothing else (G22), and no harness code earns trust until a
consumer names it (G24), but the tape is not evidence that a reported call happened.

**The path is matched after percent-decoding.** The HTTP server underneath decodes the request
path before the application sees it, so `/%65vents` is `/events`. The guard runs first either
way (G26), and the mouth matches the decoded path only.

**The stdio reader frames on `\n` alone.** The gateway reads stdin with a reader of its own
(`server.py`, `_StdinLines`) so that a stop can abandon it (G29). The SDK's reader it replaced
split lines with universal newlines, which also ended a line at a bare `\r`; this one does not.
MCP's stdio framing is newline-delimited, so only a client that does not conform to it is
affected: its messages are read as one line, and fail to parse.

**The turn is in-process.** A report taints the turn of the gateway process it reaches. A harness
whose hooks point at another gateway process, or a launcher that runs two, taints a turn no tool
call of this agent will ever be decided in. One gateway per agent session, its mouth's address
handed to that session's hooks, is the launcher's to arrange.

**Built-in tools are observed, and decided when asked; they are not confined.** The two routes
narrow the gap `docs/posture-ladder.md` names at posture 1; they do not close it. A harness's own
tool is decided only when its hook asks, and the answer binds only as far as the harness enforces
it. A hook that does not fire, fails, or was overwritten, a harness running in a mode that proceeds
without an answer, and anything the agent's user changes in the harness's configuration all leave
that tool ungoverned in exactly the way it was before these routes existed. That gap closes by
containment.

**A release trusts whoever asks with the held input digest.** The harness re-issuing a
byte-identical call after someone approved it is the intended path, and the broker cannot tell
that hook from anything else holding the launch token (G22). A request forged with the held input
digest permits only the forger's own ask: it consumes the approval, and what runs is whatever the
forger's harness then runs. Nothing checks that the input digest is a digest of the input the
harness runs afterwards; it is the adapter's claim, as class and locality are (G30).

**An approval nobody uses may never be recorded.** Approving a held harness call writes no
record, and the expiry sweep reads pending holds only. An approval that lapses unused leaves the
intent `approved` until a later request for the same call finds it past expiry and writes its
`expired` record (G36). That record needs the row to still exist. Retention can remove it first:
the sqlite store's sweep at broker boot deletes an `approved` row once its expiry has passed, with
no grace, and on DynamoDB the time-to-live set when the hold was written (its expiry plus the
pending grace) is not reset on approval, so the row can go once that passes. A request after that
finds no intent and is decided afresh, and no `expired` record is ever written. The tape then holds
the hold and nothing of the approval. No authority flows from it: the lost row is evidence, and a
release needs the row.

**A held call's intent id is reused.** The id is derived from the call, so once one hold of a call
has resolved, the next hold of the same call takes the same id. Each hold's records stay apart by
`storedCallDigest`, which covers the frozen call's timestamp.

**A permit draws the per-op counter and nothing else.** It writes no `observations` label and
draws no error budget, because the broker cannot know whether the harness ran the call or whether
it succeeded. A fault after the permitted record is written (the ledger commit, say) is answered
`refuse`, and the tape then holds the `permitted` record followed by the fault's refusal.

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
  beside `connector:`, why a report can only add taint, and the permitted read that taints at the
  permit.
- [`SCHEMAS.md`](SCHEMAS.md): the reserved coordinate (§2), the `permitted` intent state (§4) and
  the `permitted` record (§5).
- `docs/posture-ladder.md` — the vocabulary the limits above are stated in.
- `docs/contract-vs-reference.md` — why `surface.py` is contract and `server.py` is reference.
- `examples/embedded_agent/` — the consumer the conformance suites compose their runtime from.
