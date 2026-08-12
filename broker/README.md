# broker — the deterministic tool broker

The architectural center of safe-agents. Not the agent, not a "doer": the **deterministic
component between the agent and every side-effecting tool**, which the agent cannot modify, that
decides what actually happens and records that it happened.

> One rule the whole design turns on: *the agent may request anything; a deterministic component it
> cannot modify decides what actually happens, and records that it happened.*
> (`auto-agents/tool-broker-sketch.md`, opening.)

This README is the orientation. The canonical field-by-field contract is `SCHEMAS.md`; the autonomy
state machine is `grant-lifecycle.md`; strictly-attenuating delegation to sub-agents is
`sub-grants.md`; the ordered build plan and AWS mapping is `BUILD.md`. The deeper *why* lives in
the `auto-agents` corpus — this doc references its sections rather than restating them.

## The three invariants

The substrate enforces these in **every** compute mode; they hold even if the agent process is
fully compromised. "A compromised agent can still only ask." (`ARCHITECTURE.md` §"The broker is the
center"; `tool-broker-sketch.md` §"Trust zones".)

1. **The agent holds no connector credentials.** They live only in the broker's secret store. A
   jailbroken or prompt-injected agent can still only *ask* the broker.
2. **The agent's only egress is the broker** — enforced at the network layer (security group /
   subnet / VPC / container network policy), never in code the agent runs. "Call the API directly"
   must not be a path that exists. (Model inference at `api.anthropic.com` is not a connector; the
   broker mediates *tools/actions*, not the model's brain.)
3. **The broker runs under a separate IAM identity** from the agent — different role, ideally a
   different process / container / task, so a code-exec bug in the harness does not hand over the
   credential store.

Invariants 1–2 are *structural* and do most of the work before any policy logic runs. They
implement **Pillar 2 — Least Capability**: capabilities are removed, not restrained. Invariant 3
plus the audit (below) implement **Pillar 3 — External Audit**.

## Trust zones

The broker's value is entirely about which zone holds what. Credentials and enforcement move out of
the probabilistic zone; the agent keeps judgment and nothing else.

```
  UNTRUSTED            PROBABILISTIC                 TRUSTED / DETERMINISTIC          EXTERNAL
  inbound data    |    agent process            |   tool broker (PEP)            |   connectors
                  |                             |                                |
  email body  --->|  LLM + harness + skills     |   • holds ALL credentials      |  Gmail
  web content     |  • makes judgments          |   • PDP: allow/deny/xform/hold |  CRM
  CRM notes       |  • NO connector creds       |   • append-only audit (WORM)   |  Stripe
  inbound msgs    |  • egress: broker ONLY ----->   • approval queue --> human    |  Calendar
                  |  • requests, never executes |   • counters, caps, taint      |
```

(`tool-broker-sketch.md` §"Trust zones".) The agent *requests*; it never *executes*.

## Components — standard authorization vocabulary

This is policy enforcement; it uses the standard PEP/PDP/PIP/PAP terms. (`tool-broker-sketch.md`
§"Components".)

- **PEP — Policy Enforcement Point:** the broker/proxy itself, inline on every tool call. Speaks the
  tool protocol (e.g. MCP) to the agent on one side and the real connectors on the other. The
  agent's entire tool registry is *served by the PEP* (see capability-scoped registry).
- **PDP — Policy Decision Point:** a **pure, deterministic** function `(call, facts) → decision`. No
  LLM in the path. Unit-testable against a table of cases. Implements **Pillar 1 — Deterministic
  Enforcement**.
- **PIP — Policy Information Point:** supplies facts the decision needs that aren't in the request —
  is this customer restricted, how much spent against today's cap, is a human reachable. Determinist
  lookups (DynamoDB counters, allowlists).
- **PAP — Policy Administration Point:** where policy is authored. **Policy is code/config in git,
  reviewed like any other code.** "Write authority is a ceremony" becomes a pull request, literally.

## The request → decision → audit flow

1. The agent calls a tool it was served. The **PEP materializes** the call into a typed
   `BrokeredCall` envelope — the PDP never sees free text. Crucially, `effect` / `external` /
   `reversible` come from the agent's **`ToolOpTable`** — classified once in the consumer's
   `AgentManifest.tool_ops` (#171), *never* from anything the model says: the model doesn't get to
   assert its `send` is really a `draft`.
2. The PEP gathers `facts` from the PIP (counters, allowlists, reachability, constructed
   confidence).
3. The **PDP decides** — one of five verbs, default-deny (below).
4. The PEP **executes** the decision: runs the connector with broker-held credentials, or
   transforms, or persists an `Intent` for approval, or denies/abstains.
5. The **broker emits the AuditRecord** — at the moment of side effect, to a store the agent has no
   credentials to modify (see audit, below).

The full schemas for `BrokeredCall`, `Decision`, `Intent`, and `AuditRecord` are in `SCHEMAS.md`.

## The five verbs, default-deny

`decide()` returns exactly one of (`tool-broker-sketch.md` §"The decision"):

| Verb | Meaning |
|---|---|
| `allow` | Execute the typed manifest op verbatim. |
| `deny` | Refuse, with a reason. |
| `transform` | Substitute a safer **op** and execute that — e.g. `send → draft`. Op substitution only; `args` pass through verbatim. |
| `require_approval` | Hold for out-of-band human approval (below); the turn ends. |
| `abstain` | Decline as out-of-competence or inputs-suspect; optionally `escalate`. A first-class outcome, **not** a failure. |

Governing rules:

- **Default-deny for anything `effect:"write"`.** Reads are allow-by-scope.
- **An external `write` inside a tainted turn** defaults to `require_approval` or `deny` — the
  prompt-injection cut. "Read this email, then wire the money" cannot fire autonomously, however
  persuasive the email. (Taint, below.)
- **High-blast / irreversible classes** (e.g. `payments.*`) → `require_approval` always, with a
  what-you-see-is-what-executes render.
- **Cap breach** (a PIP atomic counter) → `deny` / escalate.
- **Anything not in the principal's grant never reaches `decide()` at all** — it isn't exposed.

Express the ruleset in code, or in a real policy engine (**Cedar**, **OPA/Rego**) so it is itself
reviewable and unit-tested. The safe-default *polarity* (abstain-is-safe vs a positive safe action)
is **never** baked in here — it is re-derived per agent (`ARCHITECTURE.md` §"The one thing that must
NEVER be in the base"; **Pillar cross-cut: Non-generalization**).

## Capability-scoped registry — removal over request

> Don't tell an agent not to use a tool. Don't give it the tool.

The PEP serves each principal a capability-scoped tool list. The restricted agent's served registry
contains no `email.send`, no `payments.*` — the capability doesn't exist in its world, so no prose,
model error, or injection can reach it. Scope is grant-based and lives in policy, so adding a
capability is a reviewed change. This is the difference between "the model chose not to" and "the
model could not." (`tool-broker-sketch.md` §"Capability removal"; **Pillar 2**.)

## Out-of-band approval — what-you-see-is-what-executes

`require_approval` must never return to the agent and trust it to wait.

1. The PEP **materializes** the exact request it would execute (the rendered email, the real
   recipient, the real dollar amount) and persists it as an **`Intent`** record (`SCHEMAS.md` §4).
   Fields: `id`, `materializedRequest` (the frozen `BrokeredCall`), `renderedForHuman`,
   `status:"pending"`, `expiry`, `approvedBy`, `ts`. Stored in DynamoDB.
2. The PEP returns `{ status:"pending", intentId }` to the agent. **The turn ends.** The agent has
   no tool that approves intents; it cannot self-release.
3. A separate notifier pushes the *materialized* intent (`renderedForHuman`) to the human's channel.
4. The human approves through a path authenticated to **them, not the agent**. On approval the
   broker executes the **stored `materializedRequest`** — never anything the agent re-sends.
5. Unapproved intents auto-deny at expiry; the `Intent.status` moves to `expired`.

The load-bearing property is **what-you-see-is-what-executes**: the human approves the bytes the
broker will actually send, not a summary the agent wrote. A compromised agent can stage a
benign-looking summary and a malicious payload; approve the payload, never the summary.
(`tool-broker-sketch.md` §"Out-of-band approval"; **Pillar 5 — Bounded Human Governance**.)

## Audit — broker-emitted, append-only, agent can't touch it

This inverts the usual trust hierarchy where the agent writes its own log. The record of record is
written by the layer that performs the side effect, at the moment it performs it, to a store the
agent has no credentials to modify.

- **Every** decision is logged — allows, denies, transforms, approvals, failures.
- **Append-only / write-once** at the storage layer (S3 Object Lock / WORM, or an append-only log
  fronted by a role the agent doesn't hold). Not "the agent promises to log."
- **Hash-chained** (`prevHash → hash`) so any later deletion or edit is detectable; any gap shows.
- Any human-readable activity log is a **projection** of this log; the log itself is the source of
  truth.

This also fixes the local/small-model case: the audit doesn't weaken when sensitive work runs on a
smaller model, because the small model was never the thing writing the audit. (`tool-broker-sketch.md`
§"Audit"; **Pillar 3**.) Full record schema in `SCHEMAS.md`.

## Taint tracking — the structural injection defense

Taint is a deterministic, source-based computation; the model never judges whether content "looks
malicious." Data from untrusted sources (inbound email bodies, web fetches, CRM free-text,
non-allowlisted senders) is marked tainted at ingestion; the flag rides the turn; any result derived
from tainted input keeps the mark. Policy keys on it (an external write in a tainted turn →
`require_approval`/`deny`). Untrusted content can still *inform* a draft; it can't *trigger* an
autonomous external action. (`tool-broker-sketch.md` §"Taint tracking"; memory is a taint *source* —
see `../memory/`.) **Pillar 6 — Adversarial Robustness.**

## Minimum viable vs full — the adoption split

You don't need all of it on day one. Ranked by security-per-unit-effort (`tool-broker-sketch.md`
§"Minimum viable vs full"). For a **low-risk agent**, build the MVP and stop; defer the rest. For a
**high-stakes / adversarial agent**, the deferred tiers become mandatory.

| Tier | What | Build first for… |
|---|---|---|
| **MVP (the 80%)** | Broker holds creds; agent egress = broker only; default-deny on writes; capability-scoped tool lists; broker-emitted append-only audit. | **Every** agent. Moves enforcement out of the model and gives a real tape. |
| **Then** | Out-of-band approval queue (WYSIWYE); durable spend/rate counters. | Any agent with an external write. |
| **Then** | Taint tracking; hash-chained tamper-evidence; a real policy engine (Cedar/OPA). | Agents reading untrusted inbound data. |
| **Then (autonomy ratchet)** | Autonomy-level-as-state: recorded maker-checker promotion + automatic hysteretic demotion. See `grant-lifecycle.md`. | Agents graduating off "human approves every write." |
| **Last (high-stakes only)** | Constructed confidence + drift detection; corroboration quorum; robust-randomized allocation with auditable seeds. | Only when an adversary shapes inputs or actions draw on a scarce resource. Skip for a benign personal-assistant load. |

This is **Proportionality** (the cross-cut): match the rigor to the blast radius; the heavy
machinery belongs at the irreversible, high-consequence boundary.

## What this deliberately does NOT solve

Honesty about the residual surface (`tool-broker-sketch.md` §"What this deliberately does NOT
solve"): read-side exfiltration is harder than write-side (scope reads too); the broker is now the
crown-jewel target (one hardened thing to defend, vs creds smeared everywhere); it can't stop a
human approving a bad thing (WYSIWYE reduces but doesn't eliminate social engineering); policy
completeness is on you (default-deny contains omissions, but an over-broad rule is still a footgun —
which is why policy is reviewed code); constructed confidence is still an estimate; the game model
can be wrong (drift detection is the backstop, not a guarantee).
