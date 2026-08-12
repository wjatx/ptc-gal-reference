# SCREENING — the injection-screening standard (sa#43)

> **Status: contract (2026-07-08).** Contract-tier per `docs/contract-vs-reference.md`: this
> document is the normative words, `safe_agents/channels/screening.py` is the typed encoding, and
> `safe_agents/channels/tests/test_screening.py` is the conformance suite. The injected `screen`
> seam of the reference dispatcher (`safe_agents/channels/dispatch.py`, reference-tier) is the
> conformance harness. This standard owns gate 7 of the fixed airlock ordering
> (`channels/ADAPTERS.md`) — the gate is *injected there, owned here*. No classifier is named in
> this document: any concrete screen (an LLM classifier, a rules engine, a vendor filter) is
> reference-tier, bound in a consumer repo, and conformant iff it satisfies the clauses below.

## What the screen is — and the one direction it may act

The injection screen is the **only model-judged gate** in the airlock. Every other gate is a
deterministic lookup or check; this one may consult a classifier — typically an LLM — about
*content*. That license comes with the framework's hardest boundary rule
(`channels/TRUST-MAPPING.md`, one-way rule consequence 3):

> **A screen refuses or passes — it never blesses.** Refusal is the screen's only power. A pass
> changes nothing: not the envelope, not the provenance chain, not the derived taint, not the
> `sender_class`. Model judgment may only tighten, never loosen — the model is never the judge in
> the dangerous direction (`broker/TAINT.md` §1).

Screening is **additive** to the provenance model, never a substitute for it. Taint stays derived
from provenance alone (`channels/SCHEMAS.md` §Taint); a message that screens clean is exactly as
tainted afterward as it was before. This resolves the original sa#43 "no content-inspection
heuristics" guard: that guard protects *taint* — which remains content-blind — while the screen
inspects content in the one direction a persuasive payload cannot exploit. An injection that fools
the screen gains only what it already had; an injection that trips it loses delivery.

One asymmetry to name honestly [ruling: maintainer, 2026-08-06]: "loses delivery" is only a win under
abstain-is-safe polarity. A payload crafted to TRIP the screen — hostile-looking content planted in
a legitimate peer's traffic — is the injection-as-DoS attack (`docs/friction-doctrine.md`); the
answer is the watchdog's refusal-flood signal and the consumer's polarity derivation, never a
looser screen.

The screen **ships OFF**. A dispatcher must function with a null screen (pass-through) — the
*position* of the gate is contract (`channels/ADAPTERS.md` §Gate ordering); whether to wire a
screen, and how strict it is, are consumer policy (`docs/friction-doctrine.md`).

## What a screen sees

Position fixes input. The screen is invoked with the typed envelope as of gate 6: schema-valid
(gate 3), unexpired (gate 4), trust-mapped (gate 5), and deduplicated (gate 6) — but not yet
carrying the receiver's provenance hop or resolved `sender_class` (gate 8).

- **Typed input only.** A screen consumes an `EventTrigger`, never raw bytes — the unparsed-payload
  seam is closed upstream (`channels/ADAPTERS.md` §Supersession). Where a raw original matters, it
  lives out-of-band behind `payload_ref`, outside this contract.
- **Read-only.** The envelope is immutable (frozen in the canonical encoding); a screen has no
  mutation channel. Purity is structural, not behavioral discipline.
- **Budget-protected by ordering.** The screen is the one gate that may spend model tokens. The
  fixed ordering guarantees expired, unmapped, and replayed messages never reach it, so screening
  spend is bounded by novel, authenticated, mapped traffic. The budget *mechanism* (caps, windows)
  is deliberately unspecified here — consumer policy, same as strictness.

## ScreenVerdict — what a screen may say

```ts
// STUB — illustrative; the canonical encoding is screening.py
interface ScreenVerdict {
  passed: boolean
  reason: string | null    // refuse: REQUIRED machine code ^[a-z][a-z0-9_]{0,63}$ ; pass: MUST be null
}
// ScreenVerdict.passing()        -> { passed: true,  reason: null }
// ScreenVerdict.refusing(reason) -> { passed: false, reason }
// truthiness == passed, so Callable[[EventTrigger], bool] screens remain conformant
```

Two clauses do the security work:

- **A pass is contentless.** A passing verdict carries no reason, no score, no rationale — nothing
  downstream could interpret as a blessing, cache as a safety assertion, or launder into a trusted
  record. The canonical encoding rejects construction of a pass carrying a reason.
- **A refusal's reason is a closed-vocabulary machine code, never free text.** Refuse reasons
  validate against `^[a-z][a-z0-9_]{0,63}$` — structurally incapable of carrying prose. The drop
  log is trusted, human-read surface; model free-text derived from an untrusted message is itself
  untrusted content, and writing it there would hand an injected payload a path into exactly the
  audit trail that exists to catch it. A screen maps its classifier's output onto its declared code
  set deterministically; output that maps to no code resolves as an error (below), never as a code
  minted at runtime.

The base reserves two codes: `injection_suspected` (the canonical suspicion verdict) and
`screen_error` (reserved for the seam backstop, below). Consumers extend the vocabulary in their
own screen implementations — declared in config or source, never at runtime.

## Recording — refusals always, passes by opt-in

- **Every refusal is recorded.** A refuse verdict drops the message with reason `screen_refused`
  and the verdict's code in `DropRecord.detail` (`channels/TRUST-MAPPING.md` §DropRecord — the
  `detail` field is this standard's addition, validated to the same machine-code pattern). PII
  discipline is unchanged: identity travels as a digest.
- **The verdict sink is the observability valve, and it ships OFF.** An enabled screen that only
  ever passes is otherwise indistinguishable from a null screen — the "looks enabled but isn't"
  failure `docs/friction-doctrine.md` rule 3 names. The dispatcher therefore accepts an optional
  verdict sink; when provided, **every screen invocation appends exactly one PII-safe
  `ScreenRecord`** (pass and refuse alike: channel type, identity digest, event id, verdict, code,
  timestamp). Unset — the default — nothing is recorded on pass, per allow-and-audit lightness. A
  null screen appends nothing even with a sink wired: no judgment happened, so there is nothing to
  record.
- **A pass record is evidence a check RAN, never a content endorsement** [ruling: maintainer, 2026-08-06].
  Any surface that renders it (an approval queue, a review UI) must present it as "screened: no
  refusal", never as a trust signal — a displayed "pass" is how a never-blessing screen becomes a
  de-facto blesser in a reviewer's mind (the M5 complacency discipline, applied to verdict
  evidence).

## The seam fails closed

An exception escaping the screen callable is resolved by the dispatcher as
`refusing("screen_error")` — recorded like any refusal, dedupe-marked like any handled message (a
replay of the message that crashed the screen does not re-run it). The backstop exists because the
alternative polarity is the worst one: a screen that silently passes during its own outage looks
enabled and isn't.

Fail-*open* remains available — as a choice, made inside the screen: an implementation that prefers
availability catches its own errors and returns a pass. What the contract forbids is the *silent*
version, where infrastructure failure is indistinguishable from a clean verdict. Choosing to gate
means choosing what happens when the gate is down; wiring a screen is opting into its failure mode.

## The classifier boundary — the LLM only suspects

The gate condition is falsiness of the verdict — a deterministic predicate over a typed,
schema-validated value. No model output reaches the drop decision except through `ScreenVerdict`,
and no `ScreenVerdict` state can do anything but drop-or-continue. This is the deterministic-gate
invariant (sa#44) instantiated for gate 7:

- The classifier — if there is one — runs *inside* the screen and only ever produces suspicion.
- The gate — drop or continue — is dispatcher code, pure over the verdict.
- Provenance-derived taint neither consults the screen nor yields to it: derived taint is computed
  from the chain alone, identically before and after the screen (`channels/SCHEMAS.md` §Taint), and
  the escalation floor for tainted external writes (`broker/TAINT.md` §5) fires with or without a
  screen in the pipeline. A deployment with no screen keeps every taint property; the screen is
  defense in depth, never a taint dependency.

## Provenance categories, reconciled

The original sa#43 body named three provenance categories. They predate `broker/TAINT.md` and the
provenance chain; this table is the normative mapping, and the categories are retired in favor of
the landed vocabulary:

| Original category | Landed vocabulary | Default posture |
|---|---|---|
| `internal-platform` (broker, grant store, infra APIs) | the `internal:` source namespace (`broker/TAINT.md`) | trusted in the base `InputTrustMap`; never taints |
| `external-service` (any connector result) | `connector:{tool}.{op}` self-ingested sources (`broker/TAINT.md` §1) and non-`internal:` chain sources (`email:…`, `channel:…`, `peer:…`) | untrusted; taints the turn. The only exemption is `Envelope.trusted_read_sources` (sa#137) — consumer-declared, per connector-op, config not model output |
| `human-channel` (approval path, operator command) | not a namespace — a **sender class** at the airlock: `owner`, transport-authenticated (gate 1) and trust-mapped (gate 5) | the hop is `trusted`, but authenticity never cleans content: an owner forwarding external content taints exactly per the chain (one-way rule 1) |

The categories' original intent — trust is opt-in at ingestion, based on provenance, never content
inspection — is exactly what landed; only the taxonomy moved.

## Conformance

| Clause | Test (`test_screening.py`) |
|---|---|
| refuse reasons are closed-vocabulary machine codes | `test_refusing_requires_machine_code_reason` |
| a pass is contentless (no reason survives construction) | `test_pass_is_contentless` |
| refusal → no emit, `screen_refused` drop with the code in `detail` | `test_verdict_refusal_drops_with_detail` |
| bool screens remain conformant (compat clause) | `test_bool_screen_remains_conformant` |
| escaped screen exception fails closed as `screen_error`, dedupe-marked | `test_raising_screen_fails_closed` |
| verdict sink records every invocation, pass and refuse, PII-safe | `test_verdict_sink_records_pass_and_refuse` |
| sink ships OFF; null screen appends nothing | `test_verdict_sink_ships_off_and_null_screen_appends_nothing` |
| a pass never blesses: derived taint identical through a passing screen | `test_pass_never_blesses_taint` |
| `DropRecord.detail` validates the machine-code pattern | `test_drop_record_detail_is_validated` |
| position/budget protection: expired, unmapped, replays never reach the screen | lands with the #80 suite: `test_expired_envelope_drops_before_screen` · `test_unmapped_sender_never_reaches_screen` · `test_replay_is_a_noop` (`test_adapters.py`) |

## Relationships

- `channels/ADAPTERS.md` (sa#80) — gate 7's position and the "injected, not owned" clause.
  Injected there, owned here.
- `channels/TRUST-MAPPING.md` (sa#81) — the one-way rule whose consequence 3 is this standard's
  boundary; the DropRecord type (`detail` added by this standard).
- `channels/SCHEMAS.md` (sa#74) — the envelope a screen consumes; §Taint's derived-taint rules,
  which the screen can never influence.
- `broker/TAINT.md` — §1 "the model is never the judge"; §5 the escalation floor that holds with
  or without a screen.
- sa#44 — the deterministic-gate invariant (`docs/deterministic-gate.md`); this standard is its
  reference instantiation for gate 7.
- Reference classifier binding — deliberately absent. The first concrete screen (e.g. a Bedrock
  classifier) lands consumer-side or as a named reference component in a later pass, never in
  these clauses.
