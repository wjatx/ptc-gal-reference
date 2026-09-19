"""broker.pdp.engine — the pure, deterministic policy decision function.

decide(call: BrokeredCall, facts: Facts) -> Decision

No I/O, no LLM, no DynamoDB in this path. The function is pure predicate
dispatch over a declared, executable rule table. Callable in unit tests with
in-process Facts; same inputs always produce the same Decision.

Rule table — evaluated in priority order, first match wins:
  1.  no_grant                     — defensive: principal has no grant for this tool
  2.  error_budget_escalate        — WRITE: error budget breached, escalation budget available
  3.  error_budget_deny            — WRITE: error budget breached, escalation budget exhausted
  4.  confidence_below_bar_escalate — WRITE: below the confidence bar, escalation budget available
  5.  confidence_below_bar_deny    — WRITE: below the confidence bar, escalation budget exhausted
  6.  read_query_exfil_deny        — read: query egress byte cap / period budget exceeded
  7.  read_rung_gate               — read: in-loop external read from an untrusted source
  8.  cap_budget_breached          — capacity / rate budget breached (reads now draw it too)
  9.  read_allow                   — read: all read guards above passed → allow
  10. transform_to_safer_op        — PIP supplied a safer op; downgrade the write
  11. tainted_external_write       — prompt-injection cut: taint + external + write
  12. external_irreversible        — high-blast: external + irreversible → require_approval
  13. in_loop_write                — in-loop: every write needs explicit human approval
  14. supervised_write_allow       — on-loop / out-of-loop write: allow (guards above passed)
  (fallback)                      — default-deny: write with no permitting rule matched

Reads (sa#137): the former blanket ``read_allow_by_scope`` (old rule 2) is gone. A
read now flows through the query-exfil deny, the in-loop rung-gate (routed through the
single polarity seam ``_approval_or_deny``), and the SHARED capacity budget before
``read_allow`` grants it — so a read is rung-gated, capped, and egress-bounded, not
waved through on grant presence alone. The error-budget rules (2/3) are write-scoped:
the error budget is Σ(error_prob × blast_radius) and a read carries no blast radius,
so a read does not draw it (test_pdp B4). Old rule 2 short-circuited reads above the
error-budget rules, making them write-only in practice; the explicit effect guard
preserves that read behavior now that the short-circuit is gone, and leaves every
write OUTCOME unchanged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable

from safe_agents.broker.schemas import (
    Abstain,
    Allow,
    BrokeredCall,
    Decision,
    Deny,
    RenderedIntent,
    RequireApproval,
    Transform,
)
from safe_agents.broker.schemas.common import AutonomyLevel

from .facts import Facts


# ---------------------------------------------------------------------------
# Helpers — pure, no I/O
# ---------------------------------------------------------------------------


def _intent_id(call: BrokeredCall) -> str:
    """Derive a stable intent ID from the call. Same call → same ID. Pure, no I/O.

    The principal is bound into the id explicitly, not left recoverable through
    ``turnId``. Turn identity is broker-owned, so inside the issuing broker the turn
    log does map a turnId back to one principal. A verifier that does not share that
    broker's turn log (a second broker on a shared intent table, an auditor reading
    the tape, a channel relaying ``/approve <id>``) cannot make that mapping, and
    to it an id that omits the principal names an action without naming who it
    acts for. The key mirrors ``approval.queue_guard.dedup_intent_id`` and
    ``enforcement.store.scoped_counter_key`` (agentId#skill#user#tier), so the
    three principal-scoped ids agree on what "the same principal" means.

    Release does not rely on this id for integrity: ``storedCallDigest`` binds the
    whole frozen call and the PEP's foreign-principal guard runs before any
    transition. This makes the id itself say the same thing they do.
    """
    # Spelled field-by-field (not via a local alias) so test_pdp_corpus's AST
    # read-surface guard sees exactly which principal fields the engine reads.
    principal_key = (
        f"{call.principal.agentId}#{call.principal.skill}"
        f"#{call.principal.user}#{call.principal.tier}"
    )
    raw = f"{principal_key}:{call.session.turnId}:{call.tool}:{call.op}:{call.ts}"
    return "intent-" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def _approval(call: BrokeredCall, reason: str) -> RequireApproval:
    """Materialize a RequireApproval decision with a deterministic intent reference."""
    return RequireApproval(
        kind="require_approval",
        # Carried as a FIELD as well as inside the render, so the audit tape can
        # state why a call was held without a reader parsing prose (#300).
        reason=reason,
        renderedIntent=RenderedIntent(
            id=_intent_id(call),
            renderedForHuman=(
                f"{reason}: {call.principal.agentId} requests "
                f"{call.tool}.{call.op} "
                f"(external={call.manifest.external}, reversible={call.manifest.reversible})"
            ),
        ),
    )


def _approval_or_deny(call: BrokeredCall, facts: Facts, reason: str) -> Decision:
    """Return require_approval if a human is reachable; deny otherwise.

    THE single polarity seam. Every rule that must fall back when it cannot act
    autonomously (in-loop write, tainted/irreversible external write, and the
    sa#137 in-loop external read rung-gate) routes through HERE — no caller may
    bake its own require_approval-vs-deny fallback. The polarity-design workstream
    will make this dispatch on ``Envelope.polarity`` (abstain-is-safe vs
    positive-safe-action) at this one point; keeping the fallback centralized is
    what lets that land without touching any rule. (Deny/approval literals live
    only in ``_approval`` and this helper; the rules never construct their own.)
    """
    if facts.human_reachable:
        return _approval(call, reason)
    return Deny(kind="deny", reason=f"{reason}; no human reachable for approval")


# ---------------------------------------------------------------------------
# Rule table — declared, executable, parametrized
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """A named policy rule: (name, predicate, action).

    Predicate and action are pure functions of (BrokeredCall, Facts).
    RULES is the single source of truth for policy; unit tests drive it directly.
    """

    name: str
    predicate: Callable[[BrokeredCall, Facts], bool]
    action: Callable[[BrokeredCall, Facts], Decision]


RULES: list[Rule] = [
    # 1. Defensive guard: a grant must be present for this (principal, tool).
    #    The PEP's capability-scoped registry prevents absent tools from arriving,
    #    but we check here so a mis-wired PEP fails closed rather than open.
    Rule(
        name="no_grant",
        predicate=lambda c, f: not f.grant_present,
        action=lambda c, f: Deny(kind="deny", reason="tool not granted to this principal"),
    ),
    # 2. Error budget breached, escalation channel still available.
    #    Surface to a human rather than silently proceeding or denying.
    #    Write-scoped (sa#137): the error budget is Σ(error_prob × blast_radius); a read
    #    carries no blast radius, so it does not draw the error budget (test_pdp B4). Before
    #    sa#137 rule 2 (read_allow_by_scope) short-circuited every read above this rule, so
    #    error-budget was write-only in PRACTICE; deleting that short-circuit means reads
    #    would otherwise fall into these rules, so the effect guard makes that write-scoping
    #    explicit and preserves the read behavior exactly. Write OUTCOMES are unchanged
    #    (writes always carry effect=="write"). See engine docstring for the read/write split.
    Rule(
        name="error_budget_escalate",
        predicate=lambda c, f: (
            c.manifest.effect == "write"
            and f.error_budget_breached
            and f.escalation_budget_available
        ),
        action=lambda c, f: Abstain(
            kind="abstain",
            escalate=True,
            reason="error budget breached; escalating for human review",
        ),
    ),
    # 3. Error budget breached, escalation budget also exhausted — deny outright.
    #    Write-scoped for the same reason as rule 2 (reads carry no blast radius).
    Rule(
        name="error_budget_deny",
        predicate=lambda c, f: (
            c.manifest.effect == "write"
            and f.error_budget_breached
            and not f.escalation_budget_available
        ),
        action=lambda c, f: Deny(
            kind="deny", reason="error budget breached; escalation budget exhausted"
        ),
    ),
    # 4-5. Constructed confidence below the configured bar (#184). Write-scoped: the
    #    bar gates ACTS, never reads — a read gates at its rung (sa#137) and carries
    #    no blast radius, so it is not routed here (the effect=="write" guard mirrors
    #    rules 2/3). This pair mirrors the error-budget pair exactly: below-bar is the
    #    PER-CALL gate (does THIS action clear the bar), the error budget is the
    #    CUMULATIVE one (has the period's Σ error_prob × blast_radius spent out) —
    #    GAL §7's two mechanisms. The abstain verb is the per-agent SAFE response under
    #    an abstain-is-safe polarity; the polarity-design workstream will centralize
    #    that dispatch at the _approval_or_deny seam (see its docstring). The base ships
    #    the WIRING here, never the polarity — baking a below-bar polarity default in
    #    is the latent safety bug CLAUDE.md forbids (#184).
    Rule(
        name="confidence_below_bar_escalate",
        predicate=lambda c, f: (
            c.manifest.effect == "write"
            and f.confidence_below_bar
            and f.escalation_budget_available
        ),
        action=lambda c, f: Abstain(
            kind="abstain",
            escalate=True,
            reason="constructed confidence below bar; escalating for human review",
        ),
    ),
    Rule(
        name="confidence_below_bar_deny",
        predicate=lambda c, f: (
            c.manifest.effect == "write"
            and f.confidence_below_bar
            and not f.escalation_budget_available
        ),
        action=lambda c, f: Deny(
            kind="deny",
            reason="constructed confidence below bar; escalation budget exhausted",
        ),
    ),
    # 6. Read: query-egress bound exceeded (sa#137). The agent-composed query string
    #    egresses to the search provider — a covert exfil channel. Deny before the read
    #    executes when it breaches either the per-call byte cap (max_query_bytes) or the
    #    per-period cumulative budget (query_egress_budget). Ordered before the rung-gate
    #    and cap so an over-budget read never reaches the provider on any rung.
    Rule(
        name="read_query_exfil_deny",
        predicate=lambda c, f: (
            c.manifest.effect == "read"
            and (f.query_bytes_exceeded or f.query_egress_breached)
        ),
        action=lambda c, f: Deny(kind="deny", reason="query egress bound exceeded"),
    ),
    # 7. Read: in-loop external read rung-gate (sa#137). An in-loop grant means every
    #    action needs a human; that must bind reads too, not only writes — an external
    #    read pulls untrusted content across a trust boundary. A read whose source is in
    #    the consumer's trusted_read_sources set (read_source_trusted) or held at on/
    #    out-of-loop falls through to the cap check and read_allow. Routes through the
    #    single polarity seam — no bespoke fallback here.
    Rule(
        name="read_rung_gate",
        predicate=lambda c, f: (
            c.manifest.effect == "read"
            and c.manifest.external
            and f.grant_level == AutonomyLevel.in_loop
            and not f.read_source_trusted
        ),
        action=lambda c, f: _approval_or_deny(c, f, "in-loop external read requires approval"),
    ),
    # 8. Capacity / rate budget breached. Reads now draw this cap too (sa#137): the
    #    former read_allow_by_scope short-circuited before this rule, leaving reads
    #    uncapped — deleting it routes reads through here.
    Rule(
        name="cap_budget_breached",
        predicate=lambda c, f: f.cap_budget_breached,
        action=lambda c, f: Deny(kind="deny", reason="capacity budget breached"),
    ),
    # 9. Read: all read-path guards above (exfil bound, rung-gate, capacity) passed →
    #    allow. The error-budget rules are write-scoped, so a read reaches here without
    #    drawing them. Placed after the cap rule so a read is capped, and before the
    #    write-path rules so it never falls through to a write predicate.
    Rule(
        name="read_allow",
        predicate=lambda c, f: c.manifest.effect == "read",
        action=lambda c, f: Allow(kind="allow"),
    ),
    # 10. Transform: the PIP has supplied a safer op to substitute (e.g. send→draft).
    #    Fires only on untainted external reversible writes — tainted external writes
    #    must go through require_approval (rule 11), not a silent downgrade.
    Rule(
        name="transform_to_safer_op",
        predicate=lambda c, f: (
            f.transform_op is not None
            and c.manifest.effect == "write"
            and c.manifest.external
            and c.manifest.reversible is not False
            and not c.taint.tainted
        ),
        action=lambda c, f: Transform(kind="transform", op=f.transform_op, args=c.args),
    ),
    # 11. Tainted turn + external write: the structural prompt-injection cut.
    #    "Read this email, then wire the money" cannot fire autonomously however
    #    persuasive the email. Taint propagates from untrusted sources at ingestion;
    #    the model never judges whether content looks malicious.
    Rule(
        name="tainted_external_write",
        predicate=lambda c, f: (
            c.taint.tainted and c.manifest.external and c.manifest.effect == "write"
        ),
        action=lambda c, f: _approval_or_deny(c, f, "tainted external write"),
    ),
    # 12. External + NOT recoverable (high-blast): require_approval always.
    #    reversible=False means a mistake is both irreversible AND unbounded — e.g.
    #    payments.transfer, email.send. An op that is unrecoverable-but-bounded (a fixed
    #    broker-held destination, like notify.send) is reversible=True and does NOT fire
    #    here; it's allowable autonomously on an untainted turn (rule 14).
    Rule(
        name="external_irreversible",
        predicate=lambda c, f: (
            c.manifest.external
            and c.manifest.reversible is False
            and c.manifest.effect == "write"
        ),
        action=lambda c, f: _approval_or_deny(c, f, "irreversible external write"),
    ),
    # 13. In-loop: the grant contract requires human approval for every write.
    Rule(
        name="in_loop_write",
        predicate=lambda c, f: (
            c.manifest.effect == "write" and f.grant_level == AutonomyLevel.in_loop
        ),
        action=lambda c, f: _approval_or_deny(c, f, "in-loop write requires approval"),
    ),
    # 14. On-loop / out-of-loop: allow. All high-risk cases filtered above.
    Rule(
        name="supervised_write_allow",
        predicate=lambda c, f: (
            c.manifest.effect == "write"
            and f.grant_level in (AutonomyLevel.on_loop, AutonomyLevel.out_of_loop)
        ),
        action=lambda c, f: Allow(kind="allow"),
    ),
]

# Write catch-all: no permitting rule matched → default-deny.
_DEFAULT_DENY = Deny(kind="deny", reason="write: default-deny; no permitting rule matched")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def decide(call: BrokeredCall, facts: Facts) -> Decision:
    """Pure, deterministic policy decision — the PDP entry point.

    Evaluates RULES in priority order and returns the first match.
    No I/O, no LLM, no side effects; callable in pure unit tests with in-process Facts.
    Falls back to _DEFAULT_DENY for any write that no rule explicitly permits.
    """
    for rule in RULES:
        if rule.predicate(call, facts):
            return rule.action(call, facts)
    return _DEFAULT_DENY
