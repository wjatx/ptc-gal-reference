"""Tests for broker.taint — taint propagation and broker-enforcement tie-in.

Covers:
  1. Ingestion marking: untrusted source taints the turn; trusted source does not.
  2. Propagation: tainted TurnContext produces a Taint with tainted=True and correct sources.
  3. Non-strippable: marking tainted cannot be undone within the turn.
  4. Broker-enforcement tie-in: decide() escalates on a tainted external write.
  5. Clean turn: same call without taint proceeds normally (allow).
  6. Memory propagation: memory-layer taint flag taints the turn.
  7. Trust-map injection: the base mechanism accepts any InputTrustMap; none is baked in.
"""


from safe_agents.broker.pdp import Facts, decide
from safe_agents.broker.schemas import BrokeredCall, Taint
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.taint import TurnContext, build_trust_map

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_PRINCIPAL = {"agentId": "agent-x", "skill": "email", "user": "bob", "tier": "B"}
_TS = "2026-06-28T00:00:00Z"

# A trust map that trusts only "internal:" sources; everything else is untrusted.
_TRUST_MAP = build_trust_map(trusted_prefixes=["internal:"])

# An always-deny trust map — useful for verifying the untrusted branch.
_UNTRUSTED_MAP = build_trust_map(trusted_prefixes=[])

# An always-allow trust map — useful for verifying the trusted branch.
_TRUSTED_MAP = build_trust_map(trusted_prefixes=[""])


def _facts(**overrides) -> Facts:
    defaults = {
        "grant_present": True,
        "grant_level": AutonomyLevel.out_of_loop,
        "error_budget_breached": False,
        "cap_budget_breached": False,
        "escalation_budget_available": True,
        "human_reachable": True,
        "transform_op": None,
    }
    defaults.update(overrides)
    return Facts(**defaults)


def _external_write_call(taint: Taint, turn_id: str = "turn-1") -> BrokeredCall:
    """Build an external write (email.send) BrokeredCall with the given Taint."""
    return BrokeredCall.model_validate(
        {
            "principal": _PRINCIPAL,
            "tool": "email",
            "op": "send",
            "args": {"to": "external@example.com", "body": "hello"},
            "manifest": {
                "tool": "email",
                "op": "send",
                "effect": "write",
                "external": True,
                "reversible": True,
            },
            "taint": {"tainted": taint.tainted, "sources": taint.sources},
            "session": {"turnId": turn_id, "ingestedSources": taint.sources},
            "ts": _TS,
        }
    )


# ---------------------------------------------------------------------------
# 1. Ingestion marking
# ---------------------------------------------------------------------------


def test_untrusted_source_taints_turn() -> None:
    """Ingesting from an untrusted source marks the TurnContext tainted."""
    ctx = TurnContext("turn-1")
    ctx.ingest_source("email:inbox/42", _UNTRUSTED_MAP)
    assert ctx.tainted is True


def test_trusted_source_does_not_taint() -> None:
    """Ingesting from a trusted source leaves the TurnContext clean."""
    ctx = TurnContext("turn-2")
    ctx.ingest_source("internal:system-alert", _TRUSTED_MAP)
    assert ctx.tainted is False


def test_mixed_sources_taints_if_any_untrusted() -> None:
    """A turn is tainted as soon as one untrusted source is ingested."""
    ctx = TurnContext("turn-3")
    ctx.ingest_source("internal:heartbeat", _TRUST_MAP)  # trusted
    assert ctx.tainted is False
    ctx.ingest_source("email:inbox/7", _TRUST_MAP)  # untrusted
    assert ctx.tainted is True


# ---------------------------------------------------------------------------
# 2. Propagation: sources are carried in the Taint object
# ---------------------------------------------------------------------------


def test_taint_sources_reflect_ingested_untrusted_sources() -> None:
    """to_taint() must carry the untrusted sources that caused the taint."""
    ctx = TurnContext("turn-4")
    ctx.ingest_source("email:inbox/5", _TRUST_MAP)
    ctx.ingest_source("web:fetch/news", _TRUST_MAP)
    taint = ctx.to_taint()
    assert taint.tainted is True
    assert "email:inbox/5" in taint.sources
    assert "web:fetch/news" in taint.sources


def test_trusted_sources_absent_from_taint_sources() -> None:
    """Trusted sources must not appear in the Taint.sources list."""
    ctx = TurnContext("turn-5")
    ctx.ingest_source("internal:db/users", _TRUST_MAP)
    taint = ctx.to_taint()
    assert taint.tainted is False
    assert "internal:db/users" not in taint.sources


def test_duplicate_source_recorded_once() -> None:
    """Ingesting the same untrusted source twice records it only once."""
    ctx = TurnContext("turn-6")
    ctx.ingest_source("email:inbox/9", _UNTRUSTED_MAP)
    ctx.ingest_source("email:inbox/9", _UNTRUSTED_MAP)
    taint = ctx.to_taint()
    assert taint.sources.count("email:inbox/9") == 1


# ---------------------------------------------------------------------------
# 3. Non-strippable: taint cannot be cleared within the turn
# ---------------------------------------------------------------------------


def test_taint_stripping_attempt_has_no_effect() -> None:
    """Once tainted, the TurnContext stays tainted regardless of what an agent asserts.

    The broker derives taint from TurnContext.to_taint(), not from agent-supplied values.
    An agent that constructs a BrokeredCall with tainted=False while the context is
    tainted is simply ignored — the PEP always calls ctx.to_taint() as the source of truth.
    """
    ctx = TurnContext("turn-strip")
    ctx.ingest_source("email:inbox/1", _UNTRUSTED_MAP)
    assert ctx.tainted is True

    # Simulate an agent/harness attempting to strip by reading the context's taint,
    # asserting false, and building a call — the context is still the authority.
    authoritative_taint = ctx.to_taint()
    assert authoritative_taint.tainted is True, "TurnContext taint is non-strippable"
    assert len(authoritative_taint.sources) > 0

    # Even if someone builds a stripped BrokeredCall in isolation, the authoritative
    # context still shows tainted. The PEP must use ctx.to_taint(), not model values.
    stripped_taint = Taint(tainted=False, sources=[])  # agent's attempt
    assert stripped_taint.tainted is False  # the stripped object is False in isolation

    # The context remains tainted — this is the invariant the PEP enforces.
    assert ctx.tainted is True
    assert ctx.to_taint().tainted is True


def test_taint_stripping_via_new_source_ingest_still_tainted() -> None:
    """Ingesting a trusted source after an untrusted one does not strip taint."""
    ctx = TurnContext("turn-strip-2")
    ctx.ingest_source("email:inbox/2", _UNTRUSTED_MAP)
    ctx.ingest_source("internal:safe", _TRUST_MAP)  # trusted ingestion after taint
    assert ctx.tainted is True


# ---------------------------------------------------------------------------
# 4. Broker-enforcement: decide() escalates on tainted external write
# ---------------------------------------------------------------------------


def test_tainted_turn_external_write_requires_approval() -> None:
    """Ingest from untrusted source, then attempt email.send → require_approval."""
    ctx = TurnContext("turn-enf-1")
    ctx.ingest_source("email:inbox/malicious", _UNTRUSTED_MAP)
    taint = ctx.to_taint()

    call = _external_write_call(taint, turn_id="turn-enf-1")
    decision = decide(call, _facts(human_reachable=True))

    assert decision.kind in ("require_approval", "deny"), (
        f"expected escalation, got {decision.kind!r}: {decision}"
    )


def test_tainted_turn_external_write_denies_when_no_human() -> None:
    """Tainted external write with no human reachable → deny."""
    ctx = TurnContext("turn-enf-2")
    ctx.ingest_source("web:fetch/evil", _UNTRUSTED_MAP)
    taint = ctx.to_taint()

    call = _external_write_call(taint, turn_id="turn-enf-2")
    decision = decide(call, _facts(human_reachable=False))

    assert decision.kind == "deny"


# ---------------------------------------------------------------------------
# 5. Clean turn: same call without taint proceeds normally
# ---------------------------------------------------------------------------


def test_clean_turn_external_write_allowed() -> None:
    """No untrusted sources ingested → email.send is allowed for out-of-loop agent."""
    ctx = TurnContext("turn-clean")
    ctx.ingest_source("internal:scheduled-job", _TRUST_MAP)  # trusted only
    taint = ctx.to_taint()

    assert taint.tainted is False
    call = _external_write_call(taint, turn_id="turn-clean")
    decision = decide(call, _facts(grant_level=AutonomyLevel.out_of_loop))

    assert decision.kind == "allow"


def test_empty_turn_external_write_allowed() -> None:
    """A turn with no ingestion at all is untainted and proceeds normally."""
    ctx = TurnContext("turn-empty")
    taint = ctx.to_taint()

    assert taint.tainted is False
    call = _external_write_call(taint, turn_id="turn-empty")
    decision = decide(call, _facts(grant_level=AutonomyLevel.out_of_loop))

    assert decision.kind == "allow"


# ---------------------------------------------------------------------------
# 6. Memory propagation: memory-layer taint flag taints the turn
# ---------------------------------------------------------------------------


def test_memory_taint_flag_true_taints_turn() -> None:
    """A recalled memory entry with taint_flag=True propagates taint to the current turn."""
    ctx = TurnContext("turn-mem-1")
    ctx.ingest_memory_taint(taint_flag=True, source="memory:entry-abc123")
    assert ctx.tainted is True
    assert "memory:entry-abc123" in ctx.to_taint().sources


def test_memory_taint_flag_false_does_not_taint() -> None:
    """A recalled memory entry with taint_flag=False leaves the turn clean."""
    ctx = TurnContext("turn-mem-2")
    ctx.ingest_memory_taint(taint_flag=False, source="memory:entry-safe")
    assert ctx.tainted is False


def test_memory_tainted_entry_causes_external_write_escalation() -> None:
    """Taint from a recalled memory entry escalates an external write, same as direct taint."""
    ctx = TurnContext("turn-mem-3")
    ctx.ingest_memory_taint(taint_flag=True, source="memory:entry-xyz")
    taint = ctx.to_taint()

    call = _external_write_call(taint, turn_id="turn-mem-3")
    decision = decide(call, _facts(human_reachable=True))

    assert decision.kind in ("require_approval", "deny")


def test_memory_taint_non_strippable() -> None:
    """Taint from memory cannot be cleared by a subsequent clean memory recall."""
    ctx = TurnContext("turn-mem-4")
    ctx.ingest_memory_taint(taint_flag=True, source="memory:bad-entry")
    ctx.ingest_memory_taint(taint_flag=False, source="memory:clean-entry")
    assert ctx.tainted is True


# ---------------------------------------------------------------------------
# 7. Trust-map injection: the base never bakes in a specific trust map
# ---------------------------------------------------------------------------


def test_custom_trust_map_is_respected() -> None:
    """The mechanism accepts any InputTrustMap callable — the base never picks the list."""
    # Agent A trusts CRM but not email
    crm_trust_map = build_trust_map(trusted_prefixes=["crm:"])
    ctx_a = TurnContext("turn-custom-a")
    ctx_a.ingest_source("crm:contact/99", crm_trust_map)   # trusted for A
    ctx_a.ingest_source("email:inbox/1", crm_trust_map)    # untrusted for A
    assert ctx_a.tainted is True
    assert "crm:contact/99" not in ctx_a.to_taint().sources
    assert "email:inbox/1" in ctx_a.to_taint().sources

    # Agent B trusts email but not CRM
    email_trust_map = build_trust_map(trusted_prefixes=["email:"])
    ctx_b = TurnContext("turn-custom-b")
    ctx_b.ingest_source("email:inbox/1", email_trust_map)   # trusted for B
    ctx_b.ingest_source("crm:contact/99", email_trust_map)  # untrusted for B
    assert ctx_b.tainted is True
    assert "email:inbox/1" not in ctx_b.to_taint().sources
    assert "crm:contact/99" in ctx_b.to_taint().sources
