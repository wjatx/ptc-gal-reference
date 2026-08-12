"""Self-tests for the broker/tests/scaffold.py acceptance-test substrate (sa#138
Phase 0). Proves each of the three new helpers works against TODAY's code —
this file must NOT assert any sa#122/sa#124/sa#134 behavior that doesn't exist
yet; later phases' acceptance tests are the ones that will consume these
helpers for real.
"""

from __future__ import annotations

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.runtime import AgentRequest, BrokerRuntime, Doer, FakeSecretsProvider
from safe_agents.broker.runtime.connector import StubConnector
from safe_agents.broker.schemas import ToolOp
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import (
    ENVELOPE_HASH,
    PRINCIPAL,
    make_grant,
    make_pip,
    make_quarantined_store,
    run_threaded_turn,
)

HMAC_KEY = b"test-hmac-key"


# ---------------------------------------------------------------------------
# Helper 1 — make_grant round-trips clean through the store
# ---------------------------------------------------------------------------


def test_make_grant_reads_back_clean():
    """A grant written through put_grant reads back clean: the store stamps
    the item-level HMAC over the stored bytes at write time (#246), so no
    caller-side hash cooperation is needed."""
    store = InMemoryGrantStore(hmac_key=HMAC_KEY)
    store.put_grant(make_grant("crm.list_deals"))

    result = store.get_grant(PRINCIPAL, "crm.list_deals")

    assert result.quarantined is False
    assert result.grant is not None
    assert result.grant.actionClass == "crm.list_deals"
    assert result.stored_hash is not None
    assert result.raw_data is not None


# ---------------------------------------------------------------------------
# Helper 2 — make_quarantined_store
# ---------------------------------------------------------------------------


def test_make_quarantined_store_reads_back_quarantined():
    store = make_quarantined_store("crm.list_deals", hmac_key=HMAC_KEY)

    result = store.get_grant(PRINCIPAL, "crm.list_deals")

    assert result.quarantined is True
    assert result.quarantine_reason is not None
    # Tampered bytes are never parsed (#246): grant is None, the raw bytes
    # ride on the result for audit.
    assert result.grant is None
    assert result.raw_data is not None


def test_make_quarantined_store_other_action_classes_unaffected():
    """Only the seeded action_class is corrupted; an absent one still reads as
    a plain miss (grant=None, not quarantined)."""
    store = make_quarantined_store("crm.list_deals", hmac_key=HMAC_KEY)

    result = store.get_grant(PRINCIPAL, "search.query")

    assert result.grant is None
    assert result.quarantined is False


# ---------------------------------------------------------------------------
# Helper 3 — run_threaded_turn
# ---------------------------------------------------------------------------


def _make_runtime(sink: InMemorySink, connector_result=None) -> BrokerRuntime:
    doer = Doer(
        connectors={"crm": StubConnector(result=connector_result)},
        secrets=FakeSecretsProvider({"crm": "test-crm-credential"}),
    )
    return BrokerRuntime(
        principal=PRINCIPAL,
        grants=[make_grant("crm.list_deals")],
        optable=ToolOpTable([ToolOp(tool="crm", op="list_deals", effect="read", external=False)]),
        doer=doer,
        pip=make_pip(),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
    )


def test_run_threaded_turn_shares_taint_across_both_calls():
    """Two handle_request() calls threaded through one TurnContext: both
    succeed, and taint ingested before call 1 is still set on the SAME
    context after call 2 — proving taint rides across calls rather than
    resetting per-request (the non-strippable invariant TurnContext
    documents)."""
    sink = InMemorySink()
    runtime = _make_runtime(sink)

    request_1 = AgentRequest(
        tool="crm",
        op="list_deals",
        args={},
        idempotency_key="test:threaded-1",
    )
    request_2 = AgentRequest(
        tool="crm",
        op="list_deals",
        args={},
        idempotency_key="test:threaded-2",
    )

    response_1, response_2, ctx = run_threaded_turn(
        runtime,
        request_1,
        request_2,
        ingested_sources_1=["email:untrusted-inbox"],
    )

    assert response_1.decision_kind == "allow"
    assert response_2.decision_kind == "allow"
    # Untrusted source (not under the "internal:" trusted prefix) taints the
    # turn on ingestion, and TurnContext taint is non-strippable within the
    # instance — so it is still set after the second call shares the context.
    assert ctx.tainted is True
    assert "email:untrusted-inbox" in ctx.to_taint().sources


def test_run_threaded_turn_without_ingestion_stays_untainted():
    """Sanity check on the helper itself: with no ingested sources, the shared
    context stays untainted across both calls."""
    sink = InMemorySink()
    runtime = _make_runtime(sink)

    request_1 = AgentRequest(
        tool="crm", op="list_deals", args={}, idempotency_key="test:threaded-clean-1"
    )
    request_2 = AgentRequest(
        tool="crm", op="list_deals", args={}, idempotency_key="test:threaded-clean-2"
    )

    _, _, ctx = run_threaded_turn(runtime, request_1, request_2)

    assert ctx.tainted is False
