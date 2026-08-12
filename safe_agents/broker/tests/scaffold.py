"""Shared round-trip scaffold for the connector integration tests — the common
Principal/Grant/Facts fixtures used by test_telegram_connector.py,
test_ledger_connector.py, and test_search_connector.py.

Also home to the acceptance-test substrate consumed by later broker-destub
phases (sa#138 Phase 0): a real-hash grant builder, a pre-quarantined grant
store, and a shared-TurnContext threading helper. See test_scaffold.py for
self-tests proving each works against today's code.
"""

from __future__ import annotations

from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.pdp import Facts
from safe_agents.broker.runtime import AgentRequest, BrokerResponse, BrokerRuntime
from safe_agents.broker.schemas import BrokeredCall, Envelope, Grant, compute_envelope_hash
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.taint import TurnContext

PRINCIPAL_DATA = {"agentId": "example-agent", "skill": "advisor", "user": "maintainer", "tier": "B"}
PRINCIPAL = Principal(**PRINCIPAL_DATA)

# A real envelope content-hash for the connector round-trip tests, whose own PIPs do
# not verify it — it is only stamped into the audit records they emit. BrokerRuntime
# requires ``envelope_hash`` (no stub default anymore, sa#122), so these tests pass a
# real one rather than a placeholder literal.
ENVELOPE_HASH = compute_envelope_hash(Envelope(polarity="abstain"))


def make_grant(
    action_class: str,
    *,
    level: AutonomyLevel = AutonomyLevel.on_loop,
    ts: str = "2026-07-02T00:00:00Z",
) -> Grant:
    """Build a test Grant.

    Integrity lives at the store's item level since #246 (stored-bytes basis):
    the Grant carries no hash field, and put_grant computes the item HMAC from
    the canonical payload — a grant written through any store with a matching
    hmac_key always reads back clean.
    """
    return Grant.model_validate(
        {
            "principal": PRINCIPAL_DATA,
            "actionClass": action_class,
            "level": level,
            "envelopeHash": "test-envelope-hash",
            "promotedBy": "human-reviewer",
            "evidence": "test-evidence-ref",
            "ts": ts,
            "lastSafeLevel": "in-loop",
            "demotionTriggers": [],
            "demotionReason": None,
            "labelLatency": "PT1H",
            "ownerId": "owner@example.com",
        }
    )


def make_quarantined_store(
    action_class: str, *, hmac_key: bytes = b"test-hmac-key"
) -> InMemoryGrantStore:
    """Return an InMemoryGrantStore that reads ``action_class`` back quarantined.

    Seeds a grant (put_grant stamps a genuine item-level HMAC over the stored
    bytes), then corrupts the stored data bytes in place so the next
    get_grant() fails stored-bytes verification — the same failure mode the
    store detects in production (an item tampered with, or written under a
    different key).
    """
    store = InMemoryGrantStore(hmac_key=hmac_key)
    store.put_grant(make_grant(action_class))
    # Reach into the store's internals to corrupt the persisted bytes directly —
    # put_grant() always (correctly) stamps a matching HMAC, so tampering has
    # to happen after the write to simulate a corrupted/quarantined item.
    key = store._record_key(PRINCIPAL, action_class)
    item = store._store[key]
    item["data"] = item["data"].replace(f'"{action_class}"', f'"{action_class}-tampered"', 1)
    return store


def run_threaded_turn(
    runtime: BrokerRuntime,
    request_1: AgentRequest,
    request_2: AgentRequest,
    *,
    ingested_sources_1: list[str] | None = None,
    turn_id: str = "test-threaded-turn",
) -> tuple[BrokerResponse, BrokerResponse, TurnContext]:
    """Run two handle_request() calls sharing ONE TurnContext.

    Builds a single TurnContext, ingests ``ingested_sources_1`` before the
    first call, then threads the SAME context into the second call. Returns
    both responses plus the shared context so a caller can assert taint (which
    is non-strippable within one TurnContext instance) rode from call 1 to
    call 2.
    """
    ctx = TurnContext(turn_id=turn_id)
    response_1 = runtime.handle_request(
        request_1, turn_context=ctx, ingested_sources=ingested_sources_1
    )
    response_2 = runtime.handle_request(request_2, turn_context=ctx)
    return response_1, response_2, ctx


def run_across_calls(
    runtime: BrokerRuntime,
    request_1: AgentRequest,
    request_2: AgentRequest,
    *,
    ingested_sources_1: list[str] | None = None,
) -> tuple[BrokerResponse, BrokerResponse]:
    """Run two handle_request() calls WITHOUT threading a TurnContext — the
    cross-/call analog of run_threaded_turn (sa#136).

    This is what two separate ``POST /call`` requests look like on the wire: the
    caller passes no ``turn_context``, so for taint to ride from call 1 to call 2
    the runtime must supply its OWN broker-held session turn. Where
    run_threaded_turn threads one explicit ctx to prove the in-turn mechanism
    (sa#134), this proves the broker OWNS the turn across separate calls — the
    load-bearing sa#136 guarantee.
    """
    response_1 = runtime.handle_request(request_1, ingested_sources=ingested_sources_1)
    response_2 = runtime.handle_request(request_2)
    return response_1, response_2


def make_pip(
    grant_present: bool = True,
    *,
    grant_level: AutonomyLevel = AutonomyLevel.on_loop,
    cap_budget_breached: bool = False,
    human_reachable: bool = True,
    read_source_trusted: bool = False,
    query_bytes_exceeded: bool = False,
    query_egress_breached: bool = False,
):
    """Fixed-Facts PIP for tests. The keyword-only knobs (sa#137) let a caller drive
    the read-gating rules directly; all default to today's behavior so existing
    make_pip() / make_pip(grant_present) call-sites are unchanged."""

    def pip(call: BrokeredCall) -> Facts:
        return Facts(
            grant_present=grant_present,
            grant_level=grant_level,
            error_budget_breached=False,
            cap_budget_breached=cap_budget_breached,
            escalation_budget_available=True,
            human_reachable=human_reachable,
            transform_op=None,
            read_source_trusted=read_source_trusted,
            query_bytes_exceeded=query_bytes_exceeded,
            query_egress_breached=query_egress_breached,
        )

    return pip
