"""Tests for sa#124 — quarantined-grant surfacing at the PEP's single detection point.

Today a quarantined grant (HMAC mismatch — tampering, mis-seeded key, or key-
rotation drift) was silently downgraded to "absent": the deny that followed
looked byte-for-byte identical to an un-provisioned capability. A tamper event
must never be inferable only from a quieter registry line.

The fix keeps the PIP PURE (it merely carries the quarantine signal up on the
returned Facts) and surfaces it ONCE in the PEP, right after the initial PIP
read. The end-to-end test here is the regression guard the review demanded: the
PIP is invoked twice per real request (initial decision + enforce()'s premise
revalidation), so a naive emit inside the PIP would write two tamper records and
page twice for ONE event. We assert exactly one quarantine record and one ERROR
log through the full ``handle_request`` path.
"""

from __future__ import annotations

import logging

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.manifest import CATALOG_TABLE
from safe_agents.broker.prototype.broker_server import _make_pip
from safe_agents.broker.runtime import AgentRequest, BrokerRuntime, Doer, FakeSecretsProvider
from safe_agents.broker.runtime.connector import StubConnector
from safe_agents.broker.schemas import BrokeredCall, Session, Taint
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import PRINCIPAL, make_grant, make_quarantined_store

_HMAC_KEY = b"test-hmac-key"
_COUNTER_CAP = 100.0
_PEP_LOGGER = "safe_agents.broker.runtime.pep"
# The in-force envelope hash the PIP verifies grants against. Matches the
# ``envelopeHash`` scaffold.make_grant stamps, so a clean grant reads back matching
# (no envelope-hash quarantine) — this suite exercises the HMAC-mismatch cause only.
_IN_FORCE_HASH = "test-envelope-hash"


def _make_call(action_class: str) -> BrokeredCall:
    tool, op = action_class.split(".")
    manifest = CATALOG_TABLE.entry(tool, op)
    assert manifest is not None, f"no manifest entry for {action_class!r}"
    return BrokeredCall(
        principal=PRINCIPAL,
        tool=tool,
        op=op,
        args={"message": "hi"},
        manifest=manifest,
        taint=Taint(tainted=False, sources=[]),
        session=Session(turnId="test-quarantine-surfacing", ingestedSources=[]),
        ts="2026-07-06T00:00:00Z",
    )


def _make_runtime(grant_store, sink: InMemorySink) -> BrokerRuntime:
    """A real BrokerRuntime whose PIP reads from ``grant_store`` — the same wiring
    as broker_server.build_runtime, but with the store injected for the test."""
    doer = Doer(
        connectors={"notify": StubConnector(result={"status": "sent"})},
        secrets=FakeSecretsProvider({"notify": "cred-notify"}),
    )
    return BrokerRuntime(
        principal=PRINCIPAL,
        grants=[],  # served_registry is irrelevant here; handle_request keys off the manifest
        optable=CATALOG_TABLE,
        doer=doer,
        pip=_make_pip(grant_store, InMemoryStore(), _COUNTER_CAP, _IN_FORCE_HASH),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=_IN_FORCE_HASH,
        counter_cap=_COUNTER_CAP,
    )


# ---------------------------------------------------------------------------
# Unit — the PIP is pure: it reports the quarantine on Facts, emits nothing.
# ---------------------------------------------------------------------------


def test_pip_reports_quarantine_on_facts_and_does_no_io():
    """A quarantined grant makes the PIP return Facts with quarantined=True,
    quarantine_reason set, and grant_present=False (treated as absent for the
    decision) — WITHOUT any audit sink (proving the PIP does no I/O)."""
    store = make_quarantined_store("notify.send", hmac_key=_HMAC_KEY)
    pip = _make_pip(store, InMemoryStore(), _COUNTER_CAP, _IN_FORCE_HASH)  # no audit_sink param anymore

    facts = pip(_make_call("notify.send"))

    assert facts.quarantined is True
    assert facts.quarantine_reason is not None
    assert "mismatch" in facts.quarantine_reason.lower()
    assert facts.grant_present is False


def test_pip_clean_grant_sets_no_quarantine_flag():
    """A cleanly-seeded (matching-HMAC) grant reads back with quarantined=False,
    no reason, and grant_present=True."""
    store = InMemoryGrantStore(hmac_key=_HMAC_KEY)
    store.put_grant(make_grant("notify.send"))
    pip = _make_pip(store, InMemoryStore(), _COUNTER_CAP, _IN_FORCE_HASH)

    facts = pip(_make_call("notify.send"))

    assert facts.quarantined is False
    assert facts.quarantine_reason is None
    assert facts.grant_present is True


# ---------------------------------------------------------------------------
# End-to-end — the regression guard: exactly ONE surface through handle_request,
# despite the PIP running twice (initial decision + enforce revalidation).
# ---------------------------------------------------------------------------


def test_quarantine_surfaced_exactly_once_through_handle_request(caplog):
    """The double-emit regression guard. A quarantined grant driven through the
    FULL pipeline yields EXACTLY ONE distinctive quarantine audit record and
    EXACTLY ONE ERROR log — even though the PIP is invoked twice per request."""
    store = make_quarantined_store("notify.send", hmac_key=_HMAC_KEY)
    sink = InMemorySink()
    runtime = _make_runtime(store, sink)

    with caplog.at_level(logging.ERROR, logger=_PEP_LOGGER):
        response = runtime.handle_request(
            AgentRequest(
                tool="notify",
                op="send",
                args={"message": "hi"},
                idempotency_key="test:quarantine-e2e-1",
            )
        )

    # Unchanged safe behavior: the quarantined grant denies (treated as absent).
    assert response.decision_kind == "deny"

    # EXACTLY ONE quarantine record (there is also a normal deny record from the
    # deny/abstain tail of handle_request — filter to the quarantine one).
    quarantine_records = [
        r for r in sink.records() if r.reason and "quarantin" in r.reason.lower()
    ]
    assert len(quarantine_records) == 1
    assert quarantine_records[0].decision == "deny"
    assert quarantine_records[0].outcome == "denied"

    # EXACTLY ONE ERROR page naming the action class and the reason.
    error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(error_records) == 1
    message = error_records[0].getMessage()
    assert "notify.send" in message
    assert "quarantin" in message.lower()


def test_clean_grant_surfaces_nothing_through_handle_request(caplog):
    """Negative regression: a cleanly-seeded matching-HMAC grant driven through the
    full pipeline produces ZERO quarantine records and ZERO ERROR logs — the
    surfacing fires only on an actual HMAC mismatch, never on a healthy read."""
    store = InMemoryGrantStore(hmac_key=_HMAC_KEY)
    store.put_grant(make_grant("notify.send"))
    sink = InMemorySink()
    runtime = _make_runtime(store, sink)

    with caplog.at_level(logging.ERROR, logger=_PEP_LOGGER):
        response = runtime.handle_request(
            AgentRequest(
                tool="notify",
                op="send",
                args={"message": "hi"},
                idempotency_key="test:quarantine-e2e-clean-1",
            )
        )

    assert response.decision_kind == "allow"
    quarantine_records = [
        r for r in sink.records() if r.reason and "quarantin" in r.reason.lower()
    ]
    assert quarantine_records == []
    assert [r for r in caplog.records if r.levelno == logging.ERROR] == []
