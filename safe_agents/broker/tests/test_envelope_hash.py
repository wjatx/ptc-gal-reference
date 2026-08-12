"""Tests for sa#122 — the real envelope hash wired into decisions + audit.

Retires the ``stub-envelope-hash`` / ``proto-envelope-hash`` placeholders. Two
things are now real and verified end-to-end:

  1. The hash stamped into every AuditRecord is the *content-hash of the envelope
     actually in force* — ``compute_envelope_hash(manifest.envelope)`` — not a
     literal placeholder.
  2. A grant whose ``envelopeHash`` does not match the in-force envelope is
     QUARANTINED at decision time, reusing the same sa#124 loud-surface-once path
     the HMAC-mismatch case uses (one ERROR log + one deny AuditRecord, then deny).

The hash is computed dynamically from the envelope throughout, so these tests do
not depend on any particular manifest's contents.
"""

from __future__ import annotations

import logging

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.manifest import CATALOG_TABLE
from safe_agents.broker.prototype.broker_server import _make_grant, _make_pip, build_runtime
from safe_agents.broker.runtime import AgentRequest, BrokerRuntime, Doer, FakeSecretsProvider
from safe_agents.broker.runtime.connector import StubConnector
from safe_agents.broker.schemas import AgentManifest, BrokeredCall, Envelope, Session, Taint
from safe_agents.broker.schemas import compute_envelope_hash
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import PRINCIPAL, make_grant

_HMAC_KEY = b"test-hmac-key"
_COUNTER_CAP = 100.0
_PEP_LOGGER = "safe_agents.broker.runtime.pep"

# Two DISTINCT real envelope hashes — the polarity difference guarantees the
# content hashes differ, so one can stand in for "the envelope the grant was
# issued under" and the other for "the envelope now in force".
_HASH_A = compute_envelope_hash(Envelope(polarity="abstain"))
_HASH_B = compute_envelope_hash(Envelope(polarity="act"))


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
        session=Session(turnId="test-envelope-hash", ingestedSources=[]),
        ts="2026-07-06T00:00:00Z",
    )


def _seed_store(action_class: str, grant_envelope_hash: str) -> InMemoryGrantStore:
    """An InMemoryGrantStore holding a HMAC-clean grant issued under
    ``grant_envelope_hash`` (put_grant recomputes a matching HMAC over the content,
    so the grant reads back clean — only the envelope hash can mismatch)."""
    store = InMemoryGrantStore(hmac_key=_HMAC_KEY)
    grant = make_grant(action_class).model_copy(update={"envelopeHash": grant_envelope_hash})
    store.put_grant(grant)
    return store


def _runtime(store: InMemoryGrantStore, in_force_hash: str, sink: InMemorySink) -> BrokerRuntime:
    """A real BrokerRuntime whose PIP reads ``store`` and verifies against
    ``in_force_hash`` — the same wiring build_runtime uses, injected for the test."""
    doer = Doer(
        connectors={"notify": StubConnector(result={"status": "sent"})},
        secrets=FakeSecretsProvider({"notify": "cred-notify"}),
    )
    return BrokerRuntime(
        principal=PRINCIPAL,
        grants=[],  # served_registry is irrelevant; handle_request keys off the manifest
        optable=CATALOG_TABLE,
        doer=doer,
        pip=_make_pip(store, InMemoryStore(), _COUNTER_CAP, in_force_hash),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=in_force_hash,
        counter_cap=_COUNTER_CAP,
    )


# ---------------------------------------------------------------------------
# Unit — the seed builder and the PIP verification
# ---------------------------------------------------------------------------


def test_make_grant_stamps_the_passed_in_force_hash():
    """_make_grant carries the real in-force hash, not a placeholder literal."""
    grant = _make_grant("notify.send", PRINCIPAL, _HASH_A)
    assert grant.envelopeHash == _HASH_A


def test_pip_matching_envelope_hash_is_not_quarantined():
    """A grant issued under the in-force envelope reads back clean and grantable."""
    store = _seed_store("notify.send", _HASH_A)
    pip = _make_pip(store, InMemoryStore(), _COUNTER_CAP, in_force_hash=_HASH_A)

    facts = pip(_make_call("notify.send"))

    assert facts.quarantined is False
    assert facts.quarantine_reason is None
    assert facts.grant_present is True


def test_pip_envelope_hash_mismatch_quarantines():
    """A grant issued under envelope A but verified against in-force B is quarantined
    (treated as absent) with a distinct envelope-mismatch reason — reusing the
    sa#124 Facts.quarantined channel, no new decision path."""
    store = _seed_store("notify.send", _HASH_A)
    pip = _make_pip(store, InMemoryStore(), _COUNTER_CAP, in_force_hash=_HASH_B)

    facts = pip(_make_call("notify.send"))

    assert facts.quarantined is True
    assert facts.grant_present is False
    assert facts.quarantine_reason is not None
    assert "envelope hash mismatch" in facts.quarantine_reason
    assert _HASH_A in facts.quarantine_reason and _HASH_B in facts.quarantine_reason


# ---------------------------------------------------------------------------
# End-to-end — the real hash lands in audit; the mismatch surfaces + denies
# ---------------------------------------------------------------------------


def test_allowed_call_stamps_real_envelope_hash_into_audit():
    """An ALLOWED call's executed AuditRecord carries the real sha256 content-hash of
    the in-force envelope — exactly compute_envelope_hash(manifest.envelope)."""
    manifest = AgentManifest(
        principal=PRINCIPAL,
        grant_classes=["notify.send"],
        connectors=["notify"],
        envelope=Envelope(polarity="abstain"),
    )
    in_force = compute_envelope_hash(manifest.envelope)
    sink = InMemorySink()
    runtime = _runtime(_seed_store("notify.send", in_force), in_force, sink)

    response = runtime.handle_request(
        AgentRequest(
            tool="notify",
            op="send",
            args={"message": "hi"},
            idempotency_key="test:envhash-allow-1",
        )
    )

    assert response.decision_kind == "allow"
    executed = [r for r in sink.records() if r.outcome == "executed"]
    assert len(executed) == 1
    assert executed[0].envelopeHash == in_force
    assert executed[0].envelopeHash.startswith("sha256:")


def test_envelope_mismatch_surfaces_quarantine_and_denies(caplog):
    """A grant issued under envelope A driven through the full pipeline while envelope
    B is in force: the sa#124 LOUD path fires once (ERROR log + one deny AuditRecord
    naming the envelope-hash mismatch) and the call denies."""
    sink = InMemorySink()
    runtime = _runtime(_seed_store("notify.send", _HASH_A), _HASH_B, sink)

    with caplog.at_level(logging.ERROR, logger=_PEP_LOGGER):
        response = runtime.handle_request(
            AgentRequest(
                tool="notify",
                op="send",
                args={"message": "hi"},
                idempotency_key="test:envhash-mismatch-1",
            )
        )

    assert response.decision_kind == "deny"

    # Exactly one quarantine audit record, naming the envelope-hash mismatch, and
    # stamped with the REAL in-force hash (B).
    quarantine_records = [
        r for r in sink.records() if r.reason and "envelope hash mismatch" in r.reason
    ]
    assert len(quarantine_records) == 1
    assert quarantine_records[0].decision == "deny"
    assert quarantine_records[0].outcome == "denied"
    assert quarantine_records[0].envelopeHash == _HASH_B

    # Exactly one ERROR page, naming the action class and the mismatch.
    error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(error_records) == 1
    message = error_records[0].getMessage()
    assert "notify.send" in message
    assert "envelope hash mismatch" in message


# ---------------------------------------------------------------------------
# build_runtime wiring — seeded grants are issued under the manifest's hash
# ---------------------------------------------------------------------------


def test_build_runtime_seeds_grants_under_manifest_envelope_hash(monkeypatch):
    """build_runtime computes the in-force hash from manifest.envelope and seeds every
    grant under it — so the seed can never be born already mismatched."""
    # Isolate from any ambient BROKER_* env so the default memory/seed path is used.
    for var in (
        "BROKER_STORE",
        "BROKER_GRANT_CLASSES",
        "BROKER_GRANT_LOAD",
        "BROKER_SKIP_GRANT_LOAD",
        "BROKER_AUDIT_BUCKET",
        "BROKER_AUDIT_PATH",
        "BROKER_SECRETS",
        "BROKER_SECRETS_FILE",
    ):
        monkeypatch.delenv(var, raising=False)

    manifest = AgentManifest(
        principal=PRINCIPAL,
        grant_classes=["notify.send"],
        connectors=["notify"],
        # #205: a granted write class must NAME its daily cap — a caps-less
        # envelope would be refused at build_runtime.
        envelope=Envelope.model_validate(
            {"polarity": "abstain", "caps": {"actions_per_utc_day": 25}}
        ),
        tool_ops=[CATALOG_TABLE.entry("notify", "send")],
    )
    expected = compute_envelope_hash(manifest.envelope)

    runtime, _sink = build_runtime(manifest)

    seeded = runtime.served_registry()
    assert [(t.tool, t.op) for t in seeded] == [("notify", "send")]
    # White-box: the seeded grants each carry the manifest's real envelope hash.
    assert runtime._grants  # noqa: SLF001 — verifying the seed carried the hash
    assert all(g.envelopeHash == expected for g in runtime._grants)  # noqa: SLF001
