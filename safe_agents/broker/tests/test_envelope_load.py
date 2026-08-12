"""test_envelope_load.py — build_runtime's BROKER_ENVELOPE_LOAD switch (sa#136 Slice B).

Slice B wires the envelope read seam (broker/envelope/read.py) into build_runtime:
with ``BROKER_ENVELOPE_LOAD=store`` the broker loads its in-force risk envelope from
the DynamoDB envelope store at startup instead of from the manifest. This file proves
the switch:

- store mode: the runtime's in-force hash + every envelope-derived knob (counter cap,
  trusted_read_sources) comes from the STORE envelope, not the manifest's.
- store mode with nothing seeded fails fast (EnvelopeNotFoundError) — fail-closed, the
  same posture BROKER_GRANT_LOAD="read" takes on a missing grant.
- an invalid BROKER_ENVELOPE_LOAD value fails loudly at boot.
- default/manifest mode is unchanged: the in-force envelope is manifest.envelope.

AWS-free: build_runtime defaults to in-memory stores + fake secrets + in-memory audit,
and the store-mode tests inject an InMemoryEnvelopeStore, so nothing touches AWS.
"""
from __future__ import annotations

import pytest

from safe_agents.broker.envelope.read import EnvelopeNotFoundError
from safe_agents.broker.envelope.store import InMemoryEnvelopeStore
from safe_agents.broker.prototype import broker_server
from safe_agents.broker.prototype.broker_server import build_runtime
from safe_agents.broker.schemas import AgentManifest, Envelope, compute_envelope_hash
from safe_agents.broker.schemas.common import Principal

_PRINCIPAL_DICT = {"agentId": "test-agent", "skill": "t", "user": "u", "tier": "B"}
_PRINCIPAL = Principal(**_PRINCIPAL_DICT)


def _manifest() -> AgentManifest:
    """A manifest whose envelope is DELIBERATELY distinct from the store fixture
    below (cap 7, no trusted sources) so a store-vs-manifest mix-up is visible."""
    return AgentManifest.model_validate(
        {
            "envelope": {"polarity": "abstain", "caps": {"actions_per_run": 7}},
            "principal": _PRINCIPAL_DICT,
            "grant_classes": ["search.query", "notify.send"],
            "connectors": ["github", "search"],
        }
    )


def _store_envelope() -> Envelope:
    """The envelope seeded into the store — distinct cap + a trusted source + a
    query-egress bound, none of which the manifest envelope carries."""
    return Envelope.model_validate(
        {
            "polarity": "abstain",
            "caps": {"actions_per_run": 42},
            "trusted_read_sources": ["connector:market.bars"],
            "max_query_bytes": 256,
            "query_egress_budget": 1024,
        }
    )


# ---------------------------------------------------------------------------
# store mode — the in-force envelope comes from the store, not the manifest
# ---------------------------------------------------------------------------


def test_store_mode_loads_envelope_from_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")
    store = InMemoryEnvelopeStore()
    seeded = _store_envelope()
    store.put_envelope(_PRINCIPAL, seeded)

    runtime, _ = build_runtime(_manifest(), envelope_store=store)

    # Everything envelope-derived is taken from the STORE envelope, not the manifest.
    assert runtime._counter_cap == 42.0  # store cap, not the manifest's 7
    assert runtime._trusted_read_sources == ["connector:market.bars"]
    assert runtime._envelope_hash == compute_envelope_hash(seeded)


def test_store_mode_hash_differs_from_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Belt-and-suspenders: the in-force hash is the STORE envelope's, provably not
    the manifest envelope's — so a re-seed changes what the broker enforces."""
    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")
    store = InMemoryEnvelopeStore()
    store.put_envelope(_PRINCIPAL, _store_envelope())
    manifest = _manifest()

    runtime, _ = build_runtime(manifest, envelope_store=store)

    assert runtime._envelope_hash != compute_envelope_hash(manifest.envelope)


def test_store_mode_missing_envelope_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")
    empty_store = InMemoryEnvelopeStore()  # nothing seeded

    with pytest.raises(EnvelopeNotFoundError):
        build_runtime(_manifest(), envelope_store=empty_store)


# ---------------------------------------------------------------------------
# invalid switch value — fail loudly
# ---------------------------------------------------------------------------


def test_invalid_envelope_load_value_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "bogus")
    with pytest.raises(ValueError, match="BROKER_ENVELOPE_LOAD"):
        build_runtime(_manifest())


# ---------------------------------------------------------------------------
# default / manifest mode — unchanged: in-force envelope is manifest.envelope
# ---------------------------------------------------------------------------


def test_default_mode_uses_manifest_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROKER_ENVELOPE_LOAD", raising=False)
    manifest = _manifest()

    runtime, _ = build_runtime(manifest)

    assert runtime._counter_cap == 7.0  # the manifest's cap
    assert runtime._envelope_hash == compute_envelope_hash(manifest.envelope)


def test_manifest_mode_ignores_injected_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """In manifest mode the injected store is never consulted — the manifest
    envelope wins even when a different one sits in the store."""
    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "manifest")
    store = InMemoryEnvelopeStore()
    store.put_envelope(_PRINCIPAL, _store_envelope())  # cap 42, would-be trap
    manifest = _manifest()

    runtime, _ = build_runtime(manifest, envelope_store=store)

    assert runtime._counter_cap == 7.0  # manifest, not the store's 42
    assert runtime._envelope_hash == compute_envelope_hash(manifest.envelope)


def test_resolve_envelope_load_mode_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BROKER_ENVELOPE_LOAD", raising=False)
    assert broker_server._resolve_envelope_load_mode() == "manifest"
