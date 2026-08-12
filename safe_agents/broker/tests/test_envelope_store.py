"""Tests for the envelope store + seed + read seam (sa#136, Phase 3 Slice A).

Coverage:
- InMemoryEnvelopeStore round-trip: put/get preserves all fields.
- seed_envelope() from a real agents/*.yaml (smoke-fargate.yaml) produces the
  expected Envelope fields.
- Full seam round-trip (seed_envelope -> load_inforce_envelope) is stable
  under compute_envelope_hash across seed -> load -> re-hash.
- load_inforce_envelope() raises EnvelopeNotFoundError when nothing was seeded
  for the principal — fail loudly, never a silent default.
- load_envelope_block() rejects a manifest with no envelope: block, and a
  malformed (non-mapping) envelope: block.
- DynamoDBEnvelopeStore round-trips via a mocked boto3 session, co-located in
  the same table shape (pk/sk) grants use, with the "ENVELOPE#" prefix.
- _resolve_seed_principal (#197): the store-key principal comes from the SAME
  manifest the envelope is read from; a BROKER_MANIFEST naming a different
  principal is a split-brain refusal; no principal anywhere refuses — the seed
  never falls back to a default principal.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from safe_agents.broker.envelope.read import EnvelopeNotFoundError, load_inforce_envelope
from safe_agents.broker.envelope.seed import EnvelopeSeedError, load_envelope_block, seed_envelope
from safe_agents.broker.envelope.store import (
    DynamoDBEnvelopeStore,
    InMemoryEnvelopeStore,
)
from safe_agents.broker.schemas import Envelope
from safe_agents.broker.schemas.common import Principal
from safe_agents.broker.schemas.envelope import compute_envelope_hash

REPO_ROOT = Path(__file__).parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"
SMOKE_FARGATE_YAML = AGENTS_DIR / "smoke-fargate.yaml"

PRINCIPAL = Principal(agentId="example-agent", skill="advisor", user="maintainer", tier="B")


# ---------------------------------------------------------------------------
# InMemoryEnvelopeStore — happy path round-trip
# ---------------------------------------------------------------------------


def _fixture_envelope() -> Envelope:
    return Envelope.model_validate(
        {
            "polarity": "abstain",
            "caps": {"actions_per_run": 1},
            "allowlists": {"tools": ["snapshot.read"]},
            "high_stakes": False,
        }
    )


def test_in_memory_round_trip_preserves_fields():
    store = InMemoryEnvelopeStore()
    original = _fixture_envelope()
    store.put_envelope(PRINCIPAL, original)

    got = store.get_envelope(PRINCIPAL)

    assert got is not None
    assert got.polarity == "abstain"
    assert got.caps.actions_per_utc_day == 1
    assert got.allowlists.tools == ["snapshot.read"]
    assert got.high_stakes is False


def test_in_memory_get_absent_returns_none():
    store = InMemoryEnvelopeStore()
    assert store.get_envelope(PRINCIPAL) is None


def test_in_memory_overwrite_replaces_envelope():
    store = InMemoryEnvelopeStore()
    store.put_envelope(PRINCIPAL, _fixture_envelope())
    replacement = Envelope.model_validate({"polarity": "act", "high_stakes": True})
    store.put_envelope(PRINCIPAL, replacement)

    got = store.get_envelope(PRINCIPAL)
    assert got is not None
    assert got.polarity == "act"
    assert got.high_stakes is True


# ---------------------------------------------------------------------------
# seed_envelope() from a real agents/*.yaml
# ---------------------------------------------------------------------------


def test_seed_from_fixture_yaml_matches_expected_fields():
    """smoke-fargate.yaml's envelope: block (agents/smoke-fargate.yaml lines
    ~33-39) has a known shape; seed_envelope must produce exactly that."""
    store = InMemoryEnvelopeStore()
    envelope = seed_envelope(store, SMOKE_FARGATE_YAML, PRINCIPAL)

    assert envelope.polarity == "abstain"
    assert envelope.caps is not None
    assert envelope.caps.actions_per_utc_day == 0
    assert envelope.allowlists is not None
    assert envelope.allowlists.tools == []
    assert envelope.high_stakes is False


def test_seed_envelope_writes_to_store():
    store = InMemoryEnvelopeStore()
    seed_envelope(store, SMOKE_FARGATE_YAML, PRINCIPAL)

    got = store.get_envelope(PRINCIPAL)
    assert got is not None
    assert got.polarity == "abstain"


def test_load_envelope_block_missing_manifest_raises(tmp_path):
    with pytest.raises(EnvelopeSeedError, match="not found"):
        load_envelope_block(tmp_path / "does-not-exist.yaml")


def test_load_envelope_block_missing_envelope_key_raises(tmp_path):
    manifest = tmp_path / "no-envelope.yaml"
    manifest.write_text("name: no-envelope\narm: ec2\n")

    with pytest.raises(EnvelopeSeedError, match="No 'envelope:' block"):
        load_envelope_block(manifest)


def test_load_envelope_block_non_mapping_envelope_raises(tmp_path):
    manifest = tmp_path / "bad-envelope.yaml"
    manifest.write_text("name: bad\nenvelope: [not, a, mapping]\n")

    with pytest.raises(EnvelopeSeedError, match="must be a YAML mapping"):
        load_envelope_block(manifest)


def test_seed_envelope_rejects_invalid_envelope(tmp_path):
    """A manifest whose envelope: block fails Envelope validation (missing
    polarity) must raise — never silently default one in."""
    from pydantic import ValidationError

    manifest = tmp_path / "no-polarity.yaml"
    manifest.write_text("name: bad\nenvelope:\n  high_stakes: true\n")

    store = InMemoryEnvelopeStore()
    with pytest.raises(ValidationError):
        seed_envelope(store, manifest, PRINCIPAL)


# ---------------------------------------------------------------------------
# Full seam: seed_envelope -> load_inforce_envelope -> compute_envelope_hash
# ---------------------------------------------------------------------------


def test_seed_then_load_hash_stable_across_round_trip():
    """seed -> load -> re-hash must produce the identical digest as hashing
    the freshly-validated envelope directly — the store round-trip must not
    perturb any field."""
    store = InMemoryEnvelopeStore()
    seeded = seed_envelope(store, SMOKE_FARGATE_YAML, PRINCIPAL)
    expected_hash = compute_envelope_hash(seeded)

    loaded = load_inforce_envelope(store, PRINCIPAL)
    loaded_hash = compute_envelope_hash(loaded)

    assert loaded_hash == expected_hash
    assert loaded_hash.startswith("sha256:")


def test_load_inforce_envelope_raises_when_absent():
    store = InMemoryEnvelopeStore()
    with pytest.raises(EnvelopeNotFoundError):
        load_inforce_envelope(store, PRINCIPAL)


# ---------------------------------------------------------------------------
# DynamoDBEnvelopeStore — mocked boto3, no live AWS (mirrors test_grants_store.py)
# ---------------------------------------------------------------------------


def _make_dynamo_store(table_name: str = "envelope-test") -> DynamoDBEnvelopeStore:
    return DynamoDBEnvelopeStore(table_name=table_name)


def test_dynamo_get_returns_none_on_missing_item():
    store = _make_dynamo_store()
    mock_table = MagicMock()
    mock_table.get_item.return_value = {}  # no "Item" key

    with patch("boto3.resource") as mock_resource:
        mock_resource.return_value.Table.return_value = mock_table
        result = store.get_envelope(PRINCIPAL)

    assert result is None


def test_dynamo_round_trip_via_mock_uses_envelope_prefix():
    """put_envelope then get_envelope with a mock DynamoDB preserves all
    fields, and the item keys use the ENVELOPE# prefix (co-located with, but
    distinct from, GRANT# items in the same table)."""
    store = _make_dynamo_store()

    captured_items: list[dict] = []
    mock_put_session = MagicMock()
    mock_put_table = MagicMock()
    mock_put_session.resource.return_value.Table.return_value = mock_put_table
    mock_put_table.put_item.side_effect = lambda Item: captured_items.append(Item)

    original = _fixture_envelope()
    store.put_envelope(PRINCIPAL, original, session=mock_put_session)

    assert len(captured_items) == 1
    item = captured_items[0]
    assert item["pk"].startswith("ENVELOPE#")
    assert item["sk"] == "V0"
    assert "data" in item

    mock_get_table = MagicMock()
    mock_get_table.get_item.return_value = {"Item": item}
    with patch("boto3.resource") as mock_resource:
        mock_resource.return_value.Table.return_value = mock_get_table
        result = store.get_envelope(PRINCIPAL)

    assert result is not None
    assert result.polarity == "abstain"
    assert result.allowlists.tools == ["snapshot.read"]


def test_dynamo_put_propagates_access_denied():
    """AccessDenied from DynamoDB is NOT swallowed — the caller must see it
    (same posture as DynamoDBGrantStore.put_grant)."""
    from botocore.exceptions import ClientError

    store = _make_dynamo_store()
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    mock_table.put_item.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "User is not authorized"}},
        "PutItem",
    )

    with pytest.raises(ClientError) as exc_info:
        store.put_envelope(PRINCIPAL, _fixture_envelope(), session=mock_session)

    assert exc_info.value.response["Error"]["Code"] == "AccessDeniedException"


# ---------------------------------------------------------------------------
# _resolve_seed_principal — the store-key principal comes from the SAME
# manifest the envelope is read from (#197), never a default
# ---------------------------------------------------------------------------

_ENVELOPE_YAML_BLOCK = """\
envelope:
  polarity: abstain
  caps:
    actions_per_run: 1
  allowlists:
    tools: []
  high_stakes: false
"""


def _write_manifest(tmp_path: Path, name: str, agent_id: str | None) -> Path:
    """A minimal broker AgentManifest yaml; agent_id=None omits the principal
    block (the pipeline-style agents/*.yaml shape)."""
    principal_block = (
        f"principal:\n  agentId: {agent_id}\n  skill: demo\n  user: demo-user\n  tier: B\n"
        if agent_id
        else ""
    )
    path = tmp_path / name
    path.write_text(principal_block + _ENVELOPE_YAML_BLOCK)
    return path


def test_seed_principal_derives_from_envelope_manifest(monkeypatch, tmp_path):
    """The #197 bare-invocation regression: BROKER_MANIFEST unset, the envelope
    manifest names its own principal — that principal keys the store write,
    never the broker_server default (example-advisor)."""
    from safe_agents.broker.prototype.seed_envelope import _resolve_seed_principal

    monkeypatch.delenv("BROKER_MANIFEST", raising=False)
    manifest = _write_manifest(tmp_path, "drain-manifest.yaml", "owner-example-agent")

    principal = _resolve_seed_principal(manifest)

    assert principal.agentId == "owner-example-agent"


def test_seed_principal_split_brain_refused(monkeypatch, tmp_path):
    """BROKER_MANIFEST set AND naming a different principal than the envelope
    manifest → loud refusal, no guessing which side the operator meant."""
    from safe_agents.broker.prototype.seed_envelope import (
        SeedPrincipalError,
        _resolve_seed_principal,
    )

    envelope_manifest = _write_manifest(tmp_path, "envelope.yaml", "owner-example-agent")
    broker_manifest = _write_manifest(tmp_path, "broker.yaml", "example-advisor")
    monkeypatch.setenv("BROKER_MANIFEST", str(broker_manifest))

    with pytest.raises(SeedPrincipalError, match="split-brain") as exc_info:
        _resolve_seed_principal(envelope_manifest)
    # The refusal names both principals so the operator can see which env var is stale.
    assert "owner-example-agent" in str(exc_info.value)
    assert "example-advisor" in str(exc_info.value)


def test_seed_principal_matching_broker_manifest_ok(monkeypatch, tmp_path):
    """Both env vars naming the SAME principal is the runbook shape — allowed."""
    from safe_agents.broker.prototype.seed_envelope import _resolve_seed_principal

    envelope_manifest = _write_manifest(tmp_path, "envelope.yaml", "owner-example-agent")
    broker_manifest = _write_manifest(tmp_path, "broker.yaml", "owner-example-agent")
    monkeypatch.setenv("BROKER_MANIFEST", str(broker_manifest))

    assert _resolve_seed_principal(envelope_manifest).agentId == "owner-example-agent"


def test_seed_principal_pipeline_yaml_uses_broker_manifest(monkeypatch, tmp_path):
    """A pipeline-style envelope manifest (no principal: block — the real
    smoke-fargate.yaml) with BROKER_MANIFEST explicitly set takes the broker
    manifest's principal (docs/channels-drain-bringup.md §3 keeps working)."""
    from safe_agents.broker.prototype.seed_envelope import _resolve_seed_principal

    broker_manifest = _write_manifest(tmp_path, "broker.yaml", "owner-example-agent")
    monkeypatch.setenv("BROKER_MANIFEST", str(broker_manifest))

    assert _resolve_seed_principal(SMOKE_FARGATE_YAML).agentId == "owner-example-agent"


def test_seed_principal_no_principal_anywhere_refused(monkeypatch, tmp_path):
    """No principal: block in the envelope manifest AND BROKER_MANIFEST unset →
    refusal. There is no default principal to fall back to (fail toward
    not-writing)."""
    from safe_agents.broker.prototype.seed_envelope import (
        SeedPrincipalError,
        _resolve_seed_principal,
    )

    monkeypatch.delenv("BROKER_MANIFEST", raising=False)
    envelope_manifest = _write_manifest(tmp_path, "envelope.yaml", None)

    with pytest.raises(SeedPrincipalError, match="no default principal"):
        _resolve_seed_principal(envelope_manifest)
