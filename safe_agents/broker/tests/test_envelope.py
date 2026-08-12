"""Tests for the Envelope artifact + canonical hash (sa#135).

Covers:
  1. Hash stability across serialize -> load -> re-hash, and hash sensitivity
     to a changed field. Also asserts the "sha256:" prefix.
  2. Every real agents/*.yaml envelope block validates against the schema
     (including the polarity-only rhel-openshell manifest, proving optionality).
  3. An invalid envelope (missing/bad polarity) raises pydantic.ValidationError.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from safe_agents.broker.schemas.envelope import Envelope, compute_envelope_hash

REPO_ROOT = Path(__file__).parent.parent.parent.parent  # safe-agents/
AGENTS_DIR = REPO_ROOT / "agents"


def _fixture_envelope() -> Envelope:
    return Envelope.model_validate(
        {
            "polarity": "abstain",
            "caps": {"actions_per_run": 1},
            "allowlists": {"tools": ["snapshot.read"]},
            "high_stakes": False,
        }
    )


# ---------------------------------------------------------------------------
# 1. Hash stability
# ---------------------------------------------------------------------------

def test_hash_has_sha256_prefix() -> None:
    env = _fixture_envelope()
    digest = compute_envelope_hash(env)
    assert digest.startswith("sha256:")


def test_hash_stable_across_serialize_load_rehash() -> None:
    """serialize -> load -> re-hash produces the identical digest."""
    env = _fixture_envelope()
    digest = compute_envelope_hash(env)

    reloaded = Envelope.model_validate(env.model_dump(mode="json"))
    redigest = compute_envelope_hash(reloaded)

    assert digest == redigest


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda d: d.__setitem__("high_stakes", True), id="flip_high_stakes"),
        pytest.param(
            lambda d: d["allowlists"].__setitem__("tools", ["snapshot.read", "research.web"]),
            id="add_tool",
        ),
    ],
)
def test_hash_changes_on_field_change(mutate) -> None:
    env = _fixture_envelope()
    original_digest = compute_envelope_hash(env)

    data = env.model_dump(mode="json")
    mutate(data)
    mutated_env = Envelope.model_validate(data)
    mutated_digest = compute_envelope_hash(mutated_env)

    assert original_digest != mutated_digest


# ---------------------------------------------------------------------------
# 2. Every real agents/*.yaml envelope validates
# ---------------------------------------------------------------------------

def _real_agent_envelopes() -> list[tuple[str, dict]]:
    """Collect (filename, envelope-dict) pairs for every agents/*.yaml with an envelope."""
    pairs = []
    for path in sorted(AGENTS_DIR.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text())
        envelope = raw.get("envelope")
        if envelope is not None:
            pairs.append((path.name, envelope))
    return pairs


_REAL_ENVELOPES = _real_agent_envelopes()


@pytest.mark.parametrize(
    "envelope",
    [pytest.param(env, id=name) for name, env in _REAL_ENVELOPES],
)
def test_real_manifest_envelopes_validate(envelope: dict) -> None:
    Envelope.model_validate(envelope)


def test_real_envelopes_fixture_is_nonempty() -> None:
    """Sanity check: the parametrization above actually collected manifests."""
    assert _REAL_ENVELOPES, "Expected at least one agents/*.yaml with an envelope: block"


def test_polarity_only_envelope_validates() -> None:
    """smoke-rhel-openshell.yaml declares polarity only — proves every other field is optional."""
    envelope = yaml.safe_load(
        (AGENTS_DIR / "smoke-rhel-openshell.yaml").read_text()
    )["envelope"]
    assert envelope == {"polarity": "abstain"}
    Envelope.model_validate(envelope)


# ---------------------------------------------------------------------------
# 3. Invalid envelope rejected
# ---------------------------------------------------------------------------

def test_missing_polarity_raises() -> None:
    with pytest.raises(ValidationError):
        Envelope.model_validate({})


def test_bad_polarity_value_raises() -> None:
    with pytest.raises(ValidationError):
        Envelope.model_validate({"polarity": "trust_me"})
