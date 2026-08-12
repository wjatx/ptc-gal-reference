"""Tests for the AgentManifest broker-facing manifest schema (broker-debaking P1, sa#113).

Covers:
  1. Round-trip: a dict with every block survives model_validate → model_dump(json).
  2. Envelope-only (the shape real smoke manifests have) validates; other blocks default.
  3. Missing `envelope` raises ValidationError.
  4. Missing `envelope.polarity` raises ValidationError (polarity stays load-bearing).
  5. A bad `principal.tier` raises ValidationError (Principal is really wired in).
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from safe_agents.broker.schemas import AgentManifest

FIXTURE = Path(__file__).parent / "fixtures" / "full_manifest.yaml"


def _full_manifest_dict() -> dict:
    """Author a dict exercising every AgentManifest block."""
    return {
        "envelope": {
            "polarity": "act",
            "caps": {"actions_per_run": 5},
            "allowlists": {"tools": ["example.read", "notify.send"]},
            "high_stakes": True,
        },
        "principal": {
            "agentId": "full-fixture-agent",
            "skill": "trade",
            "user": "owner@example.com",
            "tier": "B",
        },
        "grant_classes": ["example.read", "notify.send"],
        "budgets": {
            "error": {"tolerance": 0.05, "spent": 0.0},
            "attention": {"capacity": 20.0, "spent": 3.0},
            "escalation": {"capacity": 5.0, "spent": 0.0},
            "fallback": {"capacity": 10.0, "spent": 1.0},
        },
        "connectors": ["github", "example"],
    }


def test_round_trip_all_blocks() -> None:
    """A dict with every block round-trips its values through the model."""
    data = _full_manifest_dict()
    manifest = AgentManifest.model_validate(data)
    dumped = manifest.model_dump(mode="json")

    assert dumped["envelope"]["polarity"] == "act"
    assert dumped["envelope"]["caps"]["actions_per_utc_day"] == 5
    assert dumped["envelope"]["allowlists"]["tools"] == ["example.read", "notify.send"]
    assert dumped["envelope"]["high_stakes"] is True
    assert dumped["principal"] == data["principal"]
    assert dumped["grant_classes"] == ["example.read", "notify.send"]
    assert dumped["budgets"] == data["budgets"]
    assert dumped["connectors"] == ["github", "example"]


def test_fixture_file_round_trips() -> None:
    """The YAML fixture (every block) loads and validates identically."""
    raw = yaml.safe_load(FIXTURE.read_text())
    manifest = AgentManifest.model_validate(raw)
    assert manifest.principal is not None
    assert manifest.principal.tier == "B"
    assert manifest.budgets is not None
    assert manifest.budgets.error.tolerance == 0.05
    assert manifest.connectors == ["github", "example"]


def test_envelope_only_validates() -> None:
    """The shape real smoke manifests have: envelope only, rest default."""
    manifest = AgentManifest.model_validate({"envelope": {"polarity": "abstain"}})
    assert manifest.envelope.polarity == "abstain"
    assert manifest.principal is None
    assert manifest.grant_classes == []
    assert manifest.budgets is None
    assert manifest.connectors == []


def test_tool_ops_defaults_empty() -> None:
    """tool_ops (#171) defaults to an empty list when omitted."""
    manifest = AgentManifest.model_validate({"envelope": {"polarity": "abstain"}})
    assert manifest.tool_ops == []


def test_counter_period_defaults_to_utc_day() -> None:
    """counter_period (#212) defaults to utc-day — byte-for-byte the pre-#212
    counter coordinate; declaring it never churns the envelope hash (it lives
    OUTSIDE Envelope)."""
    manifest = AgentManifest.model_validate({"envelope": {"polarity": "abstain"}})
    assert manifest.counter_period == "utc-day"


def test_counter_period_accepts_utc_hour_and_rejects_unknown() -> None:
    """The period catalog is CLOSED (a Literal, never an import path or free
    string): utc-hour loads, anything else refuses at manifest load."""
    manifest = AgentManifest.model_validate(
        {"envelope": {"polarity": "abstain"}, "counter_period": "utc-hour"}
    )
    assert manifest.counter_period == "utc-hour"
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(
            {"envelope": {"polarity": "abstain"}, "counter_period": "utc-week"}
        )


def test_tool_ops_round_trips() -> None:
    """A valid tool_ops list survives model_validate -> model_dump(json)."""
    data = {
        "envelope": {"polarity": "abstain"},
        "tool_ops": [
            {"tool": "github", "op": "whoami", "effect": "read", "external": True},
            {"tool": "ledger", "op": "append", "effect": "write", "external": False,
             "reversible": True},
        ],
    }
    manifest = AgentManifest.model_validate(data)
    assert len(manifest.tool_ops) == 2
    assert manifest.tool_ops[0].tool == "github"
    assert manifest.tool_ops[0].op == "whoami"
    assert manifest.tool_ops[1].reversible is True

    dumped = manifest.model_dump(mode="json")
    assert dumped["tool_ops"][0]["tool"] == "github"
    assert dumped["tool_ops"][1]["op"] == "append"


def test_tool_ops_duplicate_pair_rejected() -> None:
    """AgentManifest itself rejects a tool_ops list with a duplicate (tool, op)
    pair at load time (a field_validator on AgentManifest, distinct from — but
    consistent with — ToolOpTable's own duplicate-key guard at table-build time)."""
    data = {
        "envelope": {"polarity": "abstain"},
        "tool_ops": [
            {"tool": "github", "op": "whoami", "effect": "read", "external": True},
            {"tool": "github", "op": "whoami", "effect": "write", "external": False,
             "reversible": True},
        ],
    }
    with pytest.raises(ValidationError, match="github.whoami"):
        AgentManifest.model_validate(data)


def test_missing_envelope_raises() -> None:
    """envelope is required; a manifest without it is invalid."""
    with pytest.raises(ValidationError):
        AgentManifest.model_validate({"principal": {
            "agentId": "a", "skill": "s", "user": "u", "tier": "A",
        }})


def test_missing_polarity_raises() -> None:
    """polarity stays load-bearing — an envelope without it is invalid."""
    with pytest.raises(ValidationError):
        AgentManifest.model_validate({"envelope": {}})


def test_bad_principal_tier_raises() -> None:
    """A bad principal.tier proves Principal is really wired in, not a passthrough dict."""
    data = _full_manifest_dict()
    data["principal"]["tier"] = "Z"
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(data)
