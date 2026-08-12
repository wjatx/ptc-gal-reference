"""Honest-manifest proof for the Alpaca paper drill (#221 Phase 1).

Mirrors ``test_example_restricted_mcp_server.py``: the
manifest validates as written AND each load-time invariant refuses a mutated
copy. Plus the drill-specific ceiling check: the #221 epic constraint — no
order / position-closing / account-mutating tool ever enters this drill's
declarations — is machine-checked, not prose. SDK-free; runs in CI.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from safe_agents.broker.schemas import AgentManifest

# Lives here, not beside the manifest: `examples/` is on no pytest path, so a test
# there never runs (#294). The house convention is example code in `examples/`, its
# test under `safe_agents/*/tests/` reaching across.
_MANIFEST_PATH = (
    Path(__file__).resolve().parents[3] / "examples" / "alpaca_paper_drill" / "manifest.yaml"
)

# The #221 ceiling: tool-name prefixes that must NEVER appear in this drill's
# declarations (order placement, position closing, account/watchlist mutation,
# options exercise — every write-shaped surface the live server advertises).
_FORBIDDEN_PREFIXES = (
    "place_",
    "close_",
    "cancel_",
    "replace_",
    "exercise_",
    "do_not_exercise_",
    "update_",
    "create_",
    "delete_",
    "add_",
    "remove_",
)


def _load() -> dict:
    return yaml.safe_load(_MANIFEST_PATH.read_text())


def test_manifest_validates_as_written():
    manifest = AgentManifest.model_validate(_load())
    server = manifest.mcp_servers["alpaca"]
    assert server.command == "uvx"
    assert server.args == ["alpaca-mcp-server==2.1.1"], "the version pin is load-bearing"
    assert server.env == {"ALPACA_PAPER_TRADE": "true"}, "paper trading is manifest-pinned"
    assert manifest.connector_auth["alpaca"].env_map == {
        "ALPACA_API_KEY": "ALPACA_KEY",
        "ALPACA_SECRET_KEY": "ALPACA_SECRET",
    }


def test_declared_subset_is_read_only_ceiling():
    """The epic constraint as a test: every declared tool is a get_*, and no
    write-shaped name appears anywhere in the declaration or its grants."""
    manifest = AgentManifest.model_validate(_load())
    declared = [t.tool_name for t in manifest.mcp_servers["alpaca"].tools]
    assert declared, "the drill declares a non-empty subset"
    for name in declared:
        assert name.startswith("get_"), f"non-read tool {name!r} entered the drill ceiling"
        assert not name.startswith(_FORBIDDEN_PREFIXES)
    for op in manifest.tool_ops:
        assert op.effect == "read", f"tool_ops classifies {op.op!r} as {op.effect!r}"
    for grant_class in manifest.grant_classes:
        assert grant_class.split(".", 1)[1].startswith("get_")


def test_paper_trade_pin_cannot_be_shadowed_by_env_map():
    """env_map targeting ALPACA_PAPER_TRADE would let the credential half
    override the paper pin — the disjointness validator refuses it."""
    raw = _load()
    raw["connector_auth"]["alpaca"]["env_map"]["ALPACA_PAPER_TRADE"] = "ALPACA_KEY"
    with pytest.raises(ValueError, match="must be disjoint"):
        AgentManifest.model_validate(raw)


def test_undeclared_order_tool_cannot_be_half_added():
    """Adding place_stock_order to mcp_servers WITHOUT its ToolOp refuses at
    load (two-key completeness) — the cheap way to sneak a tool in fails."""
    raw = _load()
    raw["mcp_servers"]["alpaca"]["tools"].append({"tool_name": "place_stock_order"})
    with pytest.raises(ValueError, match="must carry its external ToolOp"):
        AgentManifest.model_validate(raw)


def test_spawn_block_requires_connectors_wiring():
    raw = _load()
    raw["connectors"] = []
    with pytest.raises(ValueError, match="not named in 'connectors'"):
        AgentManifest.model_validate(raw)


def test_mutating_the_pin_is_visible_in_a_diff_sized_surface():
    """The whole spawn block round-trips the schema untouched — a changed pin
    or env is a manifest diff, never a runtime surprise."""
    raw = _load()
    manifest = AgentManifest.model_validate(copy.deepcopy(raw))
    assert manifest.mcp_servers["alpaca"].model_dump(exclude_defaults=True) == {
        "tools": [
            {"tool_name": "get_account_info", "structured_output": True},
            {"tool_name": "get_clock", "structured_output": True},
            {"tool_name": "get_stock_latest_quote", "structured_output": True},
        ],
        "command": "uvx",
        "args": ["alpaca-mcp-server==2.1.1"],
        "env": {"ALPACA_PAPER_TRADE": "true"},
    }
