"""Validation test for the restricted_mcp_server example (#174).

Proves the restrict-by-construction MCP example is HONEST, not decorative: the
manifest validates as written, and each invariant broker/MCP-HOST.md leans on
REFUSES a mutated copy —

  * an undeclared MCP tool with no matching ToolOp (two-key completeness, M4), and
  * a trusted read source flipped to structured_output=false (structured-only
    trust — free-text output is injection surface, M11).

Mirrors safe_agents/broker/tests/test_example_confidence_budget.py, but lives
BESIDE the example: the constraint that the example dir stay self-contained keeps
the test here rather than under broker/tests/. It imports only the public
`safe_agents.broker.schemas` surface (the one consumer-facing seam) — never
server.py, never broker internals — so it needs neither the optional `mcp` SDK
nor a running server (manifest validation is pure schema).
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from safe_agents.broker.schemas import AgentManifest

# Lives here, not beside the manifest: `examples/` is on no pytest path, so a test
# there never runs (#294). The house convention is example code in `examples/`, its
# test under `safe_agents/*/tests/` reaching across.
_MANIFEST_PATH = (
    Path(__file__).resolve().parents[3] / "examples" / "restricted_mcp_server" / "manifest.yaml"
)


def _raw() -> dict:
    """The manifest as a fresh dict, safe to mutate per-test."""
    return yaml.safe_load(_MANIFEST_PATH.read_text())


def test_manifest_validates_as_written() -> None:
    # Happy path through the public schema surface (the same validation a live
    # deploy's loader applies — consumers never import broker internals).
    manifest = AgentManifest.model_validate(_raw())

    # Exactly two declared tools, both structured — no append/delete/admin exists.
    ledger = manifest.mcp_servers["ledger"]
    names = {t.tool_name for t in ledger.tools}
    assert names == {"get_entry", "list_entries"}
    assert all(t.structured_output for t in ledger.tools)

    # Two-key completeness: every declared MCP tool carries its external-read ToolOp.
    ops = {(o.tool, o.op): o for o in manifest.tool_ops}
    for name in names:
        assert ops[("ledger", name)].external is True
        assert ops[("ledger", name)].effect == "read"

    # The one trusted source names a structured tool — legal (M10).
    assert "connector:ledger.get_entry" in manifest.envelope.trusted_read_sources


def test_undeclared_mcp_tool_refuses() -> None:
    # Add a tool to the ledger namespace with NO matching ToolOp. The manifest half
    # is now incomplete — the broker could not classify the tool — so load refuses
    # rather than admit an unclassified (server_id, tool_name) at request time (M4).
    data = _raw()
    data["mcp_servers"]["ledger"]["tools"].append(
        {"tool_name": "delete_entry", "structured_output": True}
    )
    with pytest.raises(ValidationError, match="external ToolOp"):
        AgentManifest.model_validate(data)


def test_trusting_a_free_text_tool_refuses() -> None:
    # get_entry is a trusted read source; flip it to free-text (structured_output
    # false). Trusting a free-text tool waves injection surface through, so it is
    # refused at load, never at the wire (M11).
    data = _raw()
    for tool in data["mcp_servers"]["ledger"]["tools"]:
        if tool["tool_name"] == "get_entry":
            tool["structured_output"] = False
    with pytest.raises(ValidationError, match="structured_output=false"):
        AgentManifest.model_validate(data)


def test_server_exposes_exactly_the_safe_tools() -> None:
    # The archetype's whole claim is ABSENCE, so assert it on the running server,
    # not just in prose: the ledger surface is exactly {get_entry, list_entries} —
    # no append, delete, or admin tool exists to be admitted, quarantined, or denied.
    # Guarded: the manifest tests above need no SDK; only this one imports server.py.
    pytest.importorskip("mcp")
    import asyncio

    from examples.restricted_mcp_server import server

    tools = asyncio.run(server.mcp.list_tools())
    names = {t.name for t in tools}
    assert names == {"get_entry", "list_entries"}
    for hazard in ("append_entry", "delete_entry", "post_adjustment", "admin"):
        assert hazard not in names
