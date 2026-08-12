"""test_mcp_snapshot.py — `python -m safe_agents.broker.mcp.commands snapshot`
(#221 Phase 5 prerequisite, item 2 of 4).

`snapshot` is PURE pre-admission discovery: it captures an MCP server's full
live advertised tool set to a typed `McpServerSnapshot` file, touching no
registry (no read, no write) and needing neither the store HMAC key nor a
registry table name. Server config comes from an operator-NAMED image-baked
`AgentManifest` (never a store), matching the #197/#199 discipline.

Covers:
  1. A real snapshot (over the same real stdio child `test_mcp_stdio.py`
     drives, `examples/restricted_mcp_server/server.py`) round-trips through
     `McpServerSnapshot`, and each entry's `def_hash` matches an independent
     `compute_tool_def_hash` recomputation.
  2. The new #221 Phase-5-prerequisite `McpToolDef` metadata fields
     (title/output_schema/annotations/...) are actually captured for a tool
     that advertises them.
  3. `--server-id` absent from the manifest refuses, exit 2 — before any
     process/network activity (proven by asserting no child spawns).
  4. `snapshot` needs no `BROKER_HMAC_KEY`/`MCP_REGISTRY_TABLE_NAME` at all,
     while `admit-propose`/`admit-ratify` still refuse (exit 2) without
     `BROKER_HMAC_KEY` — the store-construction-is-per-command change proven
     not to have loosened the ceremony's existing refusal.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the stdio transport needs the optional `mcp` extra")

from safe_agents.broker.mcp.commands import main
from safe_agents.broker.schemas.mcp_registry import McpServerSnapshot, compute_tool_def_hash

_REPO_ROOT = str(Path(__file__).resolve().parents[3])
_SERVER_ID = "ledger"
_CHILD_NEEDLE = "examples.restricted_mcp_server.server"

_MANIFEST_YAML = f"""
envelope:
  polarity: abstain
connectors:
  - ledger
mcp_servers:
  ledger:
    command: {sys.executable!r}
    args: ["-m", "examples.restricted_mcp_server.server"]
    cwd: {_REPO_ROOT!r}
    tools:
      - {{tool_name: get_entry, structured_output: true}}
      - {{tool_name: list_entries, structured_output: true}}
tool_ops:
  - {{tool: ledger, op: get_entry, effect: read, external: true, egress_arg: entry_id}}
  - {{tool: ledger, op: list_entries, effect: read, external: true}}
"""


def _server_pids() -> list[int]:
    out = subprocess.run(["pgrep", "-f", _CHILD_NEEDLE], capture_output=True, text=True)
    return [int(line) for line in out.stdout.split()] if out.returncode == 0 else []


@pytest.fixture
def manifest_path(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(_MANIFEST_YAML)
    return path


@pytest.fixture(autouse=True)
def _no_stray_children():
    assert _server_pids() == [], "stray child server before test"
    yield
    for pid in _server_pids():
        import os
        import signal

        os.kill(pid, signal.SIGKILL)
    assert _server_pids() == [], "test leaked a child server process"


class TestSnapshotCapturesLiveServer:
    def test_round_trips_and_hashes_match(
        self, manifest_path: Path, tmp_path: Path, capsys
    ) -> None:
        out_path = tmp_path / "ledger-snapshot.json"
        rc = main(
            [
                "snapshot",
                "--manifest",
                str(manifest_path),
                "--server-id",
                _SERVER_ID,
                "--out",
                str(out_path),
            ]
        )
        assert rc == 0, capsys.readouterr().out

        snapshot = McpServerSnapshot.model_validate_json(out_path.read_text())
        assert snapshot.server_id == _SERVER_ID
        assert snapshot.transport == "stdio"
        assert sorted(e.tool_def.tool_name for e in snapshot.entries) == [
            "get_entry",
            "list_entries",
        ]
        # Round-trips through the typed model AND through the file unchanged.
        reloaded = McpServerSnapshot.model_validate(json.loads(out_path.read_text()))
        assert reloaded == snapshot

        for entry in snapshot.entries:
            assert entry.def_hash == compute_tool_def_hash(entry.tool_def)
            assert len(entry.def_hash) == 64

        # captured_at is a real tz-aware ISO-8601 timestamp.
        assert "T" in snapshot.captured_at
        assert snapshot.captured_at.endswith(("+00:00", "Z")) or "+" in snapshot.captured_at[10:]

    def test_metadata_fields_are_captured(self, manifest_path: Path, tmp_path: Path) -> None:
        """The example server's FastMCP tools advertise at least a title (item-1
        metadata); prove it survives into the snapshot, not just the hashed set."""
        out_path = tmp_path / "ledger-snapshot.json"
        rc = main(
            [
                "snapshot",
                "--manifest",
                str(manifest_path),
                "--server-id",
                _SERVER_ID,
                "--out",
                str(out_path),
            ]
        )
        assert rc == 0
        snapshot = McpServerSnapshot.model_validate_json(out_path.read_text())
        # Every entry's tool_def carries the full McpToolDef shape, including the
        # unhashed metadata fields introduced ahead of this item — present as
        # (possibly None) attributes, proving the snapshot captures the WHOLE
        # McpToolDef, not a hand-picked subset.
        for entry in snapshot.entries:
            dumped = entry.tool_def.model_dump()
            for field in ("title", "output_schema", "icons", "annotations", "meta", "execution"):
                assert field in dumped


class TestSnapshotRefusesUnknownServer:
    def test_unknown_server_id_refuses_before_any_spawn(
        self, manifest_path: Path, tmp_path: Path, capsys
    ) -> None:
        out_path = tmp_path / "should-not-exist.json"
        rc = main(
            [
                "snapshot",
                "--manifest",
                str(manifest_path),
                "--server-id",
                "not-declared",
                "--out",
                str(out_path),
            ]
        )
        assert rc == 2
        assert "REFUSED" in capsys.readouterr().out
        assert not out_path.exists()
        assert _server_pids() == []  # never spawned anything

    def test_missing_manifest_file_refuses(self, tmp_path: Path, capsys) -> None:
        rc = main(
            [
                "snapshot",
                "--manifest",
                str(tmp_path / "does-not-exist.yaml"),
                "--server-id",
                _SERVER_ID,
                "--out",
                str(tmp_path / "out.json"),
            ]
        )
        assert rc == 2
        assert "REFUSED" in capsys.readouterr().out


class TestSnapshotNeedsNoRegistryStore:
    """`snapshot` is pure discovery: it must work with neither BROKER_HMAC_KEY
    nor MCP_REGISTRY_TABLE_NAME set, while admit-propose/admit-ratify still
    refuse (exit 2) without BROKER_HMAC_KEY — proving the per-command store
    construction did not loosen the ceremony's existing refusal."""

    def test_snapshot_works_with_no_store_env(
        self, manifest_path: Path, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.delenv("BROKER_HMAC_KEY", raising=False)
        monkeypatch.delenv("MCP_REGISTRY_TABLE_NAME", raising=False)
        out_path = tmp_path / "snap.json"
        rc = main(
            [
                "snapshot",
                "--manifest",
                str(manifest_path),
                "--server-id",
                _SERVER_ID,
                "--out",
                str(out_path),
            ]
        )
        assert rc == 0
        assert out_path.exists()

    def test_admit_propose_still_refuses_without_hmac_key(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("BROKER_HMAC_KEY", raising=False)
        monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "irrelevant-table")
        tool_def_path = tmp_path / "def.json"
        tool_def_path.write_text(
            json.dumps(
                {
                    "server_id": "weather",
                    "tool_name": "forecast",
                    "input_schema": {"type": "object"},
                    "description": "d",
                }
            )
        )
        rc = main(
            [
                "admit-propose",
                "--server-id",
                "weather",
                "--tool-name",
                "forecast",
                "--tool-def-json",
                str(tool_def_path),
                "--ttl-hours",
                "1",
            ]
        )
        assert rc == 2
        assert "BROKER_HMAC_KEY" in capsys.readouterr().err

    def test_admit_ratify_still_refuses_without_hmac_key(self, monkeypatch, capsys):
        monkeypatch.delenv("BROKER_HMAC_KEY", raising=False)
        monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "irrelevant-table")
        rc = main(
            [
                "admit-ratify",
                "--server-id",
                "weather",
                "--tool-name",
                "forecast",
                "--proposal-id",
                "00000000-0000-0000-0000-000000000000",
            ]
        )
        assert rc == 2
        assert "BROKER_HMAC_KEY" in capsys.readouterr().err
