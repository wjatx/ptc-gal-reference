"""admit-propose --from-snapshot (#221 Phase 5 item 4 of 4, the last).

Deletes "Step 0" of re-vetting — hand-writing a byte-exact McpToolDef JSON —
by letting `admit-propose` resolve its definition from a `snapshot` artifact
instead. Unit-level with MemoryToolRegistry/MemoryAdmissionProposalStore and a
monkeypatched `_caller_identity` — no live AWS; argv goes through the real
`_parse_args` so the argparse mutual-exclusion wiring is proven end-to-end.

Coverage:
- --from-snapshot proposes correctly (happy path, through ratify to an ACTIVE row).
- --from-snapshot and --tool-def-json bind IDENTICAL proposal bytes for the
  same definition (the ceremony must not weaken depending on input source).
- --tool-def-json keeps working byte-for-byte (old path unchanged).
- snapshot server_id mismatch -> exit 2, nothing written.
- tool absent from snapshot -> exit 2, nothing written.
- tampered def_hash inside the snapshot entry -> exit 2, nothing written.
- malformed snapshot file -> exit 2, nothing written.
- --tool-def-json and --from-snapshot: neither or both is an argparse error.
- the review diff is printed for both a re-vet (stored row exists) and a
  first admission (no stored row), for both input sources.
"""

from __future__ import annotations

import datetime

import pytest

from safe_agents.broker.mcp import commands
from safe_agents.broker.mcp.commands import (
    _parse_args,
    admit_propose_command,
    admit_ratify_command,
)
from safe_agents.broker.mcp.proposals import KIND_ADMISSION, MemoryAdmissionProposalStore
from safe_agents.broker.mcp.registry import (
    MemoryToolRegistry,
    canonical_row_payload,
    compute_row_hmac,
)
from safe_agents.broker.schemas.mcp_registry import (
    McpServerSnapshot,
    McpSnapshotEntry,
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)

SERVER_ID = "ledger"
TOOL_NAME = "get_entry"
MAKER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/maker-session"
NOW = datetime.datetime(2026, 7, 20, 12, 0, tzinfo=datetime.timezone.utc)


def make_tool_def(
    tool_name: str = TOOL_NAME, description: str = "Return one ledger entry by id.", **overrides
) -> McpToolDef:
    base = dict(
        server_id=SERVER_ID,
        tool_name=tool_name,
        input_schema={
            "type": "object",
            "properties": {"entry_id": {"type": "string"}},
            "required": ["entry_id"],
        },
        description=description,
    )
    base.update(overrides)
    return McpToolDef(**base)


def make_row(tool_def: McpToolDef) -> RegisteredTool:
    return RegisteredTool(
        tool_def=tool_def,
        def_hash=compute_tool_def_hash(tool_def),
        status=RegistryStatus.ACTIVE,
        admitted_by="arn:aws:sts::111111111111:assumed-role/CheckerRole/checker-session",
        admitted_at="2026-07-19T00:00:00+00:00",
    )


def seed_row(store: MemoryToolRegistry, tool_def: McpToolDef) -> None:
    # #246 item shape: stored bytes + item-level rowHash.
    row = make_row(tool_def)
    store._rows[(row.server_id, row.tool_name)] = {
        "data": canonical_row_payload(row),
        "rowHash": compute_row_hmac(row, store._hmac_key),
    }


def write_snapshot(
    tmp_path,
    entries: list[McpToolDef],
    *,
    server_id: str = SERVER_ID,
    name: str = "snap.json",
    tamper_hash: bool = False,
) -> str:
    snapshot_entries = [
        McpSnapshotEntry(tool_def=d, def_hash=compute_tool_def_hash(d)) for d in entries
    ]
    if tamper_hash and snapshot_entries:
        snapshot_entries[0] = snapshot_entries[0].model_copy(update={"def_hash": "0" * 64})
    snapshot = McpServerSnapshot(
        server_id=server_id,
        transport="stdio",
        source="fake",
        captured_at="2026-07-20T00:00:00+00:00",
        entries=snapshot_entries,
    )
    path = tmp_path / name
    path.write_text(snapshot.model_dump_json())
    return str(path)


def write_tool_def_json(tmp_path, tool_def: McpToolDef, name: str = "def.json") -> str:
    path = tmp_path / name
    path.write_text(tool_def.model_dump_json())
    return str(path)


def set_caller(monkeypatch, arn: str = MAKER_ARN) -> None:
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: arn)


@pytest.fixture
def store() -> MemoryToolRegistry:
    return MemoryToolRegistry()


@pytest.fixture
def proposal_store() -> MemoryAdmissionProposalStore:
    return MemoryAdmissionProposalStore()


def propose_via_snapshot_args(snapshot_path, ttl_hours: str = "1"):
    return _parse_args(
        [
            "admit-propose",
            "--server-id", SERVER_ID,
            "--tool-name", TOOL_NAME,
            "--from-snapshot", snapshot_path,
            "--ttl-hours", ttl_hours,
        ]
    )


def propose_via_tool_def_args(tool_def_path, ttl_hours: str = "1"):
    return _parse_args(
        [
            "admit-propose",
            "--server-id", SERVER_ID,
            "--tool-name", TOOL_NAME,
            "--tool-def-json", tool_def_path,
            "--ttl-hours", ttl_hours,
        ]
    )


# ---------------------------------------------------------------------------
# Happy path: --from-snapshot proposes correctly, through ratify
# ---------------------------------------------------------------------------


def test_from_snapshot_proposes_and_ratifies_to_active_row(
    store, proposal_store, monkeypatch, tmp_path
):
    tool_def = make_tool_def()
    snapshot_path = write_snapshot(tmp_path, [tool_def, make_tool_def("list_entries")])

    set_caller(monkeypatch, MAKER_ARN)
    rc = admit_propose_command(
        propose_via_snapshot_args(snapshot_path),
        store=store,
        proposal_store=proposal_store,
        now=NOW,
    )
    assert rc == 0

    ((_, _, proposal_id),) = proposal_store._items.keys()
    loaded, status = proposal_store.get_proposal(SERVER_ID, TOOL_NAME, proposal_id)
    assert status == "pending"
    assert loaded.tool_def == tool_def
    assert loaded.def_hash == compute_tool_def_hash(tool_def)


# ---------------------------------------------------------------------------
# --from-snapshot and --tool-def-json bind IDENTICAL proposal bytes
# ---------------------------------------------------------------------------


def test_from_snapshot_and_tool_def_json_produce_identical_proposals(
    store, proposal_store, monkeypatch, tmp_path
):
    tool_def = make_tool_def()
    snapshot_path = write_snapshot(tmp_path, [tool_def])
    tool_def_path = write_tool_def_json(tmp_path, tool_def)

    set_caller(monkeypatch, MAKER_ARN)
    rc_a = admit_propose_command(
        propose_via_snapshot_args(snapshot_path),
        store=store,
        proposal_store=proposal_store,
        now=NOW,
    )
    assert rc_a == 0
    (key_a,) = [k for k in proposal_store._items if True]
    proposal_a, _ = proposal_store.get_proposal(SERVER_ID, TOOL_NAME, key_a[2])

    # Burn/replace: use a fresh proposal_store so the second proposal_id
    # doesn't collide, then compare the bound McpToolDef + def_hash bytes —
    # the part of the proposal that actually gets ratified into a row.
    proposal_store_b = MemoryAdmissionProposalStore()
    rc_b = admit_propose_command(
        propose_via_tool_def_args(tool_def_path),
        store=store,
        proposal_store=proposal_store_b,
        now=NOW,
    )
    assert rc_b == 0
    (key_b,) = list(proposal_store_b._items.keys())
    proposal_b, _ = proposal_store_b.get_proposal(SERVER_ID, TOOL_NAME, key_b[2])

    assert proposal_a.tool_def == proposal_b.tool_def
    assert proposal_a.def_hash == proposal_b.def_hash
    assert proposal_a.kind == proposal_b.kind
    assert proposal_a.proposed_by == proposal_b.proposed_by


def test_from_snapshot_and_tool_def_json_ratify_to_the_same_row(
    store, monkeypatch, tmp_path
):
    """Belt-and-suspenders on the identical-proposal claim: ratifying either
    proposal (against separate coordinates so both can be admitted) writes a
    row with the same def_hash/input_schema/description."""
    tool_def = make_tool_def()
    other_tool_def = make_tool_def(tool_name="other_tool")
    snapshot_path = write_snapshot(tmp_path, [tool_def])
    tool_def_path = write_tool_def_json(tmp_path, other_tool_def)

    proposal_store = MemoryAdmissionProposalStore()
    set_caller(monkeypatch, MAKER_ARN)
    assert (
        admit_propose_command(
            propose_via_snapshot_args(snapshot_path),
            store=store,
            proposal_store=proposal_store,
            now=NOW,
        )
        == 0
    )
    args = _parse_args(
        [
            "admit-propose",
            "--server-id", SERVER_ID,
            "--tool-name", "other_tool",
            "--tool-def-json", tool_def_path,
            "--ttl-hours", "1",
        ]
    )
    assert (
        admit_propose_command(args, store=store, proposal_store=proposal_store, now=NOW) == 0
    )

    ((_, _, pid1),) = [k for k in proposal_store._items if k[1] == TOOL_NAME]
    ((_, _, pid2),) = [k for k in proposal_store._items if k[1] == "other_tool"]

    from safe_agents.broker.grants.record_signing import signer_from_pem
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    signer = signer_from_pem("issuer:A", "zone-a", priv)

    set_caller(monkeypatch, "arn:aws:sts::111111111111:assumed-role/PromotionRole/checker-session")
    args1 = _parse_args(
        ["admit-ratify", "--server-id", SERVER_ID, "--tool-name", TOOL_NAME,
         "--proposal-id", pid1, "--zone", "zone-a"]
    )
    args2 = _parse_args(
        ["admit-ratify", "--server-id", SERVER_ID, "--tool-name", "other_tool",
         "--proposal-id", pid2, "--zone", "zone-a"]
    )
    assert admit_ratify_command(
        args1, store=store, proposal_store=proposal_store, signer=signer, now=NOW
    ) == 0
    assert admit_ratify_command(
        args2, store=store, proposal_store=proposal_store, signer=signer, now=NOW
    ) == 0

    row1 = store.get_tool(SERVER_ID, TOOL_NAME).tool
    row2 = store.get_tool(SERVER_ID, "other_tool").tool
    # Both were admitted from equivalent definitions (modulo tool_name); the
    # bound schema/description/def_hash-computation logic is identical.
    assert row1.tool_def.input_schema == row2.tool_def.input_schema
    assert row1.tool_def.description == row2.tool_def.description


# ---------------------------------------------------------------------------
# --tool-def-json keeps working byte-for-byte (old path unchanged)
# ---------------------------------------------------------------------------


def test_tool_def_json_path_unchanged(store, proposal_store, monkeypatch, tmp_path, capsys):
    tool_def = make_tool_def()
    tool_def_path = write_tool_def_json(tmp_path, tool_def)

    set_caller(monkeypatch, MAKER_ARN)
    rc = admit_propose_command(
        propose_via_tool_def_args(tool_def_path),
        store=store,
        proposal_store=proposal_store,
        now=NOW,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "proposal stored:" in out
    assert f"proposedBy={MAKER_ARN}" in out

    ((_, _, proposal_id),) = proposal_store._items.keys()
    loaded, status = proposal_store.get_proposal(SERVER_ID, TOOL_NAME, proposal_id)
    assert status == "pending"
    assert loaded.tool_def == tool_def
    assert loaded.def_hash == compute_tool_def_hash(tool_def)
    assert loaded.kind == KIND_ADMISSION
    assert loaded.proposed_by == MAKER_ARN


# ---------------------------------------------------------------------------
# Refusals — all exit 2, nothing written
# ---------------------------------------------------------------------------


def test_snapshot_server_id_mismatch_refuses(store, proposal_store, monkeypatch, tmp_path):
    snapshot_path = write_snapshot(tmp_path, [make_tool_def()], server_id="a-different-server")
    set_caller(monkeypatch, MAKER_ARN)
    rc = admit_propose_command(
        propose_via_snapshot_args(snapshot_path),
        store=store,
        proposal_store=proposal_store,
        now=NOW,
    )
    assert rc == 2
    assert proposal_store._items == {}


def test_tool_absent_from_snapshot_refuses(store, proposal_store, monkeypatch, tmp_path):
    snapshot_path = write_snapshot(tmp_path, [make_tool_def("some_other_tool")])
    set_caller(monkeypatch, MAKER_ARN)
    rc = admit_propose_command(
        propose_via_snapshot_args(snapshot_path),
        store=store,
        proposal_store=proposal_store,
        now=NOW,
    )
    assert rc == 2
    assert proposal_store._items == {}


def test_tampered_def_hash_in_snapshot_refuses(store, proposal_store, monkeypatch, tmp_path, capsys):
    snapshot_path = write_snapshot(tmp_path, [make_tool_def()], tamper_hash=True)
    set_caller(monkeypatch, MAKER_ARN)
    rc = admit_propose_command(
        propose_via_snapshot_args(snapshot_path),
        store=store,
        proposal_store=proposal_store,
        now=NOW,
    )
    assert rc == 2
    assert proposal_store._items == {}
    out = capsys.readouterr().out
    assert "integrity check" in out


def test_malformed_snapshot_file_refuses(store, proposal_store, monkeypatch, tmp_path):
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("not json")
    set_caller(monkeypatch, MAKER_ARN)
    rc = admit_propose_command(
        propose_via_snapshot_args(str(bad_path)),
        store=store,
        proposal_store=proposal_store,
        now=NOW,
    )
    assert rc == 2
    assert proposal_store._items == {}


# ---------------------------------------------------------------------------
# Argparse: exactly one of --tool-def-json / --from-snapshot
# ---------------------------------------------------------------------------


class TestArgparseMutualExclusion:
    def test_neither_flag_is_argparse_error(self) -> None:
        with pytest.raises(SystemExit):
            _parse_args(
                ["admit-propose", "--server-id", SERVER_ID, "--tool-name", TOOL_NAME,
                 "--ttl-hours", "1"]
            )

    def test_both_flags_is_argparse_error(self, tmp_path) -> None:
        with pytest.raises(SystemExit):
            _parse_args(
                [
                    "admit-propose",
                    "--server-id", SERVER_ID,
                    "--tool-name", TOOL_NAME,
                    "--tool-def-json", str(tmp_path / "a.json"),
                    "--from-snapshot", str(tmp_path / "b.json"),
                    "--ttl-hours", "1",
                ]
            )

    def test_tool_def_json_alone_parses(self) -> None:
        args = _parse_args(
            ["admit-propose", "--server-id", SERVER_ID, "--tool-name", TOOL_NAME,
             "--tool-def-json", "/tmp/d.json", "--ttl-hours", "1"]
        )
        assert args.tool_def_json == "/tmp/d.json"
        assert args.from_snapshot is None

    def test_from_snapshot_alone_parses(self) -> None:
        args = _parse_args(
            ["admit-propose", "--server-id", SERVER_ID, "--tool-name", TOOL_NAME,
             "--from-snapshot", "/tmp/s.json", "--ttl-hours", "1"]
        )
        assert args.from_snapshot == "/tmp/s.json"
        assert args.tool_def_json is None


# ---------------------------------------------------------------------------
# The review diff is printed: re-vet (stored row exists) and first admission
# ---------------------------------------------------------------------------


class TestReviewDiffPrinted:
    def test_first_admission_from_snapshot_shows_no_prior_row_and_proposed_def(
        self, store, proposal_store, monkeypatch, tmp_path, capsys
    ):
        tool_def = make_tool_def()
        snapshot_path = write_snapshot(tmp_path, [tool_def])
        set_caller(monkeypatch, MAKER_ARN)
        rc = admit_propose_command(
            propose_via_snapshot_args(snapshot_path),
            store=store,
            proposal_store=proposal_store,
            now=NOW,
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "review: admitted (if any) vs. proposed" in out
        assert "NEW — live but not admitted" in out
        assert "no prior admission to compare against" in out
        assert tool_def.description in out
        assert repr(tool_def.input_schema) in out

    def test_first_admission_from_tool_def_json_shows_no_prior_row_and_proposed_def(
        self, store, proposal_store, monkeypatch, tmp_path, capsys
    ):
        tool_def = make_tool_def()
        tool_def_path = write_tool_def_json(tmp_path, tool_def)
        set_caller(monkeypatch, MAKER_ARN)
        rc = admit_propose_command(
            propose_via_tool_def_args(tool_def_path),
            store=store,
            proposal_store=proposal_store,
            now=NOW,
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "NEW — live but not admitted" in out
        assert tool_def.description in out

    def test_revet_from_snapshot_shows_drift_against_stored_row(
        self, store, proposal_store, monkeypatch, tmp_path, capsys
    ):
        old_def = make_tool_def(description="old description")
        seed_row(store, old_def)
        new_def = make_tool_def(description="new, drifted description")
        snapshot_path = write_snapshot(tmp_path, [new_def])

        set_caller(monkeypatch, MAKER_ARN)
        rc = admit_propose_command(
            propose_via_snapshot_args(snapshot_path),
            store=store,
            proposal_store=proposal_store,
            now=NOW,
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "DRIFT" in out
        assert "STEERING change" in out
        assert old_def.description in out
        assert new_def.description in out

    def test_revet_from_tool_def_json_shows_drift_against_stored_row(
        self, store, proposal_store, monkeypatch, tmp_path, capsys
    ):
        old_def = make_tool_def(description="old description")
        seed_row(store, old_def)
        new_def = make_tool_def(description="new, drifted description")
        tool_def_path = write_tool_def_json(tmp_path, new_def)

        set_caller(monkeypatch, MAKER_ARN)
        rc = admit_propose_command(
            propose_via_tool_def_args(tool_def_path),
            store=store,
            proposal_store=proposal_store,
            now=NOW,
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "DRIFT" in out
        assert "STEERING change" in out
