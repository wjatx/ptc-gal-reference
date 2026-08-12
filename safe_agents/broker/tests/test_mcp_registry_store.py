"""MCP admitted-tool registry store + admission ceremony (#174).

Mirrors the grants store/ceremony conformance suites (test_grants_store.py,
test_grants_commands.py): unit-level with the Memory stores and a monkeypatched
_caller_identity — no live AWS. argv goes through the real _parse_args so the
argparse wiring is proven end-to-end.

Coverage:
- compute_row_hmac round-trip (deterministic, field-sensitive) + un-quarantined read.
- a tampered stored row surfaces a quarantine flag; the row is returned for audit.
- admit_tool refuses to write over an HMAC-quarantined row (M6).
- admit-propose → admit-ratify happy path: record written then row (both present),
  the admission record verifies against the issuer public key (M8).
- maker == checker (same STS arn) ratify → structural refusal, proposal pending (M7).
- an expired proposal → refusal.
- a tampered stored proposal → ProposalIntegrityError refusal.
- a re-vet against a NEW definition updates the row def_hash and appends a 2nd record.
- admit-ratify with no issuer signer refuses (M8); issuer_keys refuses a
  half-configured signing environment (#201).
"""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safe_agents.broker.grants import issuer_keys
from safe_agents.broker.grants.issuer_keys import IssuerSigningConfigError
from safe_agents.broker.grants.record_signing import signer_from_pem
from safe_agents.broker.mcp import commands
from safe_agents.broker.mcp.commands import (
    _parse_args,
    admit_propose_command,
    admit_ratify_command,
)
from safe_agents.broker.mcp.proposals import (
    KIND_ADMISSION,
    KIND_REVET,
    MemoryAdmissionProposalStore,
)
from safe_agents.broker.mcp.registry import (
    DynamoToolRegistry,
    MemoryToolRegistry,
    QuarantinedToolRowError,
    ToolReadResult,
    ToolRowConflictError,
    canonical_row_payload,
    compute_row_hmac,
)
from safe_agents.broker.prototype.boot_config import BrokerConfigError
from safe_agents.broker.mcp.signing import verify_admission_record, canonical_record_payload
from safe_agents.broker.schemas.mcp_registry import (
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)
from safe_agents.channels.keys import key_resolver_from_map

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

SERVER_ID = "market-data"
TOOL_NAME = "quote"
MAKER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/maker-session"
CHECKER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/checker-session"
NOW = datetime.datetime(2026, 7, 17, 12, 0, tzinfo=datetime.timezone.utc)


def make_tool_def(description: str = "return a quote") -> McpToolDef:
    return McpToolDef(
        server_id=SERVER_ID,
        tool_name=TOOL_NAME,
        input_schema={"type": "object", "properties": {"symbol": {"type": "string"}}},
        description=description,
    )


def make_row(tool_def: McpToolDef | None = None) -> RegisteredTool:
    tool_def = tool_def or make_tool_def()
    return RegisteredTool(
        tool_def=tool_def,
        def_hash=compute_tool_def_hash(tool_def),
        status=RegistryStatus.ACTIVE,
        admitted_by=CHECKER_ARN,
        admitted_at="2026-07-17T00:00:00+00:00",
    )


@pytest.fixture
def store() -> MemoryToolRegistry:
    return MemoryToolRegistry()


@pytest.fixture
def proposal_store() -> MemoryAdmissionProposalStore:
    return MemoryAdmissionProposalStore()


def _keypair() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = (
        sk.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return priv, pub


@pytest.fixture
def signer_and_resolver():
    priv, pub = _keypair()
    return signer_from_pem("issuer:A", "zone-a", priv), key_resolver_from_map({"issuer:A": pub})


def set_caller(monkeypatch, arn: str) -> None:
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: arn)


def propose_args(tool_def_path, kind: str = KIND_ADMISSION, ttl_hours: str = "1"):
    return _parse_args(
        [
            "admit-propose",
            "--server-id", SERVER_ID,
            "--tool-name", TOOL_NAME,
            "--tool-def-json", str(tool_def_path),
            "--kind", kind,
            "--ttl-hours", ttl_hours,
        ]
    )


def ratify_args(proposal_id: str):
    return _parse_args(
        [
            "admit-ratify",
            "--server-id", SERVER_ID,
            "--tool-name", TOOL_NAME,
            "--proposal-id", proposal_id,
            "--zone", "zone-a",
        ]
    )


def run_propose(proposal_store, monkeypatch, tool_def_path, *, caller=MAKER_ARN,
                kind=KIND_ADMISSION, ttl_hours="1", now=NOW, store=None) -> str:
    set_caller(monkeypatch, caller)
    before = set(proposal_store._items.keys())
    # `store` is read-only here: propose renders the admitted-vs-proposed review
    # diff before writing. A fresh empty registry renders the first-admission
    # branch, which is what these ceremony tests exercise.
    rc = admit_propose_command(
        propose_args(tool_def_path, kind, ttl_hours),
        store=store if store is not None else MemoryToolRegistry(),
        proposal_store=proposal_store,
        now=now,
    )
    assert rc == 0
    new = set(proposal_store._items.keys()) - before
    assert len(new) == 1
    return next(iter(new))[2]


def write_tool_def(tmp_path, name: str, tool_def: McpToolDef):
    path = tmp_path / name
    path.write_text(tool_def.model_dump_json())
    return path


# ---------------------------------------------------------------------------
# Store-level: HMAC round-trip, quarantine-on-read, refuse-overwrite (M13, M6)
# ---------------------------------------------------------------------------


def test_compute_row_hmac_is_deterministic_and_field_sensitive():
    row = make_row()
    key = b"k"
    assert compute_row_hmac(row, key) == compute_row_hmac(row, key)
    other = row.model_copy(update={"tool_def": make_tool_def("something else")})
    assert compute_row_hmac(row, key) != compute_row_hmac(other, key)


def test_admit_tool_round_trip_reads_unquarantined(store):
    row = make_row()
    store.admit_tool(row)
    result = store.get_tool(SERVER_ID, TOOL_NAME)
    assert not result.quarantined
    assert result.tool is not None
    assert result.tool.status is RegistryStatus.ACTIVE
    assert result.tool.def_hash == compute_tool_def_hash(make_tool_def())
    # #246 stored-bytes basis: the item-level rowHash is the HMAC over the
    # stored data string, which IS the canonical row payload.
    assert result.raw_data == canonical_row_payload(row)
    assert result.stored_hash == compute_row_hmac(row, store._hmac_key)


def test_tampered_row_surfaces_quarantine_flag(store):
    store.admit_tool(make_row())
    store._rows[(SERVER_ID, TOOL_NAME)]["rowHash"] = "tampered-hash-value"
    result = store.get_tool(SERVER_ID, TOOL_NAME)
    assert result.quarantined is True
    assert result.quarantine_reason is not None
    # #246: tampered bytes are evidence, never parsed — tool is None and the
    # raw bytes ride along for audit.
    assert result.tool is None
    assert result.raw_data is not None


def test_write_over_quarantined_row_refused(store):
    store.admit_tool(make_row())
    store._rows[(SERVER_ID, TOOL_NAME)]["rowHash"] = "bad"
    with pytest.raises(QuarantinedToolRowError):
        store.admit_tool(make_row(make_tool_def("a re-vetted definition")))


# ---------------------------------------------------------------------------
# Conditional row write — #190 mirror (Finding A): the write binds to the
# guarded re-read, so a row changed underfoot is refused, never overwritten
# ---------------------------------------------------------------------------


def test_admit_tool_refuses_write_when_row_changed_underfoot(store):
    """A concurrent re-vet landing between the guarded re-read and our write
    fails the conditional write — overwriting it would launder the concurrent
    state under a fresh HMAC and destroy the tamper/concurrency evidence (M6)."""
    store.admit_tool(make_row())
    snap = store.get_tool(SERVER_ID, TOOL_NAME)  # the baseline the caller evaluated

    # A concurrent re-vet lands (its own conditional write succeeds against the
    # then-current row), moving the coordinate off `snap`.
    store.admit_tool(make_row(make_tool_def("concurrently re-vetted")))
    after_concurrent = store.get_tool(SERVER_ID, TOOL_NAME).raw_data

    # Our write, conditioned on the now-stale snapshot, is refused.
    with pytest.raises(ToolRowConflictError):
        store.admit_tool(make_row(make_tool_def("our stale re-vet")), expected=snap)
    # The row is unchanged — the concurrent state stands for audit.
    assert store.get_tool(SERVER_ID, TOOL_NAME).raw_data == after_concurrent


def test_admit_tool_revet_with_correct_expected_state_succeeds(store):
    """The same coordinate, re-vetted against the state actually read, writes."""
    store.admit_tool(make_row())
    snap = store.get_tool(SERVER_ID, TOOL_NAME)
    revet_def = make_tool_def("return a quote; now also read the ledger")
    store.admit_tool(make_row(revet_def), expected=snap)

    result = store.get_tool(SERVER_ID, TOOL_NAME)
    assert not result.quarantined
    assert result.tool.def_hash == compute_tool_def_hash(revet_def)


def test_admit_tool_first_admission_refuses_concurrent_create(store):
    """A first admission conditioned on 'no row' is refused if a row was created
    concurrently — never silently overwrites the row that won the race."""
    empty_snap = store.get_tool(SERVER_ID, TOOL_NAME)  # tool=None baseline
    assert empty_snap.tool is None

    store.admit_tool(make_row())  # a row is created concurrently
    winner = store.get_tool(SERVER_ID, TOOL_NAME).raw_data

    with pytest.raises(ToolRowConflictError):
        store.admit_tool(
            make_row(make_tool_def("racing first admission")), expected=empty_snap
        )
    assert store.get_tool(SERVER_ID, TOOL_NAME).raw_data == winner


# ---------------------------------------------------------------------------
# The DynamoDB arm conditions identically (Finding A) — expression shape +
# ConditionalCheckFailedException -> ToolRowConflictError, mirroring
# test_grants_store's update_grant coverage
# ---------------------------------------------------------------------------


def _dynamo_store_with_read(monkeypatch, read: ToolReadResult) -> DynamoToolRegistry:
    """A DynamoToolRegistry whose guarded re-read is stubbed to `read` (get_tool
    reads via a session-less client; the stub keeps the test AWS-free)."""
    store = DynamoToolRegistry(hmac_key=b"k", table_name="T")
    monkeypatch.setattr(store, "get_tool", lambda server_id, tool_name: read)
    return store


def _capture_admit(store: DynamoToolRegistry, row, *, expected=None) -> dict:
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    store.admit_tool(row, session=mock_session, expected=expected)
    assert mock_table.update_item.call_count == 1
    return mock_table.update_item.call_args.kwargs


def test_dynamo_admit_tool_first_admission_conditions_on_absence(monkeypatch):
    store = _dynamo_store_with_read(monkeypatch, ToolReadResult(tool=None))
    row = make_row()
    kwargs = _capture_admit(store, row)

    assert kwargs["ConditionExpression"] == "attribute_not_exists(pk)"
    assert kwargs["UpdateExpression"] == "SET #data = :data, rowHash = :new_hash"
    assert kwargs["ExpressionAttributeNames"] == {"#data": "data"}
    # #246: the written data IS the canonical payload and :new_hash is the
    # HMAC over those exact bytes (the item-level slot is the only one).
    assert kwargs["ExpressionAttributeValues"][":data"] == canonical_row_payload(row)
    assert kwargs["ExpressionAttributeValues"][":new_hash"] == compute_row_hmac(row, b"k")


def test_dynamo_admit_tool_revet_conditions_on_rowhash_and_data(monkeypatch):
    existing = make_row()
    # The guarded re-read's baseline: stored bytes + item-level hash (#246).
    snap = ToolReadResult(
        tool=existing,
        raw_data=canonical_row_payload(existing),
        stored_hash=compute_row_hmac(existing, b"k"),
    )
    store = _dynamo_store_with_read(monkeypatch, snap)

    kwargs = _capture_admit(store, make_row(make_tool_def("revet")), expected=snap)

    assert kwargs["ConditionExpression"] == (
        "attribute_exists(pk) AND rowHash = :expected AND #data = :prev_data"
    )
    assert kwargs["ExpressionAttributeValues"][":expected"] == snap.stored_hash
    assert kwargs["ExpressionAttributeValues"][":prev_data"] == snap.raw_data


def test_dynamo_admit_tool_maps_conditional_failure_to_conflict(monkeypatch):
    from botocore.exceptions import ClientError

    store = _dynamo_store_with_read(monkeypatch, ToolReadResult(tool=None))
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    mock_table.update_item.side_effect = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "failed"}},
        "UpdateItem",
    )
    with pytest.raises(ToolRowConflictError):
        store.admit_tool(make_row(), session=mock_session)


def test_dynamo_admit_tool_propagates_access_denied(monkeypatch):
    """AccessDenied is NOT mapped to a conflict — the caller must see it."""
    from botocore.exceptions import ClientError

    store = _dynamo_store_with_read(monkeypatch, ToolReadResult(tool=None))
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    mock_table.update_item.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}},
        "UpdateItem",
    )
    with pytest.raises(ClientError):
        store.admit_tool(make_row(), session=mock_session)


# ---------------------------------------------------------------------------
# Ceremony: propose → ratify happy path (M7, M8; record-before-row)
# ---------------------------------------------------------------------------


def test_admit_propose_ratify_happy_path(store, proposal_store, monkeypatch, signer_and_resolver, tmp_path):
    signer, resolver = signer_and_resolver
    path = write_tool_def(tmp_path, "def.json", make_tool_def())
    proposal_id = run_propose(proposal_store, monkeypatch, path)

    set_caller(monkeypatch, CHECKER_ARN)
    rc = admit_ratify_command(
        ratify_args(proposal_id), store=store, proposal_store=proposal_store, signer=signer, now=NOW
    )
    assert rc == 0

    # Row present and ACTIVE at the admitted def_hash.
    result = store.get_tool(SERVER_ID, TOOL_NAME)
    assert not result.quarantined
    assert result.tool.status is RegistryStatus.ACTIVE
    assert result.tool.def_hash == compute_tool_def_hash(make_tool_def())
    assert result.tool.admitted_by == CHECKER_ARN

    # Exactly one admission record, and it verifies against the issuer pubkey.
    records = store.list_records(SERVER_ID, TOOL_NAME)
    assert len(records) == 1
    record = records[0]
    assert record.recordType == KIND_ADMISSION
    assert record.proposedBy == MAKER_ARN and record.ratifiedBy == CHECKER_ARN
    envelope = store.get_record_signature(SERVER_ID, TOOL_NAME, record.ts)
    assert verify_admission_record(canonical_record_payload(record), envelope, resolver).ok

    # The proposal is burned (single-shot).
    _, status = proposal_store.get_proposal(SERVER_ID, TOOL_NAME, proposal_id)
    assert status == "ratified"


def test_same_identity_ratify_refused(store, proposal_store, monkeypatch, signer_and_resolver, tmp_path):
    signer, _ = signer_and_resolver
    path = write_tool_def(tmp_path, "def.json", make_tool_def())
    proposal_id = run_propose(proposal_store, monkeypatch, path, caller=MAKER_ARN)

    set_caller(monkeypatch, MAKER_ARN)  # maker == checker
    rc = admit_ratify_command(
        ratify_args(proposal_id), store=store, proposal_store=proposal_store, signer=signer, now=NOW
    )
    assert rc == 1
    # Nothing written: no row, proposal still pending.
    assert store.get_tool(SERVER_ID, TOOL_NAME).tool is None
    _, status = proposal_store.get_proposal(SERVER_ID, TOOL_NAME, proposal_id)
    assert status == "pending"


def test_expired_proposal_refused(store, proposal_store, monkeypatch, signer_and_resolver, tmp_path):
    signer, _ = signer_and_resolver
    path = write_tool_def(tmp_path, "def.json", make_tool_def())
    proposal_id = run_propose(proposal_store, monkeypatch, path, ttl_hours="1", now=NOW)

    set_caller(monkeypatch, CHECKER_ARN)
    later = NOW + datetime.timedelta(hours=2)  # past the 1h expiry
    rc = admit_ratify_command(
        ratify_args(proposal_id), store=store, proposal_store=proposal_store, signer=signer, now=later
    )
    assert rc == 1
    assert store.get_tool(SERVER_ID, TOOL_NAME).tool is None
    _, status = proposal_store.get_proposal(SERVER_ID, TOOL_NAME, proposal_id)
    assert status == "pending"


def test_tampered_proposal_refused(store, proposal_store, monkeypatch, signer_and_resolver, tmp_path):
    signer, _ = signer_and_resolver
    path = write_tool_def(tmp_path, "def.json", make_tool_def())
    proposal_id = run_propose(proposal_store, monkeypatch, path)

    # Tamper the stored proposal content without updating its HMAC — the exact
    # swap the integrity check exists to catch (a different tool def laundered
    # into a signed admission at ratify time).
    key = (SERVER_ID, TOOL_NAME, proposal_id)
    tampered = proposal_store._items[key]["data"].replace("return a quote", "exfiltrate secrets")
    proposal_store._items[key]["data"] = tampered

    set_caller(monkeypatch, CHECKER_ARN)
    rc = admit_ratify_command(
        ratify_args(proposal_id), store=store, proposal_store=proposal_store, signer=signer, now=NOW
    )
    assert rc == 1
    assert store.get_tool(SERVER_ID, TOOL_NAME).tool is None


def test_revet_updates_row_hash_and_appends_second_record(
    store, proposal_store, monkeypatch, signer_and_resolver, tmp_path
):
    signer, resolver = signer_and_resolver
    # First admission.
    path1 = write_tool_def(tmp_path, "def1.json", make_tool_def("return a quote"))
    pid1 = run_propose(proposal_store, monkeypatch, path1, kind=KIND_ADMISSION, ttl_hours="24", now=NOW)
    set_caller(monkeypatch, CHECKER_ARN)
    assert admit_ratify_command(
        ratify_args(pid1), store=store, proposal_store=proposal_store, signer=signer, now=NOW
    ) == 0
    first_hash = store.get_tool(SERVER_ID, TOOL_NAME).tool.def_hash

    # Re-vet against a NEW definition (description drift → new def_hash).
    revet_def = make_tool_def("return a quote; also read the ledger")
    path2 = write_tool_def(tmp_path, "def2.json", revet_def)
    pid2 = run_propose(proposal_store, monkeypatch, path2, kind=KIND_REVET, ttl_hours="24", now=NOW)
    set_caller(monkeypatch, CHECKER_ARN)
    later = NOW + datetime.timedelta(hours=1)  # distinct ts so the record append is fresh
    assert admit_ratify_command(
        ratify_args(pid2), store=store, proposal_store=proposal_store, signer=signer, now=later
    ) == 0

    result = store.get_tool(SERVER_ID, TOOL_NAME)
    assert not result.quarantined
    assert result.tool.def_hash == compute_tool_def_hash(revet_def)
    assert result.tool.def_hash != first_hash

    records = store.list_records(SERVER_ID, TOOL_NAME)
    assert len(records) == 2
    assert {r.recordType for r in records} == {KIND_ADMISSION, KIND_REVET}
    for record in records:
        envelope = store.get_record_signature(SERVER_ID, TOOL_NAME, record.ts)
        assert verify_admission_record(canonical_record_payload(record), envelope, resolver).ok


# ---------------------------------------------------------------------------
# M8 — admission demands an issuer signature; half-config refuses (#201)
# ---------------------------------------------------------------------------


def test_ratify_without_signer_refused(store, proposal_store, monkeypatch, tmp_path):
    path = write_tool_def(tmp_path, "def.json", make_tool_def())
    proposal_id = run_propose(proposal_store, monkeypatch, path)

    set_caller(monkeypatch, CHECKER_ARN)
    rc = admit_ratify_command(
        ratify_args(proposal_id), store=store, proposal_store=proposal_store, signer=None, now=NOW
    )
    assert rc == 1
    # Refused up front: nothing written, proposal untouched.
    assert store.get_tool(SERVER_ID, TOOL_NAME).tool is None
    assert store.list_records(SERVER_ID, TOOL_NAME) == []
    _, status = proposal_store.get_proposal(SERVER_ID, TOOL_NAME, proposal_id)
    assert status == "pending"


def test_half_configured_issuer_signing_refuses(monkeypatch):
    # key_id set, ARN unset — signing is half-configured; resolve refuses rather
    # than degrading to an unsigned record (the ceremony surfaces this via main).
    monkeypatch.setenv(issuer_keys.ISSUER_SIGNING_KEY_ID_ENV, "issuer:A")
    monkeypatch.delenv(issuer_keys.ISSUER_SIGNING_KEY_SECRET_ARN_ENV, raising=False)
    with pytest.raises(IssuerSigningConfigError):
        issuer_keys.resolve_record_signer(zone="zone-a")


# ---------------------------------------------------------------------------
# Ceremony named-config-or-refuse (#205): the real table write must NAME its
# HMAC key and its table — never a dev fallback (Findings B, C)
# ---------------------------------------------------------------------------


def test_build_stores_refuses_without_hmac_key(monkeypatch):
    """The ceremony always writes the real table, so BROKER_HMAC_KEY must be
    named — a dev-key fallback would HMAC rows the broker then quarantines
    (Finding B). Refuses regardless of BROKER_STORE (never routes through the
    broker's read-side resolve_hmac_key dev fallback)."""
    monkeypatch.delenv("BROKER_HMAC_KEY", raising=False)
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "some-table")
    with pytest.raises(BrokerConfigError, match="BROKER_HMAC_KEY"):
        commands._build_stores(None)


def test_build_stores_refuses_without_table_name(monkeypatch):
    """A missing MCP_REGISTRY_TABLE_NAME is a clean refusal, never the raw
    KeyError DynamoToolRegistry would raise at first use (Finding C)."""
    monkeypatch.setenv("BROKER_HMAC_KEY", "k")
    monkeypatch.delenv("MCP_REGISTRY_TABLE_NAME", raising=False)
    with pytest.raises(BrokerConfigError, match="MCP registry table"):
        commands._build_stores(None)


def test_build_stores_sqlite_arm_builds_sqlite_pair(monkeypatch, tmp_path):
    """On BROKER_STORE=sqlite the ceremony pair is sqlite-backed at the
    boot_config-resolved db path — no MCP_REGISTRY_TABLE_NAME involved (the
    table name is a Dynamo concept; the db path replaces it on this arm)."""
    from safe_agents.broker.mcp.sqlite_stores import (
        SqliteAdmissionProposalStore,
        SqliteToolRegistry,
    )

    monkeypatch.setenv("BROKER_STORE", "sqlite")
    monkeypatch.setenv("BROKER_HMAC_KEY", "k")
    monkeypatch.setenv("BROKER_SQLITE_PATH", str(tmp_path / "broker.db"))
    monkeypatch.delenv("MCP_REGISTRY_TABLE_NAME", raising=False)
    registry, proposal_store = commands._build_stores(None)
    assert isinstance(registry, SqliteToolRegistry)
    assert isinstance(proposal_store, SqliteAdmissionProposalStore)
    assert isinstance(commands._build_registry_store(None), SqliteToolRegistry)


def test_build_stores_sqlite_arm_refuses_without_db_path(monkeypatch):
    """The db path is NAMED on the sqlite arm — a defaulted path would open a
    fresh empty database while the operator believed their admitted set was in
    force."""
    monkeypatch.setenv("BROKER_STORE", "sqlite")
    monkeypatch.setenv("BROKER_HMAC_KEY", "k")
    monkeypatch.delenv("BROKER_SQLITE_PATH", raising=False)
    with pytest.raises(BrokerConfigError, match="BROKER_SQLITE_PATH"):
        commands._build_stores(None)


def test_build_stores_sqlite_arm_still_requires_hmac_key(monkeypatch, tmp_path):
    """The HMAC key stays ceremony-named on the sqlite arm too — a durable
    local store's tamper evidence is only as real as its key discipline."""
    monkeypatch.setenv("BROKER_STORE", "sqlite")
    monkeypatch.delenv("BROKER_HMAC_KEY", raising=False)
    monkeypatch.setenv("BROKER_SQLITE_PATH", str(tmp_path / "broker.db"))
    with pytest.raises(BrokerConfigError, match="BROKER_HMAC_KEY"):
        commands._build_stores(None)


def test_main_missing_table_name_exits_2_not_keyerror(monkeypatch, capsys):
    """main() surfaces the missing-table refusal as a clean exit 2 (the #205
    idiom), not an uncaught KeyError traceback (Finding C)."""
    monkeypatch.setenv("BROKER_HMAC_KEY", "k")
    monkeypatch.delenv("MCP_REGISTRY_TABLE_NAME", raising=False)
    rc = commands.main(
        [
            "admit-propose",
            "--server-id", SERVER_ID,
            "--tool-name", TOOL_NAME,
            "--tool-def-json", "/nonexistent.json",
            "--ttl-hours", "1",
        ]
    )
    assert rc == 2
    assert "MCP registry table" in capsys.readouterr().err


# ===========================================================================
# admit-reject (#236) — a bad proposal has an exit other than expiry
#
# Before this, `consume_proposal` accepted a "rejected" status but no CLI wired
# it, so a maker's mistake could only be left to time out. "It expired" and "a
# checker looked at it and said no" are different facts and only one of them is
# evidence.
# ===========================================================================


class TestAdmitReject:
    def _reject_args(self, proposal_id: str):
        return _parse_args(
            [
                "admit-reject",
                "--server-id", SERVER_ID,
                "--tool-name", TOOL_NAME,
                "--proposal-id", proposal_id,
            ]
        )

    def test_reject_burns_the_proposal_and_it_can_never_be_ratified(
        self, proposal_store, monkeypatch, tmp_path, signer_and_resolver, capsys
    ):
        signer, _ = signer_and_resolver
        path = write_tool_def(tmp_path, "d.json", make_tool_def())
        proposal_id = run_propose(proposal_store, monkeypatch, path, caller=MAKER_ARN)

        set_caller(monkeypatch, CHECKER_ARN)
        assert commands.admit_reject_command(
            self._reject_args(proposal_id), proposal_store=proposal_store
        ) == 0
        out = capsys.readouterr().out
        assert "REJECTED" in out and CHECKER_ARN in out

        # The burn is real: ratify now refuses, and NOTHING was admitted.
        registry = MemoryToolRegistry()
        rc = admit_ratify_command(
            ratify_args(proposal_id),
            store=registry,
            proposal_store=proposal_store,
            signer=signer,
            now=NOW,
        )
        assert rc == 1
        assert "not pending" in capsys.readouterr().out
        assert registry.get_tool(SERVER_ID, TOOL_NAME).tool is None

    def test_the_maker_may_withdraw_its_own_proposal(
        self, proposal_store, monkeypatch, tmp_path, capsys
    ):
        """Deliberately NOT maker != checker gated: rejection only destroys a
        path to admission, so gating it would leave a maker who spotted their
        own mistake with expiry as the only exit."""
        path = write_tool_def(tmp_path, "d.json", make_tool_def())
        proposal_id = run_propose(proposal_store, monkeypatch, path, caller=MAKER_ARN)
        set_caller(monkeypatch, MAKER_ARN)
        assert commands.admit_reject_command(
            self._reject_args(proposal_id), proposal_store=proposal_store
        ) == 0
        assert "REJECTED" in capsys.readouterr().out

    def test_double_reject_and_unknown_proposal_refuse(
        self, proposal_store, monkeypatch, tmp_path, capsys
    ):
        path = write_tool_def(tmp_path, "d.json", make_tool_def())
        proposal_id = run_propose(proposal_store, monkeypatch, path, caller=MAKER_ARN)
        set_caller(monkeypatch, CHECKER_ARN)
        assert commands.admit_reject_command(
            self._reject_args(proposal_id), proposal_store=proposal_store
        ) == 0
        capsys.readouterr()
        # Single-shot: the second rejection is refused, not idempotently green.
        assert commands.admit_reject_command(
            self._reject_args(proposal_id), proposal_store=proposal_store
        ) == 1
        assert "not pending" in capsys.readouterr().out

        assert commands.admit_reject_command(
            self._reject_args("no-such-proposal"), proposal_store=proposal_store
        ) == 1
        assert "no admission proposal" in capsys.readouterr().out

    def test_a_tampered_proposal_refuses_rejection_too(
        self, proposal_store, monkeypatch, tmp_path, capsys
    ):
        """The proposal HMAC gates this read exactly as it gates ratify: a
        store-tampered proposal is an incident, not something to quietly burn."""
        path = write_tool_def(tmp_path, "d.json", make_tool_def())
        proposal_id = run_propose(proposal_store, monkeypatch, path, caller=MAKER_ARN)
        item = proposal_store._items[(SERVER_ID, TOOL_NAME, proposal_id)]
        item["data"] = item["data"].replace("quote", "quote ")
        set_caller(monkeypatch, CHECKER_ARN)
        assert commands.admit_reject_command(
            self._reject_args(proposal_id), proposal_store=proposal_store
        ) == 1
        assert "REFUSED" in capsys.readouterr().out
        # Still pending — a refusal wrote nothing.
        assert proposal_store._items[(SERVER_ID, TOOL_NAME, proposal_id)]["status"] == "pending"
