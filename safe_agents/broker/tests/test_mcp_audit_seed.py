"""MCP registry integrity audit — seed rules (#235).

Every rule is exercised in BOTH directions: a clean dataset passes, and a
deliberately damaged one flips it RED. That is the #201 discipline — a rule that
has never fired is not a proven rule, and the seed's whole value is that its
checks are known to detect something.

The sharp test here is `test_valid_signature_over_different_bytes_is_caught`:
a forged record can carry a signature that verifies perfectly and still not be
the record that is stored. "Is it signed?" does not catch that; comparing the
signed statement to the stored bytes does.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safe_agents.broker.mcp.audit import (
    ORPHAN_RECORD,
    ORPHAN_ROW,
    RECORD_PAYLOAD_MATCHES_STORED,
    RECORD_SIGNATURE_VERIFIES,
    ROW_HMAC_INTACT,
    ROW_MATCHES_LAST_RECORD,
    _dsse_pae,
    dataset_from_items,
    run_audit,
)
from safe_agents.broker.mcp.registry import canonical_row_payload, compute_row_hmac
from safe_agents.broker.schemas.mcp_registry import (
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
)

HMAC_KEY = b"test-hmac-key"
KEY_ID = "test-issuer-1"
SERVER, TOOL = "ledger", "get_entry"
DEF_HASH = "a" * 64
TS = "2026-07-20T12:00:00+00:00"


@pytest.fixture
def keypair():
    sk = Ed25519PrivateKey.generate()
    pem = (
        sk.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return sk, {KEY_ID: pem}


def _row_item(def_hash: str = DEF_HASH, *, tamper: bool = False) -> dict:
    # #246: nested row, canonical stored bytes, item-level rowHash over those
    # exact bytes; a tamper mutates the stored data STRING out-of-band.
    row = RegisteredTool(
        tool_def=McpToolDef(
            server_id=SERVER,
            tool_name=TOOL,
            input_schema={"type": "object"},
            description="Return one ledger entry.",
        ),
        def_hash=def_hash,
        status=RegistryStatus.ACTIVE,
        admitted_by="arn:aws:sts::111111111111:assumed-role/CheckerRole/checker",
        admitted_at=TS,
    )
    data = canonical_row_payload(row)
    stored_hash = compute_row_hmac(row, HMAC_KEY)
    if tamper:
        data = data.replace("Return one ledger entry.", "tampered underneath")
    return {
        "pk": f"TOOLDEF#{SERVER}#{TOOL}",
        "sk": "ROW",
        "data": data,
        "rowHash": stored_hash,
    }


def _record_dict(def_hash: str = DEF_HASH) -> dict:
    return {
        "recordType": "admission",
        "serverId": SERVER,
        "toolName": TOOL,
        "defHash": def_hash,
        "proposedBy": "arn:aws:sts::111111111111:assumed-role/MakerRole/maker",
        "ratifiedBy": "arn:aws:sts::111111111111:assumed-role/CheckerRole/checker",
        "ts": TS,
    }


class TestCleanDatasetPasses:
    def test_a_healthy_coordinate_reports_no_violations(self, keypair) -> None:
        sk, keys = keypair
        rec = _record_dict()
        items = [_row_item(), _make_record(sk, TS, rec)]
        report = run_audit(dataset_from_items(items), hmac_key=HMAC_KEY, verify_keys=keys)
        assert report.violations == ()
        assert report.skipped_rules == ()
        assert (report.rows_examined, report.records_examined) == (1, 1)


class TestSignatureRules:
    def test_valid_signature_over_different_bytes_is_caught(self, keypair) -> None:
        """THE sharp one. The signature verifies — over a record that is not the
        one stored. A naive 'is it signed?' check passes this forgery."""
        sk, keys = keypair
        stored = _record_dict()
        forged = _record_dict() | {"ratifiedBy": "arn:aws:sts::999:assumed-role/Evil/e"}
        items = [_row_item(), _make_record(sk, TS, stored, signed_record=forged)]
        report = run_audit(dataset_from_items(items), hmac_key=HMAC_KEY, verify_keys=keys)
        assert [v.rule for v in report.violations] == [RECORD_PAYLOAD_MATCHES_STORED]

    def test_signature_from_the_wrong_key_is_caught(self, keypair) -> None:
        _, keys = keypair
        other = Ed25519PrivateKey.generate()
        items = [_row_item(), _make_record(other, TS, _record_dict())]
        report = run_audit(dataset_from_items(items), hmac_key=HMAC_KEY, verify_keys=keys)
        assert [v.rule for v in report.violations] == [RECORD_SIGNATURE_VERIFIES]

    def test_an_unsigned_record_is_caught(self, keypair) -> None:
        _, keys = keypair
        item = _make_record(Ed25519PrivateKey.generate(), TS, _record_dict())
        del item["signature"]
        report = run_audit(dataset_from_items([_row_item(), item]), hmac_key=HMAC_KEY, verify_keys=keys)
        assert [v.rule for v in report.violations] == [RECORD_SIGNATURE_VERIFIES]

    def test_keyless_posture_SKIPS_loudly_rather_than_passing(self, keypair) -> None:
        """An empty violations tuple must not read as green when the rule could
        not run — the grants auditor's discipline, mirrored."""
        sk, _ = keypair
        items = [_row_item(), _make_record(sk, TS, _record_dict())]
        report = run_audit(dataset_from_items(items), hmac_key=HMAC_KEY, verify_keys=None)
        assert set(report.skipped_rules) == {RECORD_SIGNATURE_VERIFIES, RECORD_PAYLOAD_MATCHES_STORED}
        assert report.violations == ()


class TestRowRules:
    def test_a_row_edited_out_of_band_is_quarantined(self, keypair) -> None:
        sk, keys = keypair
        items = [_row_item(tamper=True), _make_record(sk, TS, _record_dict())]
        report = run_audit(dataset_from_items(items), hmac_key=HMAC_KEY, verify_keys=keys)
        assert ROW_HMAC_INTACT in [v.rule for v in report.violations]

    def test_keyless_row_check_SKIPS(self, keypair) -> None:
        sk, keys = keypair
        items = [_row_item(tamper=True), _make_record(sk, TS, _record_dict())]
        report = run_audit(dataset_from_items(items), hmac_key=None, verify_keys=keys)
        assert ROW_HMAC_INTACT in report.skipped_rules
        assert ROW_HMAC_INTACT not in [v.rule for v in report.violations]

    def test_a_row_the_ledger_does_not_explain_is_caught(self, keypair) -> None:
        """Callability granted by something other than the ceremony: the row sits
        at a hash no record ever ratified."""
        sk, keys = keypair
        items = [_row_item(def_hash="b" * 64), _make_record(sk, TS, _record_dict("a" * 64))]
        report = run_audit(dataset_from_items(items), hmac_key=HMAC_KEY, verify_keys=keys)
        assert ROW_MATCHES_LAST_RECORD in [v.rule for v in report.violations]

    def test_the_NEWEST_record_is_the_one_that_must_match(self, keypair) -> None:
        """A re-vet history is legal: older records name superseded hashes. Only
        the newest has to explain the row."""
        sk, keys = keypair
        items = [
            _row_item(def_hash="b" * 64),
            _make_record(sk, "2026-07-19T00:00:00+00:00", _record_dict("a" * 64)),
            _make_record(sk, "2026-07-20T00:00:00+00:00", _record_dict("b" * 64)),
        ]
        report = run_audit(dataset_from_items(items), hmac_key=HMAC_KEY, verify_keys=keys)
        assert report.violations == ()


class TestOrphanRules:
    def test_a_row_with_no_record_is_caught(self) -> None:
        report = run_audit(dataset_from_items([_row_item()]), hmac_key=HMAC_KEY)
        assert ORPHAN_ROW in [v.rule for v in report.violations]

    def test_a_record_with_no_row_is_caught(self, keypair) -> None:
        """#235 blind spot 2 — the ceremony leaves this on a conditional-write
        conflict. NOTE: adopting per-coordinate atomicity makes this
        unreachable, at which point the rule should be deleted, not kept green."""
        sk, keys = keypair
        report = run_audit(
            dataset_from_items([_make_record(sk, TS, _record_dict())]),
            hmac_key=HMAC_KEY,
            verify_keys=keys,
        )
        assert ORPHAN_RECORD in [v.rule for v in report.violations]


def _make_record(sk, ts, record, *, signed_record=None):
    """Module-level builder (the fixture-scoped one would shadow `sk`)."""
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://safe-agents.dev/mcp-admission/v1",
        "predicate": {"record": signed_record if signed_record is not None else record},
    }
    payload = json.dumps(statement, sort_keys=True, ensure_ascii=True).encode()
    payload_type = "application/vnd.in-toto+json"
    sig = sk.sign(_dsse_pae(payload_type, payload))
    return {
        "pk": f"TOOLREC#{SERVER}#{TOOL}",
        "sk": ts,
        "data": json.dumps(record, sort_keys=True, ensure_ascii=True),
        "signature": json.dumps(
            {
                "payload": base64.b64encode(payload).decode(),
                "payloadType": payload_type,
                "signatures": [{"keyid": KEY_ID, "sig": base64.b64encode(sig).decode()}],
            }
        ),
    }
