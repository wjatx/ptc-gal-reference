"""Auditor-specific unit tests for grants.audit (#62).

The six auditor invariants live as rows in test_grants_integrity.py's TABLE;
this file covers what isn't a table row: the paginated Scan loader (stub pages
for the ExclusiveStartKey loop, moto for real item shapes end-to-end), parse
failures becoming findings instead of crashes, keyed/keyless mode handling
(skipped rules surface LOUDLY), and the read-only source guard.
"""

from __future__ import annotations

import inspect
import os

import pytest

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import json

from safe_agents.broker.grants import audit as audit_module
from safe_agents.broker.grants.acknowledgments import (
    canonical_ack_payload,
    AcknowledgmentRecord,
    sign_acknowledgment,
    violation_detail_digest,
)
from safe_agents.broker.grants.audit import (
    ACKNOWLEDGMENT_NOT_WAIVABLE,
    ACKNOWLEDGMENT_SIGNATURE_VERIFIES,
    GRANT_ENVELOPE_IN_FORCE,
    GRANT_TAMPER,
    HMAC_RULES,
    PROPOSAL_LIFECYCLE,
    RECORD_SIGNATURE_VERIFIES,
    UNPARSEABLE_ITEM,
    dataset_from_items,
    load_dataset,
    run_audit,
)
from safe_agents.broker.grants.proposals import compute_proposal_hash
from safe_agents.broker.grants.record_signing import canonical_record_payload, signer_from_pem
from safe_agents.broker.grants.store import _hmac_payload, canonical_grant_payload
from safe_agents.broker.schemas import Envelope, Grant, PromotionRecord
from safe_agents.broker.schemas.envelope import compute_envelope_hash
from safe_agents.broker.schemas.common import Principal
from safe_agents.channels.keys import key_resolver_from_map

PRINCIPAL = Principal(agentId="agent-audit", skill="email", user="alice", tier="B")
ACTION_CLASS = "email.send"
HMAC_KEY = b"test-hmac-key-audit"

_GRANT_PK = "GRANT#agent-audit#email#alice#B"
_RECORD_PK = "RECORD#agent-audit#email#alice#B#email.send"
_PROPOSAL_PK = "PROPOSAL#agent-audit#email#alice#B#email.send"


def _make_grant(**overrides) -> Grant:
    defaults = dict(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level="in-loop",
        envelopeHash="sha256:env-001",
        promotedBy="alice",
        evidence="evidence-ref-001",
        ts="2026-06-28T00:00:00Z",
        lastSafeLevel="in-loop",
        demotionTriggers=["budget_breach"],
        demotionReason=None,
        labelLatency="P1D",
        ownerId="alice",
    )
    defaults.update(overrides)
    return Grant(**defaults)


def _make_record(
    record_type: str = "bootstrap",
    *,
    ts: str = "2026-07-01T00:00:00+00:00",
    **overrides,
) -> PromotionRecord:
    is_promotion = record_type == "promotion"
    defaults = dict(
        recordType=record_type,
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        fromLevel="in-loop" if is_promotion else None,
        toLevel="on-loop" if is_promotion else "in-loop",
        evidence="evidence-ref-001",
        predicate="predicate passed" if is_promotion else None,
        proposedBy="human-proposer",
        ratifiedBy="checker-distinct" if is_promotion else "human-proposer",
        envelopeHash="sha256:env-001",
        ts=ts,
    )
    defaults.update(overrides)
    return PromotionRecord(**defaults)


def _grant_item(
    grant: Grant | None = None, *, data: str | None = None, grant_hash: str | None = None
) -> dict:
    """A GRANT# item in the stored-bytes shape (#246): data is the canonical
    payload and grantHash the HMAC over exactly those bytes — pass grant_hash
    to plant a tampered item."""
    grant = grant or _make_grant()
    payload = data if data is not None else canonical_grant_payload(grant)
    return {
        "pk": _GRANT_PK,
        "sk": f"CLASS#{ACTION_CLASS}",
        "data": payload,
        "grantHash": grant_hash if grant_hash is not None else _hmac_payload(payload, HMAC_KEY),
    }


def _proposal_item(data: str = '{"proposal_id": "prop-1"}', status: str = "pending") -> dict:
    return {
        "pk": _PROPOSAL_PK,
        "sk": "prop-1",
        "data": data,
        "proposalHash": compute_proposal_hash(data, HMAC_KEY),
        "status": status,
    }


def _issuer_signer_and_resolver():
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    signer = signer_from_pem("issuer:audit-test", "zone-test", private_pem)
    return signer, key_resolver_from_map({"issuer:audit-test": public_pem})


# ---------------------------------------------------------------------------
# Loader — the ExclusiveStartKey pagination loop (deterministic stub pages)
# ---------------------------------------------------------------------------


class _PagedTable:
    """Table stub whose scan returns fixed pages; records the kwargs seen."""

    def __init__(self, pages: list[dict]) -> None:
        self._pages = list(pages)
        self.scan_calls: list[dict] = []

    def scan(self, **kwargs):
        self.scan_calls.append(kwargs)
        return self._pages.pop(0)


def test_load_dataset_follows_last_evaluated_key():
    table = _PagedTable(
        [
            {
                "Items": [_grant_item()],
                "LastEvaluatedKey": {"pk": _GRANT_PK, "sk": "CLASS#email.send"},
            },
            {"Items": [_proposal_item()]},
        ]
    )

    dataset = load_dataset(table)

    assert len(dataset.grants) == 1
    assert len(dataset.proposals) == 1
    assert len(table.scan_calls) == 2
    assert "ExclusiveStartKey" not in table.scan_calls[0]
    assert table.scan_calls[1]["ExclusiveStartKey"] == {
        "pk": _GRANT_PK,
        "sk": "CLASS#email.send",
    }


# ---------------------------------------------------------------------------
# Parsing — failures are findings, never crashes; foreign item kinds ignored
# ---------------------------------------------------------------------------


def test_unparseable_lifecycle_items_become_findings():
    dataset = dataset_from_items(
        [
            {"pk": _GRANT_PK, "sk": "CLASS#email.send", "data": "not-json"},
            {"pk": _RECORD_PK, "sk": "sk-1"},  # no data attribute at all
            {"pk": _PROPOSAL_PK, "sk": "prop-1", "status": "pending"},  # no data
            {"sk": "orphan-without-pk"},
        ]
    )

    assert dataset.grants == ()
    assert dataset.records == ()
    assert dataset.proposals == ()
    assert len(dataset.parse_violations) == 4
    assert all(v.rule == UNPARSEABLE_ITEM for v in dataset.parse_violations)

    # The findings ride into the report — an unreadable item is never dropped
    report = run_audit(dataset, hmac_key=HMAC_KEY)
    assert {v.rule for v in report.violations} == {UNPARSEABLE_ITEM}


def test_non_lifecycle_item_kinds_are_ignored():
    dataset = dataset_from_items(
        [
            {"pk": "COUNTER#agent-audit#email.send#2026-07-14", "sk": "V0", "n": 3},
            _grant_item(),
        ]
    )
    assert len(dataset.grants) == 1
    assert dataset.parse_violations == ()


# ---------------------------------------------------------------------------
# GRANT_ENVELOPE_IN_FORCE (#201) — a grant stamped under a stale/wrong envelope
# is broker-quarantined on every call; the audit must say so
# ---------------------------------------------------------------------------


def _envelope_item(envelope: Envelope | None = None, *, data: str | None = None) -> dict:
    envelope = envelope or Envelope(polarity="abstain")
    return {
        "pk": f"ENVELOPE#{_GRANT_PK.removeprefix('GRANT#')}",
        "sk": "V0",
        "data": data if data is not None else envelope.model_dump_json(),
    }


def test_grant_matching_in_force_envelope_passes():
    envelope = Envelope(polarity="abstain")
    grant = _make_grant(envelopeHash=compute_envelope_hash(envelope))
    report = run_audit(dataset_from_items([_grant_item(grant), _envelope_item(envelope)]))
    assert GRANT_ENVELOPE_IN_FORCE not in {v.rule for v in report.violations}
    assert report.envelopes_examined == 1


def test_grant_stamped_under_stale_envelope_is_a_violation():
    # The #199 shape: HMAC-clean grant honestly recording a hash that is NOT
    # the in-force envelope's — dead at the broker, previously green here.
    report = run_audit(
        dataset_from_items([_grant_item(), _envelope_item()])  # grant says env-001
    )
    fired = [v for v in report.violations if v.rule == GRANT_ENVELOPE_IN_FORCE]
    assert len(fired) == 1
    assert "re-seed" in fired[0].detail


def test_grant_without_envelope_row_is_not_judged():
    # Manifest-mode floors store no ENVELOPE# rows — the rule only judges
    # where an in-force row exists (read-side limit, documented at the rule).
    report = run_audit(dataset_from_items([_grant_item()]))
    assert GRANT_ENVELOPE_IN_FORCE not in {v.rule for v in report.violations}


def test_unparseable_envelope_row_is_a_finding():
    report = run_audit(dataset_from_items([_envelope_item(data="not-json")]))
    assert {v.rule for v in report.violations} == {UNPARSEABLE_ITEM}


# ---------------------------------------------------------------------------
# Acknowledgments (#196) — signed waivers disposition TRUE findings;
# green-with-annotations, never silently green, never a laundering seam
# ---------------------------------------------------------------------------


def _ack_item(ack: AcknowledgmentRecord, envelope: dict | str) -> dict:
    return {
        "pk": f"ACK#{ack.coordinate}",
        "sk": f"{ack.ts}#{ack.rule}",
        "data": canonical_ack_payload(ack),
        "signature": json.dumps(envelope, sort_keys=True)
        if isinstance(envelope, dict)
        else envelope,
    }


def _stale_envelope_items() -> list[dict]:
    """A grant honestly recording env-001 (with its bootstrap ledger record)
    beside an in-force envelope that hashes differently — the #199 shape:
    exactly one finding, GRANT_ENVELOPE_IN_FORCE."""
    record = _make_record()
    return [
        _grant_item(),
        _envelope_item(),
        {"pk": _RECORD_PK, "sk": f"{record.ts}#bootstrap", "data": record.model_dump_json()},
    ]


def _ack_for(violation, signer, **overrides) -> AcknowledgmentRecord:
    defaults = dict(
        rule=violation.rule,
        coordinate=violation.coordinate,
        detailDigest=violation_detail_digest(violation.detail),
        rationale="expected stale window pending re-seed",
        acknowledgedBy="arn:aws:sts::123:assumed-role/PromotionRole/maintainer",
        ts="2026-07-14T15:00:00+00:00",
    )
    defaults.update(overrides)
    return AcknowledgmentRecord(**defaults)


def test_verified_acknowledgment_moves_finding_to_acknowledged():

    signer, resolver = _issuer_signer_and_resolver()
    first = run_audit(dataset_from_items(_stale_envelope_items()), record_key_resolver=resolver)
    violation = next(v for v in first.violations if v.rule == GRANT_ENVELOPE_IN_FORCE)

    ack = _ack_for(violation, signer)
    envelope = sign_acknowledgment(ack, signer)
    report = run_audit(
        dataset_from_items(_stale_envelope_items() + [_ack_item(ack, envelope)]),
        record_key_resolver=resolver,
    )
    assert report.violations == ()  # green...
    assert len(report.acknowledged) == 1  # ...with annotations, never silently
    entry = report.acknowledged[0]
    assert entry.violation == violation
    assert "maintainer" in entry.waiver_ref and "re-seed" in entry.waiver_ref


def test_acknowledgment_with_stale_fingerprint_waives_nothing():
    signer, resolver = _issuer_signer_and_resolver()
    first = run_audit(dataset_from_items(_stale_envelope_items()), record_key_resolver=resolver)
    violation = next(v for v in first.violations if v.rule == GRANT_ENVELOPE_IN_FORCE)

    # Same rule + coordinate, but the digest binds a DIFFERENT finding — a new
    # violation at the same coordinate must never be auto-waived.
    ack = _ack_for(violation, signer, detailDigest=violation_detail_digest("old finding"))
    report = run_audit(
        dataset_from_items(_stale_envelope_items() + [_ack_item(ack, sign_acknowledgment(ack, signer))]),
        record_key_resolver=resolver,
    )
    assert GRANT_ENVELOPE_IN_FORCE in {v.rule for v in report.violations}
    assert report.acknowledged == ()


def test_acknowledgment_for_unwaivable_rule_is_itself_a_finding():
    signer, resolver = _issuer_signer_and_resolver()
    ack = AcknowledgmentRecord(
        rule=GRANT_TAMPER,  # HMAC tamper is never waivable
        coordinate="agent-audit#email#alice#B#email.send",
        detailDigest=violation_detail_digest("whatever"),
        rationale="trying to launder a tamper",
        acknowledgedBy="arn:aws:sts::123:assumed-role/PromotionRole/mallory",
        ts="2026-07-14T15:00:00+00:00",
    )
    report = run_audit(
        dataset_from_items([_ack_item(ack, sign_acknowledgment(ack, signer))]),
        record_key_resolver=resolver,
    )
    assert {v.rule for v in report.violations} == {ACKNOWLEDGMENT_NOT_WAIVABLE}


def test_forged_acknowledgment_is_a_finding_and_waives_nothing():
    signer, resolver = _issuer_signer_and_resolver()
    stranger_signer, _ = _issuer_signer_and_resolver()  # key the resolver doesn't know
    first = run_audit(dataset_from_items(_stale_envelope_items()), record_key_resolver=resolver)
    violation = next(v for v in first.violations if v.rule == GRANT_ENVELOPE_IN_FORCE)

    ack = _ack_for(violation, signer)
    report = run_audit(
        dataset_from_items(
            _stale_envelope_items() + [_ack_item(ack, sign_acknowledgment(ack, stranger_signer))]
        ),
        record_key_resolver=resolver,
    )
    fired = {v.rule for v in report.violations}
    assert ACKNOWLEDGMENT_SIGNATURE_VERIFIES in fired
    assert GRANT_ENVELOPE_IN_FORCE in fired  # the waiver did NOT apply
    assert report.acknowledged == ()


def test_keyless_run_applies_no_waivers_and_skips_loudly():
    signer, resolver = _issuer_signer_and_resolver()
    first = run_audit(dataset_from_items(_stale_envelope_items()), record_key_resolver=resolver)
    violation = next(v for v in first.violations if v.rule == GRANT_ENVELOPE_IN_FORCE)
    ack = _ack_for(violation, signer)

    report = run_audit(
        dataset_from_items(_stale_envelope_items() + [_ack_item(ack, sign_acknowledgment(ack, signer))])
    )  # no resolver: the CI keyless mode
    assert GRANT_ENVELOPE_IN_FORCE in {v.rule for v in report.violations}
    assert report.acknowledged == ()
    assert ACKNOWLEDGMENT_SIGNATURE_VERIFIES in report.skipped_rules


def test_record_signature_string_attribute_is_decoded():
    signer, resolver = _issuer_signer_and_resolver()
    record = _make_record("promotion", ts="2026-07-02T00:00:00+00:00")
    envelope = signer.sign_record(record)
    import json

    dataset = dataset_from_items(
        [
            {
                "pk": _RECORD_PK,
                "sk": f"{record.ts}#promotion",
                # the store writes the canonical payload — the exact bytes the
                # signature binds (#246 re-shape C)
                "data": canonical_record_payload(record),
                # stored as a JSON string on the item, like the DynamoDB store
                "signature": json.dumps(envelope, sort_keys=True),
            }
        ]
    )
    report = run_audit(dataset, record_key_resolver=resolver)
    assert RECORD_SIGNATURE_VERIFIES not in {v.rule for v in report.violations}


def test_mangled_signature_attribute_fails_closed():
    resolver = _issuer_signer_and_resolver()[1]
    record = _make_record("promotion", ts="2026-07-02T00:00:00+00:00")
    dataset = dataset_from_items(
        [
            {
                "pk": _RECORD_PK,
                "sk": f"{record.ts}#promotion",
                "data": record.model_dump_json(),
                "signature": "{not-decodable-json",
            }
        ]
    )
    report = run_audit(dataset, record_key_resolver=resolver)
    assert RECORD_SIGNATURE_VERIFIES in {v.rule for v in report.violations}


# ---------------------------------------------------------------------------
# Mode handling — skipped rules are LOUD, never silently green
# ---------------------------------------------------------------------------


def test_keyless_mode_skips_hmac_rules_loudly():
    dataset = dataset_from_items(
        [
            _grant_item(grant_hash="deliberately-tampered"),
            _proposal_item(status="pending"),
        ]
    )

    keyless = run_audit(dataset)
    fired = {v.rule for v in keyless.violations}
    # The tamper is invisible without the key — but the rules are named as
    # skipped, so a keyless pass can never masquerade as a keyed one.
    assert GRANT_TAMPER not in fired
    assert set(HMAC_RULES) <= set(keyless.skipped_rules)
    assert RECORD_SIGNATURE_VERIFIES in keyless.skipped_rules

    keyed = run_audit(dataset, hmac_key=HMAC_KEY)
    assert GRANT_TAMPER in {v.rule for v in keyed.violations}
    assert set(HMAC_RULES).isdisjoint(keyed.skipped_rules)


def test_status_vocabulary_half_runs_keyless():
    dataset = dataset_from_items([_proposal_item(status="resurrected")])
    report = run_audit(dataset)
    assert PROPOSAL_LIFECYCLE in {v.rule for v in report.violations}


def test_report_counts_examined_items():
    dataset = dataset_from_items(
        [_grant_item(), _proposal_item()]
        + [
            {
                "pk": _RECORD_PK,
                "sk": "2026-07-01T00:00:00+00:00#bootstrap",
                "data": _make_record().model_dump_json(),
            }
        ]
    )
    report = run_audit(dataset, hmac_key=HMAC_KEY)
    assert report.grants_examined == 1
    assert report.records_examined == 1
    assert report.proposals_examined == 1


# ---------------------------------------------------------------------------
# Read-only guard — the auditor's source names no write API
# ---------------------------------------------------------------------------


def test_audit_module_source_names_no_write_api():
    source = inspect.getsource(audit_module)
    for forbidden in ("put_item", "update_item", "delete_item", "batch_writer"):
        assert forbidden not in source, (
            f"audit.py must never write: found {forbidden!r} in the source"
        )


# ---------------------------------------------------------------------------
# End-to-end against moto — real store item shapes through the real Scan
# ---------------------------------------------------------------------------

moto = pytest.importorskip("moto", reason="moto is required for the loader e2e tests")
boto3 = pytest.importorskip("boto3", reason="boto3 is required for the loader e2e tests")

from moto import mock_aws  # noqa: E402

from safe_agents.broker.grants.store import (  # noqa: E402
    DynamoDBGrantStore,
    DynamoDBPromotionRecordStore,
)

REGION = "us-east-1"
TABLE = "safe-agents-audit-test"


@pytest.fixture
def table_name():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName=TABLE,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.Table(TABLE).wait_until_exists()
        yield TABLE


def _table(table_name):
    return boto3.resource("dynamodb", region_name=REGION).Table(table_name)


def _seed_clean_state(table_name, signer) -> None:
    """One grant + its earning ledger + a valid pending proposal, via the REAL
    store write paths, so load_dataset parses production item shapes."""
    grant_store = DynamoDBGrantStore(hmac_key=HMAC_KEY, table_name=table_name)
    grant_store.put_grant(_make_grant(), session=boto3.Session())

    record_store = DynamoDBPromotionRecordStore(table_name=table_name)
    record_store.put_record(_make_record(), session=boto3.Session())
    promotion = _make_record("promotion", ts="2026-07-02T00:00:00+00:00")
    record_store.put_record(
        promotion, session=boto3.Session(), signature=signer.sign_record(promotion)
    )

    # Raw proposal item in the store's exact shape (the auditor never parses
    # the proposal payload, so an opaque data string is a faithful fixture)
    _table(table_name).put_item(Item=_proposal_item())


def test_full_keyed_audit_of_real_items_is_green(table_name):
    signer, resolver = _issuer_signer_and_resolver()
    _seed_clean_state(table_name, signer)

    report = run_audit(
        load_dataset(_table(table_name)),
        hmac_key=HMAC_KEY,
        record_key_resolver=resolver,
    )

    assert report.violations == ()
    assert report.skipped_rules == ()
    assert (report.grants_examined, report.records_examined, report.proposals_examined) == (
        1, 2, 1,
    )


def test_keyed_audit_flags_table_tamper(table_name):
    signer, resolver = _issuer_signer_and_resolver()
    _seed_clean_state(table_name, signer)

    # Tamper the grant's data payload in place (its hash fields untouched)
    table = _table(table_name)
    item = table.get_item(Key={"pk": _GRANT_PK, "sk": f"CLASS#{ACTION_CLASS}"})["Item"]
    table.update_item(
        Key={"pk": _GRANT_PK, "sk": f"CLASS#{ACTION_CLASS}"},
        UpdateExpression="SET #data = :tampered",
        ExpressionAttributeNames={"#data": "data"},
        ExpressionAttributeValues={":tampered": item["data"].replace('"alice"', '"mallory"')},
    )

    report = run_audit(
        load_dataset(table), hmac_key=HMAC_KEY, record_key_resolver=resolver
    )
    assert GRANT_TAMPER in {v.rule for v in report.violations}
