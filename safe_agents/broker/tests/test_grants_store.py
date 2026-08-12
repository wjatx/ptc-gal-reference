"""Tests for the grant store client (sa#55).

Coverage:
- Round-trip read/write preserves all fields (InMemoryGrantStore).
- STORED-BYTES basis (#246): the stored data string IS the HMAC basis;
  verification never re-serializes, so a byte-divergent-but-intact item still
  reads clean and a tampered item quarantines with grant=None.
- Schema validation rejects a Grant missing ownerId.
- The DynamoDBGrantStore propagates AccessDenied without swallowing it
  (mock boto3 session; no live AWS required).
- compute_grant_hash is deterministic and sensitive to field changes.
- update_grant: conditional UpdateItem semantics — success, conflict on a stale
  expected hash, conflict on a missing item (never creates), prev_raw_data
  REQUIRED (the legacy fallback is retired).
- DynamoDBPromotionRecordStore: RECORD# item layout, append-only condition,
  RecordAlreadyExistsError on a key collision.
- Record ts canonical validation (#191): both put_record implementations
  reject a 'Z'-suffixed, naive, non-UTC-offset, or unparseable ts with
  RecordTimestampFormatError before any write; list_records' ts_prefix
  narrows to sk values beginning with the prefix (the runner's same-day read).

Real-DynamoDB (moto) coverage for both stores lives in test_dynamo_stores.py.
"""

import pytest
from pydantic import ValidationError
from unittest.mock import MagicMock, patch

from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.grants.store import (
    InMemoryGrantStore,
    DynamoDBGrantStore,
    DynamoDBPromotionRecordStore,
    GrantUpdateConflictError,
    RecordAlreadyExistsError,
    RecordTimestampFormatError,
    _hmac_payload,
    canonical_grant_payload,
    compute_grant_hash,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-1", skill="email", user="alice", tier="B")

GRANT_BASE = dict(
    principal=PRINCIPAL,
    actionClass="email.send",
    level="in-loop",
    envelopeHash="sha256:abc",
    promotedBy="alice",
    evidence="evidence-ref-001",
    ts="2026-06-28T00:00:00Z",
    lastSafeLevel="in-loop",
    demotionTriggers=["stale_confidence"],
    demotionReason=None,
    labelLatency="P1D",
    ownerId="alice",
)

TEST_KEY = b"test-hmac-key-for-tests"


def make_grant(**overrides) -> Grant:
    """Build a valid Grant (integrity lives at the store's item level, #246)."""
    return Grant(**{**GRANT_BASE, **overrides})


# ---------------------------------------------------------------------------
# compute_grant_hash
# ---------------------------------------------------------------------------


def test_hash_is_deterministic():
    g = make_grant()
    key = b"k"
    assert compute_grant_hash(g, key) == compute_grant_hash(g, key)


def test_hash_changes_on_field_change():
    g1 = make_grant(ownerId="alice")
    g2 = make_grant(ownerId="bob")
    assert compute_grant_hash(g1, b"k") != compute_grant_hash(g2, b"k")


def test_hash_is_hmac_of_canonical_payload():
    """compute_grant_hash is exactly the HMAC of the canonical payload — the
    same bytes put_grant stores (storage and basis are ONE serialization)."""
    g = make_grant()
    assert compute_grant_hash(g, b"k") == _hmac_payload(canonical_grant_payload(g), b"k")


def test_verification_uses_stored_bytes_not_reserialization():
    """An item whose data bytes differ from today's canonical re-serialization
    (here: non-sorted key order) but whose grantHash matches THOSE bytes reads
    back clean — verification HMACs the stored bytes verbatim and never
    re-serializes (#246: schema evolution can never false-tamper old items)."""
    import json as _json

    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    # Reverse-key-order serialization of a valid grant: parseable, semantically
    # identical, byte-different from canonical_grant_payload.
    payload_dict = make_grant().model_dump(mode="json")
    divergent = _json.dumps(dict(reversed(list(payload_dict.items()))))
    assert divergent != canonical_grant_payload(make_grant())
    key = ("agent-1#email#alice#B", "email.send")
    store._store[key] = {"data": divergent, "grantHash": _hmac_payload(divergent, TEST_KEY)}

    result = store.get_grant(PRINCIPAL, "email.send")
    assert result.quarantined is False
    assert result.grant == make_grant()
    assert result.raw_data == divergent


def test_hash_sensitive_to_key():
    g = make_grant()
    assert compute_grant_hash(g, b"key-a") != compute_grant_hash(g, b"key-b")


# ---------------------------------------------------------------------------
# InMemoryGrantStore — happy path
# ---------------------------------------------------------------------------


def test_round_trip_preserves_all_fields():
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    original = make_grant()
    store.put_grant(original, session=None)

    result = store.get_grant(PRINCIPAL, "email.send")

    assert result.grant is not None
    assert not result.quarantined
    # Check every field except hash (which put_grant recomputes)
    g = result.grant
    assert g.principal == PRINCIPAL
    assert g.actionClass == "email.send"
    assert g.level == AutonomyLevel.in_loop
    assert g.envelopeHash == "sha256:abc"
    assert g.promotedBy == "alice"
    assert g.evidence == "evidence-ref-001"
    assert g.lastSafeLevel == AutonomyLevel.in_loop
    assert g.demotionTriggers == [DemotionTrigger.stale_confidence]
    assert g.demotionReason is None
    assert g.labelLatency == "P1D"
    assert g.ownerId == "alice"


def test_put_grant_sets_valid_hash():
    """After put_grant, the item-level hash equals compute_grant_hash and the
    stored bytes are the canonical payload."""
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    g = make_grant()
    store.put_grant(g, session=None)

    result = store.get_grant(PRINCIPAL, "email.send")
    assert result.stored_hash == compute_grant_hash(g, TEST_KEY)
    assert result.raw_data == canonical_grant_payload(g)


def test_get_nonexistent_returns_none():
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    result = store.get_grant(PRINCIPAL, "nonexistent.class")
    assert result.grant is None
    assert not result.quarantined


def test_overwrite_replaces_grant():
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    store.put_grant(make_grant(ownerId="alice"), session=None)
    store.put_grant(make_grant(ownerId="bob"), session=None)

    result = store.get_grant(PRINCIPAL, "email.send")
    assert result.grant is not None
    assert result.grant.ownerId == "bob"


# ---------------------------------------------------------------------------
# InMemoryGrantStore — hash mismatch triggers quarantine
# ---------------------------------------------------------------------------


def test_hash_mismatch_sets_quarantine_flag():
    """Tampering with the stored hash attribute must surface a quarantine flag."""
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    store.put_grant(make_grant(), session=None)

    # Tamper: overwrite the item-level hash directly (simulates item corruption)
    key = ("agent-1#email#alice#B", "email.send")
    store._store[key]["grantHash"] = "tampered-hash-value"

    result = store.get_grant(PRINCIPAL, "email.send")
    assert result.quarantined is True
    assert result.quarantine_reason is not None
    # Tampered bytes are never parsed (#246): grant is None, bytes ride raw_data.
    assert result.grant is None
    assert result.raw_data is not None


def test_data_tamper_quarantines_and_bytes_ride_for_audit():
    """A byte tamper of the data payload quarantines, and the raw bytes are
    returned for audit — callers get evidence, never a parsed Grant."""
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    store.put_grant(make_grant(), session=None)
    key = ("agent-1#email#alice#B", "email.send")
    tampered = store._store[key]["data"].replace('"alice"', '"mallory"', 1)
    store._store[key]["data"] = tampered

    result = store.get_grant(PRINCIPAL, "email.send")
    assert result.quarantined is True
    assert result.grant is None
    assert result.raw_data == tampered


# ---------------------------------------------------------------------------
# Schema validation — Grant missing ownerId must be rejected
# ---------------------------------------------------------------------------


def test_schema_rejects_grant_missing_owner_id():
    """Grant.ownerId is required; construction without it raises ValidationError."""
    data = {k: v for k, v in GRANT_BASE.items() if k != "ownerId"}
    with pytest.raises(ValidationError) as exc_info:
        Grant(**data)
    assert "ownerId" in str(exc_info.value)


def test_schema_rejects_grant_missing_principal():
    data = {k: v for k, v in GRANT_BASE.items() if k != "principal"}
    with pytest.raises(ValidationError) as exc_info:
        Grant(**data)
    assert "principal" in str(exc_info.value)


# ---------------------------------------------------------------------------
# DynamoDBGrantStore — agent IAM role cannot write (mock boto3; no live AWS)
# ---------------------------------------------------------------------------


def _make_dynamo_store(table_name: str = "grants-test") -> DynamoDBGrantStore:
    return DynamoDBGrantStore(hmac_key=TEST_KEY, table_name=table_name)


def test_dynamo_put_propagates_access_denied():
    """AccessDenied from DynamoDB is NOT swallowed — the caller must see it."""
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
        store.put_grant(make_grant(), session=mock_session)

    assert exc_info.value.response["Error"]["Code"] == "AccessDeniedException"


def test_dynamo_get_returns_none_on_missing_item():
    store = _make_dynamo_store()
    mock_table = MagicMock()
    mock_table.get_item.return_value = {}  # no "Item" key

    with patch("boto3.resource") as mock_resource:
        mock_resource.return_value.Table.return_value = mock_table
        result = store.get_grant(PRINCIPAL, "email.send")

    assert result.grant is None
    assert not result.quarantined


def test_dynamo_round_trip_via_mock():
    """put_grant then get_grant with a mock DynamoDB preserves all fields."""
    store = _make_dynamo_store()

    # Capture what put_item was called with
    captured_items: list[dict] = []
    mock_put_session = MagicMock()
    mock_put_table = MagicMock()
    mock_put_session.resource.return_value.Table.return_value = mock_put_table
    mock_put_table.put_item.side_effect = lambda Item: captured_items.append(Item)

    store.put_grant(make_grant(), session=mock_put_session)
    assert len(captured_items) == 1
    item = captured_items[0]
    assert item["pk"].startswith("GRANT#")
    assert item["sk"].startswith("CLASS#")
    # The stored bytes ARE the basis: data is the canonical payload and the
    # item-level grantHash is the HMAC over exactly those bytes (#246).
    assert item["data"] == canonical_grant_payload(make_grant())
    assert item["grantHash"] == _hmac_payload(item["data"], TEST_KEY)

    # Now simulate get_grant returning what was stored
    mock_get_table = MagicMock()
    mock_get_table.get_item.return_value = {"Item": item}
    with patch("boto3.resource") as mock_resource:
        mock_resource.return_value.Table.return_value = mock_get_table
        result = store.get_grant(PRINCIPAL, "email.send")

    assert result.grant is not None
    assert not result.quarantined
    assert result.grant.ownerId == "alice"
    assert result.grant.actionClass == "email.send"


def test_dynamo_get_quarantines_on_hash_mismatch():
    """A tampered 'data' blob in DynamoDB triggers the quarantine flag on read."""
    store = _make_dynamo_store()

    # Build a well-formed item but corrupt the item-level hash
    item = {
        "pk": "GRANT#agent-1#email#alice#B",
        "sk": "CLASS#email.send",
        "data": canonical_grant_payload(make_grant()),
        "grantHash": "tampered",
    }

    mock_get_table = MagicMock()
    mock_get_table.get_item.return_value = {"Item": item}
    with patch("boto3.resource") as mock_resource:
        mock_resource.return_value.Table.return_value = mock_get_table
        result = store.get_grant(PRINCIPAL, "email.send")

    assert result.quarantined is True
    assert result.grant is None  # tampered bytes are never parsed (#246)
    assert result.raw_data == item["data"]  # bytes ride for audit


# ---------------------------------------------------------------------------
# update_grant — conditional UpdateItem semantics (InMemory)
# ---------------------------------------------------------------------------


def test_inmemory_update_grant_persists_and_rehashes():
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    store.put_grant(make_grant(), session=None)
    current = store.get_grant(PRINCIPAL, "email.send")

    updated = current.grant.model_copy(update={"level": AutonomyLevel.in_loop, "ownerId": "bob"})
    store.update_grant(updated, current.stored_hash, session=None, prev_raw_data=current.raw_data)

    after = store.get_grant(PRINCIPAL, "email.send")
    assert not after.quarantined  # hash was recomputed on write
    assert after.grant.ownerId == "bob"


def test_inmemory_update_grant_conflict_on_stale_hash():
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    store.put_grant(make_grant(ownerId="alice"), session=None)
    current = store.get_grant(PRINCIPAL, "email.send")

    # Concurrent modification lands between read and write
    store.put_grant(make_grant(ownerId="mallory"), session=None)

    updated = current.grant.model_copy(update={"level": AutonomyLevel.in_loop})
    with pytest.raises(GrantUpdateConflictError, match="concurrently"):
        store.update_grant(
            updated, current.stored_hash, session=None, prev_raw_data=current.raw_data
        )


def test_inmemory_update_grant_never_creates():
    store = InMemoryGrantStore(hmac_key=TEST_KEY)  # empty
    with pytest.raises(GrantUpdateConflictError, match="cannot create"):
        store.update_grant(make_grant(), "any-hash", session=None, prev_raw_data="{}")
    assert store.get_grant(PRINCIPAL, "email.send").grant is None


def test_update_grant_requires_prev_raw_data():
    """prev_raw_data=None refuses BEFORE any store access (#246: the legacy
    fallback is retired; failing toward writing nothing)."""
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    store.put_grant(make_grant(), session=None)
    current = store.get_grant(PRINCIPAL, "email.send")
    with pytest.raises(ValueError, match="prev_raw_data"):
        store.update_grant(current.grant, current.stored_hash, session=None)


def test_read_result_carries_raw_data():
    """GrantReadResult.raw_data is the exact stored serialization — the
    integrity basis update_grant conditions on."""
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    store.put_grant(make_grant(), session=None)
    result = store.get_grant(PRINCIPAL, "email.send")
    assert result.raw_data == canonical_grant_payload(result.grant)


def test_inmemory_update_grant_rejects_data_tamper_with_intact_hash():
    """A tamper of the data payload alone (hash attribute untouched) landing
    between the guarded re-read and the write must fail the conditional write
    — overwriting it would destroy the tamper evidence."""
    store = InMemoryGrantStore(hmac_key=TEST_KEY)
    store.put_grant(make_grant(), session=None)
    current = store.get_grant(PRINCIPAL, "email.send")

    # Tamper the stored data bytes WITHOUT touching the hash attribute.
    key = (f"{PRINCIPAL.agentId}#{PRINCIPAL.skill}#{PRINCIPAL.user}#{PRINCIPAL.tier}", "email.send")
    tampered = store._store[key]["data"].replace('"evidence-ref-001"', '"tampered"', 1)
    store._store[key]["data"] = tampered

    updated = current.grant.model_copy(update={"ownerId": "bob"})
    with pytest.raises(GrantUpdateConflictError):
        store.update_grant(
            updated, current.stored_hash, session=None, prev_raw_data=current.raw_data
        )
    # The tampered state stands for audit — never silently overwritten.
    assert store._store[key]["data"] == tampered


# ---------------------------------------------------------------------------
# update_grant — DynamoDB expression shape + error mapping (mock boto3)
# ---------------------------------------------------------------------------


def _capture_update(store: DynamoDBGrantStore, **update_kwargs) -> dict:
    """Run update_grant against a MagicMock table; return the update_item kwargs."""
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table

    store.update_grant(session=mock_session, **update_kwargs)

    assert mock_table.update_item.call_count == 1
    return mock_table.update_item.call_args.kwargs


def test_dynamo_update_grant_conditions_on_hash_and_bytes():
    """The condition requires BOTH halves from the guarded re-read: the
    item-level grantHash AND the exact stored data bytes — a tamper of either
    half alone fails the write."""
    store = _make_dynamo_store()
    kwargs = _capture_update(
        store, updated=make_grant(), expected_hash="expected-123", prev_raw_data='{"old": 1}'
    )

    assert kwargs["ConditionExpression"] == (
        "attribute_exists(pk) AND grantHash = :expected AND #data = :prev_data"
    )
    assert kwargs["ExpressionAttributeValues"][":expected"] == "expected-123"
    assert kwargs["ExpressionAttributeValues"][":prev_data"] == '{"old": 1}'
    # The write SETs both the data blob and the item-level hash, via #data
    # ('data' is a DynamoDB reserved word)
    assert kwargs["UpdateExpression"] == "SET #data = :data, grantHash = :new_hash"
    assert kwargs["ExpressionAttributeNames"] == {"#data": "data"}
    written = kwargs["ExpressionAttributeValues"][":data"]
    assert written == canonical_grant_payload(make_grant())
    assert kwargs["ExpressionAttributeValues"][":new_hash"] == _hmac_payload(written, TEST_KEY)


def test_dynamo_update_grant_requires_prev_raw_data():
    """prev_raw_data=None refuses BEFORE any AWS call (#246)."""
    store = _make_dynamo_store()
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    with pytest.raises(ValueError, match="prev_raw_data"):
        store.update_grant(make_grant(), "expected-123", session=mock_session)
    mock_table.update_item.assert_not_called()


def test_dynamo_update_grant_maps_conditional_failure_to_conflict():
    from botocore.exceptions import ClientError

    store = _make_dynamo_store()
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    mock_table.update_item.side_effect = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "The conditional request failed"}},
        "UpdateItem",
    )

    with pytest.raises(GrantUpdateConflictError):
        store.update_grant(make_grant(), "stale-hash", session=mock_session, prev_raw_data="{}")


def test_dynamo_update_grant_propagates_access_denied():
    """AccessDenied is NOT mapped to a conflict — the caller must see it."""
    from botocore.exceptions import ClientError

    store = _make_dynamo_store()
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    mock_table.update_item.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "User is not authorized"}},
        "UpdateItem",
    )

    with pytest.raises(ClientError) as exc_info:
        store.update_grant(make_grant(), "hash", session=mock_session, prev_raw_data="{}")
    assert exc_info.value.response["Error"]["Code"] == "AccessDeniedException"


# ---------------------------------------------------------------------------
# DynamoDBPromotionRecordStore — item layout + append-only error mapping
# ---------------------------------------------------------------------------


def make_record(**overrides) -> PromotionRecord:
    """A valid bootstrap-typed record (simplest shape: no maker≠checker rule)."""
    defaults = dict(
        recordType="bootstrap",
        actionClass="email.send",
        principal=PRINCIPAL,
        fromLevel=None,
        toLevel=AutonomyLevel.in_loop,
        evidence="seed",
        proposedBy="alice",
        ratifiedBy="alice",
        envelopeHash="sha256:abc",
        ts="2026-06-28T00:00:00+00:00",
    )
    defaults.update(overrides)
    return PromotionRecord(**defaults)


def test_record_store_item_layout():
    """pk mirrors the GRANT# component order with actionClass appended;
    sk is ts-first for chronological Query."""
    store = DynamoDBPromotionRecordStore(table_name="grants-test")
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table

    store.put_record(make_record(), session=mock_session)

    kwargs = mock_table.update_item.call_args.kwargs
    assert kwargs["Key"] == {
        "pk": "RECORD#agent-1#email#alice#B#email.send",
        "sk": "2026-06-28T00:00:00+00:00#bootstrap",
    }
    assert kwargs["ConditionExpression"] == "attribute_not_exists(pk)"
    assert kwargs["UpdateExpression"] == "SET #data = :data"
    stored = PromotionRecord.model_validate_json(kwargs["ExpressionAttributeValues"][":data"])
    assert stored == make_record()


def test_record_store_append_only_violation_raises():
    from botocore.exceptions import ClientError

    store = DynamoDBPromotionRecordStore(table_name="grants-test")
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    mock_table.update_item.side_effect = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "The conditional request failed"}},
        "UpdateItem",
    )

    with pytest.raises(RecordAlreadyExistsError, match="append-only"):
        store.put_record(make_record(), session=mock_session)


def test_inmemory_record_store_append_only():
    """The in-memory fake enforces the same append-only key rule as DynamoDB."""
    store = InMemoryPromotionRecordStore()
    store.put_record(make_record(), session=None)

    with pytest.raises(RecordAlreadyExistsError, match="append-only"):
        store.put_record(make_record(), session=None)

    # A different sk (ts or recordType) under the same pk appends fine
    store.put_record(make_record(ts="2026-06-28T01:00:00+00:00"), session=None)
    assert len(store.records) == 2


# ---------------------------------------------------------------------------
# Record ts canonical validation — reject, never normalize (#191)
# ---------------------------------------------------------------------------


# The sk is "<ts>#<recordType>" and list_records relies on LEXICAL sk order
# being chronological: 'Z' sorts after digits while '+' sorts before them, so
# a mixed-suffix ledger silently loses chronological order. Records may also
# be DSSE-signed over their stored bytes — hence reject, never normalize.
NON_CANONICAL_TS = [
    "2026-06-28T00:00:00Z",       # 'Z' suffix
    "2026-06-28T00:00:00",        # naive
    "2026-06-28T02:00:00+02:00",  # non-UTC offset
    "not-a-timestamp",            # unparseable
]


@pytest.mark.parametrize("ts", NON_CANONICAL_TS)
def test_dynamo_put_record_rejects_non_canonical_ts(ts):
    store = DynamoDBPromotionRecordStore(table_name="grants-test")
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table

    with pytest.raises(RecordTimestampFormatError):
        store.put_record(make_record(ts=ts), session=mock_session)
    # Rejected BEFORE any write reaches DynamoDB
    mock_table.update_item.assert_not_called()


@pytest.mark.parametrize("ts", NON_CANONICAL_TS)
def test_inmemory_put_record_rejects_non_canonical_ts(ts):
    store = InMemoryPromotionRecordStore()
    with pytest.raises(RecordTimestampFormatError):
        store.put_record(make_record(ts=ts), session=None)
    assert store.records == []


def test_canonical_ts_accepted_by_both_stores():
    canonical = make_record(ts="2026-06-28T00:00:00+00:00")

    in_memory = InMemoryPromotionRecordStore()
    in_memory.put_record(canonical, session=None)
    assert in_memory.records == [canonical]

    store = DynamoDBPromotionRecordStore(table_name="grants-test")
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    store.put_record(canonical, session=mock_session)
    assert mock_table.update_item.call_count == 1


# ---------------------------------------------------------------------------
# list_records ts_prefix — the runner's same-day dedupe read (#191)
# ---------------------------------------------------------------------------


def test_dynamo_list_records_ts_prefix_narrows_query():
    store = DynamoDBPromotionRecordStore(table_name="grants-test")
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    mock_table.query.return_value = {"Items": []}

    store.list_records(PRINCIPAL, "email.send", mock_session, ts_prefix="2026-06-28")

    kwargs = mock_table.query.call_args.kwargs
    assert kwargs["KeyConditionExpression"] == "pk = :pk AND begins_with(sk, :prefix)"
    assert kwargs["ExpressionAttributeValues"][":prefix"] == "2026-06-28"


def test_dynamo_list_records_without_prefix_keeps_pk_only_query():
    store = DynamoDBPromotionRecordStore(table_name="grants-test")
    mock_session = MagicMock()
    mock_table = MagicMock()
    mock_session.resource.return_value.Table.return_value = mock_table
    mock_table.query.return_value = {"Items": []}

    store.list_records(PRINCIPAL, "email.send", mock_session)

    kwargs = mock_table.query.call_args.kwargs
    assert kwargs["KeyConditionExpression"] == "pk = :pk"
    assert ":prefix" not in kwargs["ExpressionAttributeValues"]


def test_inmemory_list_records_ts_prefix_filters_by_day():
    store = InMemoryPromotionRecordStore()
    store.put_record(make_record(ts="2026-06-29T01:00:00+00:00"), session=None)
    store.put_record(make_record(ts="2026-06-28T01:00:00+00:00"), session=None)

    same_day = store.list_records(PRINCIPAL, "email.send", ts_prefix="2026-06-28")
    assert [r.ts for r in same_day] == ["2026-06-28T01:00:00+00:00"]

    # No prefix → all records, sk-sorted (chronological) despite insertion order
    all_records = store.list_records(PRINCIPAL, "email.send")
    assert [r.ts for r in all_records] == [
        "2026-06-28T01:00:00+00:00",
        "2026-06-29T01:00:00+00:00",
    ]
