"""Tests for broker.audit — tamper-evident AuditRecord emission.

All tests run against InMemorySink. No AWS credentials, no moto, no live S3.

Acceptance criteria (from sa#24 #49):
- Ten emissions form a valid chain (each prevHash == prior record's hash).
- Mutating any field breaks the chain (ChainError from verify_chain).
- Deleting a record creates a seq gap (ChainError from verify_chain).
- Sink interface exposes only append — no delete / overwrite method.
"""


import json
import pathlib

import pytest

from safe_agents.broker.audit import (
    GENESIS_PREV_HASH,
    ChainError,
    InMemorySink,
    S3ObjectLockSink,
    emit,
    hash_stored_call,
    verify_chain,
)
from safe_agents.broker.schemas import AuditRecord, BrokeredCall
from safe_agents.broker.schemas.common import Principal

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-1", skill="email", user="alice", tier="B")

BASE_EMIT = dict(
    principal=PRINCIPAL,
    tool="email",
    op="send",
    args={"to": "bob@example.com", "subject": "Hi"},
    envelope_hash="sha256:envelope",
    decision="allow",
    outcome="executed",
)


def _fill(n: int, **overrides):
    """Emit n records into a fresh InMemorySink; return (sink, records list)."""
    sink = InMemorySink()
    records = [emit(sink, **{**BASE_EMIT, **overrides}) for _ in range(n)]
    return sink, records


# ---------------------------------------------------------------------------
# 1. Ten emissions form a valid chain
# ---------------------------------------------------------------------------

def test_ten_emissions_valid_chain():
    _, records = _fill(10)
    assert len(records) == 10

    # Seq is monotonically 0..9
    for i, r in enumerate(records):
        assert r.seq == i, f"seq={r.seq} at index {i}"

    # Genesis record's prevHash is the sentinel
    assert records[0].prevHash == GENESIS_PREV_HASH

    # Each subsequent record's prevHash equals the prior record's hash
    for i in range(1, len(records)):
        assert records[i].prevHash == records[i - 1].hash, (
            f"chain broken between seq={i - 1} and seq={i}"
        )

    # verify_chain must pass without exception
    verify_chain(records)


# ---------------------------------------------------------------------------
# 2. Mutation of any field breaks the chain
# ---------------------------------------------------------------------------

# #198 receipt kwargs — used wherever a test needs records that HAVE receipts set.
RECEIPT_EMIT = dict(
    intent_id="intent-golden-1",
    stored_call_digest="sha256:" + "5" * 64,
    result_digest="sha256:" + "6" * 64,
)


@pytest.mark.parametrize("field,value", [
    ("tool", "payments"),
    ("op", "transfer"),
    ("ts", "1970-01-01T00:00:00+00:00"),
    ("argsDigest", "sha256:" + "a" * 64),
    ("envelopeHash", "sha256:" + "b" * 64),
    ("outcome", "denied"),
    # #198 — mutating a PRESENT receipt field breaks the chain like any other field
    ("intentId", "intent-swapped"),
    ("storedCallDigest", "sha256:" + "e" * 64),
    ("resultDigest", "sha256:" + "f" * 64),
])
def test_field_mutation_breaks_chain(field, value):
    _, records = _fill(5, **RECEIPT_EMIT)
    records = list(records)
    # Tamper with the middle record
    records[2] = records[2].model_copy(update={field: value})
    with pytest.raises(ChainError):
        verify_chain(records)


def test_prevHash_mutation_breaks_chain():
    _, records = _fill(3)
    records = list(records)
    records[1] = records[1].model_copy(update={"prevHash": "sha256:" + "c" * 64})
    with pytest.raises(ChainError):
        verify_chain(records)


def test_stored_hash_field_tampered_is_detected():
    # If an attacker updates record.hash in-place but not the fields,
    # the verifier must detect the mismatch.
    _, records = _fill(3)
    records = list(records)
    records[0] = records[0].model_copy(update={"hash": "sha256:" + "d" * 64})
    with pytest.raises(ChainError):
        verify_chain(records)


# ---------------------------------------------------------------------------
# 3. Deletion creates a seq gap — detectable
# ---------------------------------------------------------------------------

def test_delete_middle_record_detected():
    _, records = _fill(5)
    gapped = [r for r in records if r.seq != 2]
    assert len(gapped) == 4
    with pytest.raises(ChainError):
        verify_chain(gapped)


def test_delete_first_record_detected():
    _, records = _fill(5)
    without_first = records[1:]
    # seq=1's prevHash points to seq=0; verify_chain starts expecting seq=0 (GENESIS).
    with pytest.raises(ChainError):
        verify_chain(without_first)


def test_delete_last_record_shortens_chain():
    # Dropping the tail is not detectable from the chain alone (the verifier only
    # checks the records it is given). This is expected and correct — detecting
    # tail truncation requires an out-of-band record count or tip commitment.
    _, records = _fill(5)
    verify_chain(records[:-1])  # must not raise


# ---------------------------------------------------------------------------
# 4. Sink interface: only append — no delete / overwrite
# ---------------------------------------------------------------------------

FORBIDDEN_WRITE_NAMES = {
    "delete",
    "remove",
    "overwrite",
    "replace",
    "truncate",
    "clear",
    "pop",
    "reset",
}


def _public_callable_names(obj) -> set[str]:
    """Return names of public, callable attributes (methods)."""
    return {
        name
        for name in dir(obj)
        if not name.startswith("_") and callable(getattr(type(obj), name, None))
        and not isinstance(getattr(type(obj), name, None), property)
    }


def test_in_memory_sink_no_delete_or_overwrite():
    sink = InMemorySink()
    methods = _public_callable_names(sink)
    overlap = FORBIDDEN_WRITE_NAMES & methods
    assert overlap == set(), (
        f"InMemorySink exposes forbidden write methods: {overlap!r}"
    )


def test_s3_sink_no_delete_or_overwrite():
    sink = S3ObjectLockSink("test-bucket")
    methods = _public_callable_names(sink)
    overlap = FORBIDDEN_WRITE_NAMES & methods
    assert overlap == set(), (
        f"S3ObjectLockSink exposes forbidden write methods: {overlap!r}"
    )


# ---------------------------------------------------------------------------
# 5. argsDigest is a hash — raw args are never in the record
# ---------------------------------------------------------------------------

def test_args_digest_hides_raw_args():
    sensitive = {"to": "bob@example.com", "body": "secret-password-123"}
    sink = InMemorySink()
    record = emit(sink, **{**BASE_EMIT, "args": sensitive})

    # Raw field values must not appear in argsDigest
    for v in sensitive.values():
        assert v not in record.argsDigest, f"{v!r} leaked into argsDigest"

    # argsDigest must be a sha256 hex string of the correct length
    assert record.argsDigest.startswith("sha256:")
    assert len(record.argsDigest) == len("sha256:") + 64


# ---------------------------------------------------------------------------
# 6. All six decision outcomes produce valid records
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("decision,outcome", [
    ("allow", "executed"),
    ("deny", "denied"),
    ("transform", "executed"),
    ("require_approval", "held"),
    ("abstain", "denied"),
    ("allow", "failed"),  # failure mid-execution still writes outcome=failed
])
def test_all_decision_outcome_pairs_emit(decision, outcome):
    sink = InMemorySink()
    record = emit(sink, **{**BASE_EMIT, "decision": decision, "outcome": outcome})
    assert record.decision == decision
    assert record.outcome == outcome
    verify_chain(sink.records())


# ---------------------------------------------------------------------------
# 7. Empty and single-record chains verify without error
# ---------------------------------------------------------------------------

def test_empty_chain_is_valid():
    verify_chain([])


def test_single_record_chain_is_valid():
    _, records = _fill(1)
    verify_chain(records)
    assert records[0].prevHash == GENESIS_PREV_HASH


# ---------------------------------------------------------------------------
# 8. Failure path: outcome=failed still writes a record
# ---------------------------------------------------------------------------

def test_failure_mid_execution_writes_record():
    sink = InMemorySink()
    record = emit(
        sink,
        **{**BASE_EMIT, "outcome": "failed", "error": "connector timeout"},
    )
    assert record.outcome == "failed"
    assert record.error == "connector timeout"
    assert record.seq == 0
    verify_chain([record])


# ---------------------------------------------------------------------------
# 9. Hash chaining is deterministic — same fields produce same hash
# ---------------------------------------------------------------------------

def test_args_digest_is_deterministic():
    args = {"b": 2, "a": 1}  # unsorted
    sink1 = InMemorySink()
    sink2 = InMemorySink()
    r1 = emit(sink1, **{**BASE_EMIT, "args": args})
    r2 = emit(sink2, **{**BASE_EMIT, "args": args})
    assert r1.argsDigest == r2.argsDigest


# ---------------------------------------------------------------------------
# 10. #198 receipts — back-compat + tamper evidence
# ---------------------------------------------------------------------------

def test_golden_prereceipts_chain_verifies():
    """Byte-for-byte back-compat: a chain hashed by PRE-#198 emit() still verifies.

    The fixture's hashes were computed before the receipt fields existed; absent
    (None) receipt fields must be omitted from the recomputed hash, so every
    pre-receipts record recomputes byte-for-byte.
    """
    path = pathlib.Path(__file__).parent / "fixtures" / "golden_prereceipts_chain.json"
    records = [AuditRecord.model_validate(r) for r in json.loads(path.read_text(encoding="utf-8"))]
    verify_chain(records)  # must not raise
    assert all(
        r.intentId is None and r.storedCallDigest is None and r.resultDigest is None
        for r in records
    )


def test_receipt_fields_default_none_keep_hash_identical():
    """Explicit-None receipt kwargs == omitted: the record verifies with all None."""
    sink = InMemorySink()
    record = emit(
        sink,
        **BASE_EMIT,
        intent_id=None,
        stored_call_digest=None,
        result_digest=None,
    )
    verify_chain([record])
    assert record.intentId is None
    assert record.storedCallDigest is None
    assert record.resultDigest is None


def test_receipt_fields_present_chain_verifies():
    _, records = _fill(3, **RECEIPT_EMIT)
    verify_chain(records)
    for r in records:
        assert r.intentId == RECEIPT_EMIT["intent_id"]
        assert r.storedCallDigest == RECEIPT_EMIT["stored_call_digest"]
        assert r.resultDigest == RECEIPT_EMIT["result_digest"]


@pytest.mark.parametrize("field", ["intentId", "storedCallDigest", "resultDigest"])
def test_stripping_receipt_field_breaks_chain(field):
    """A PRESENT receipt field is hash-covered: stripping it back to None must be
    tamper-evident, not silently equivalent to a pre-receipts record."""
    _, records = _fill(3, **RECEIPT_EMIT)
    records = list(records)
    records[1] = records[1].model_copy(update={field: None})
    with pytest.raises(ChainError):
        verify_chain(records)


def test_stored_call_digest_stable_across_intent_store_roundtrip():
    """hash_stored_call must survive the intent store's JSON round trip
    (approval/store.py serializes model_dump_json -> model_validate_json)."""
    call = BrokeredCall.model_validate(
        {
            "principal": {"agentId": "agent-1", "skill": "email", "user": "alice", "tier": "B"},
            "tool": "payments",
            "op": "transfer",
            "args": {"amount": 500, "to": "acct-xyz"},
            "manifest": {"tool": "payments", "op": "transfer", "effect": "write", "external": True, "reversible": False},
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "turn-x", "ingestedSources": []},
            "ts": "2026-07-14T00:00:00Z",
        }
    )
    roundtripped = BrokeredCall.model_validate_json(call.model_dump_json())
    assert hash_stored_call(call) == hash_stored_call(roundtripped)
