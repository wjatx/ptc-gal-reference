"""Core audit-chain logic: emit() and verify_chain().

emit()         — build and append one AuditRecord at the moment of a broker decision.
verify_chain() — detect mutation (broken hash) or deletion (seq gap) in a record list.

The agent process must never call emit(). Only the broker runtime (running under its
own IAM identity, with s3:PutObject and nothing else on the audit bucket) does.
"""

from __future__ import annotations

import datetime
import threading

from safe_agents.broker.schemas import AuditRecord
from safe_agents.broker.schemas.common import Principal

from ._hash import GENESIS_PREV_HASH, hash_args, hash_record
from ._sink import AuditSink

# Fallback used only if a sink predates the ``lock`` property; a process-wide lock is
# still correct (it just serialises across sinks). Every shipped sink exposes ``lock``.
_FALLBACK_LOCK = threading.Lock()

# #198 — receipt fields are hash-covered ONLY when present: absent (None) fields are
# omitted from the hashed dict, so every pre-receipts record recomputes byte-for-byte,
# while STRIPPING a present receipt field breaks the chain like any other mutation.
_RECEIPT_FIELDS = ("intentId", "storedCallDigest", "resultDigest")


def _hashable_fields(record_fields: dict) -> dict:
    """Filter record_fields to what hash_record covers (#198 back-compat rule).

    The SINGLE filter both emit() and verify_chain() call, so the two cannot drift.
    """
    return {
        k: v
        for k, v in record_fields.items()
        if not (k in _RECEIPT_FIELDS and v is None)
    }


def emit(
    sink: AuditSink,
    *,
    principal: Principal,
    tool: str,
    op: str,
    args: object,
    decision: str,
    outcome: str,
    envelope_hash: str,
    reason: str | None = None,
    approved_by: str | None = None,
    error: str | None = None,
    seed: str | None = None,
    intent_id: str | None = None,
    stored_call_digest: str | None = None,
    result_digest: str | None = None,
) -> AuditRecord:
    """Build and append a tamper-evident AuditRecord for one broker decision.

    Must be called at the moment of the side effect — never buffered. When a
    connector fails mid-execution, call emit() with outcome="failed" before
    re-raising the exception so the failure is always on the tape.

    The 'args' value is hashed; raw args are never written to the audit store
    (PII discipline — the audit must not become a PII store).

    Raises:
        ValueError: if the sink rejects the record (e.g. seq mismatch).
        pydantic.ValidationError: if any field value is out of schema.
    """
    # Read-then-append is a single critical section: reading next_seq/last_hash and
    # the append() that advances them must not interleave with another thread, or two
    # concurrent /call requests under ThreadingHTTPServer would read the same seq and
    # produce a colliding, gapped chain. Hold the sink's lock across the whole span.
    lock = getattr(sink, "lock", None) or _FALLBACK_LOCK
    with lock:
        seq = sink.next_seq
        prev_hash = sink.last_hash
        ts = datetime.datetime.now(datetime.UTC).isoformat()
        args_digest = hash_args(args)

        # All fields except 'hash' — used for the tamper-evident hash computation.
        record_fields: dict = {
            "seq": seq,
            "ts": ts,
            "principal": principal.model_dump(),
            "tool": tool,
            "op": op,
            "argsDigest": args_digest,
            "decision": decision,
            "reason": reason,
            "envelopeHash": envelope_hash,
            "approvedBy": approved_by,
            "outcome": outcome,
            "error": error,
            "seed": seed,
            "intentId": intent_id,
            "storedCallDigest": stored_call_digest,
            "resultDigest": result_digest,
            "prevHash": prev_hash,
        }
        record_hash = hash_record(_hashable_fields(record_fields))

        record = AuditRecord(**record_fields, hash=record_hash)
        sink.append(record)
    return record


class ChainError(Exception):
    """Raised by verify_chain() when a broken or gapped chain is detected."""


def verify_chain(
    records: list[AuditRecord],
    *,
    expected_start_seq: int = 0,
    expected_prev_hash: str = GENESIS_PREV_HASH,
) -> None:
    """Verify that a sequence of AuditRecords forms an intact hash chain.

    Checks performed for each record in order:
    1. Seq continuity — the first record must have seq == expected_start_seq;
       any gap (e.g. a deleted record) is detected.
    2. prevHash linkage — prevHash must equal the prior record's hash (or
       expected_prev_hash for the very first record supplied).
    3. Hash integrity — the stored hash must equal the hash recomputed from
       all fields (including prevHash); any field mutation is detectable.

    By default, expected_start_seq=0 and expected_prev_hash=GENESIS_PREV_HASH, so
    a full chain from the beginning is verified. Callers verifying a known suffix
    can pass explicit values for both parameters.

    Raises:
        ChainError: on the first violation found.
    """
    if not records:
        return

    expected_seq = expected_start_seq
    prev_hash = expected_prev_hash

    for record in records:
        # 1. Gap detection (deletion of a record shifts seq values)
        if record.seq != expected_seq:
            raise ChainError(
                f"seq gap detected: expected {expected_seq}, found {record.seq}"
            )
        expected_seq += 1

        # 2. prevHash linkage
        if record.prevHash != prev_hash:
            raise ChainError(
                f"prevHash mismatch at seq={record.seq}: "
                f"expected {prev_hash!r}, got {record.prevHash!r}"
            )

        # 3. Hash integrity — recompute and compare
        record_fields = {
            "seq": record.seq,
            "ts": record.ts,
            "principal": record.principal.model_dump(),
            "tool": record.tool,
            "op": record.op,
            "argsDigest": record.argsDigest,
            "decision": record.decision,
            "reason": record.reason,
            "envelopeHash": record.envelopeHash,
            "approvedBy": record.approvedBy,
            "outcome": record.outcome,
            "error": record.error,
            "seed": record.seed,
            "intentId": record.intentId,
            "storedCallDigest": record.storedCallDigest,
            "resultDigest": record.resultDigest,
            "prevHash": record.prevHash,
        }
        computed = hash_record(_hashable_fields(record_fields))
        if record.hash != computed:
            raise ChainError(
                f"hash mismatch at seq={record.seq}: record was tampered "
                f"(stored={record.hash!r}, computed={computed!r})"
            )

        prev_hash = record.hash
