"""Audit-chain integrity verifier — reads the tape, reuses broker.audit.verify_chain.

This is a WATCHDOG: it detects and reports; it never writes, fixes, or modifies records.

The reader is injected so callers can supply an in-memory fake for tests or an S3-backed
reader for production without touching this logic.

Structured findings are returned (never raised); the caller decides what alarm to fire.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from safe_agents.broker.audit import ChainError, verify_chain
from safe_agents.broker.schemas import AuditRecord

# Patterns used to extract the broken seq from ChainError messages produced by
# broker.audit.verify_chain — these mirror the messages in _chain.py.
_SEQ_PATTERNS = [
    re.compile(r"seq gap detected: expected (\d+)"),
    re.compile(r"(?:prevHash|hash) mismatch at seq=(\d+)"),
]


def _extract_seq(msg: str) -> int | None:
    """Try to parse the first broken seq from a ChainError message."""
    for pat in _SEQ_PATTERNS:
        m = pat.search(msg)
        if m:
            return int(m.group(1))
    return None


@runtime_checkable
class AuditTapeReader(Protocol):
    """Read-only access to a sequence of AuditRecords ordered by seq.

    Implementations must return records sorted ascending by seq. The verifier
    does not sort — it trusts the reader's ordering contract.
    """

    def read_all(self) -> list[AuditRecord]:
        """Return all records in seq-ascending order."""
        ...


@dataclass(frozen=True)
class ChainIntegrityFinding:
    """Structured result from check_chain_integrity().

    intact=True  — the tape is valid; no fields are set.
    intact=False — the tape has a gap or mutation; error and (when parseable)
                   broken_seq describe the first violation found.
    """

    intact: bool
    error: str | None = None
    broken_seq: int | None = None


def check_chain_integrity(reader: AuditTapeReader) -> ChainIntegrityFinding:
    """Verify the audit tape loaded by reader forms an intact hash chain.

    Delegates the per-record checks to broker.audit.verify_chain. Converts
    ChainError to a structured finding so callers can alarm/log without catching.

    An empty tape is considered intact (no records to be broken).
    """
    records = reader.read_all()
    try:
        verify_chain(records)
        return ChainIntegrityFinding(intact=True)
    except ChainError as exc:
        msg = str(exc)
        return ChainIntegrityFinding(
            intact=False,
            error=msg,
            broken_seq=_extract_seq(msg),
        )


# ---------------------------------------------------------------------------
# In-memory fake reader — for tests and local development only
# ---------------------------------------------------------------------------

class InMemoryTapeReader:
    """AuditTapeReader backed by a plain list. No AWS required.

    The list is copied on construction; the reader is immutable after that point.
    """

    def __init__(self, records: list[AuditRecord]) -> None:
        self._records = list(records)

    def read_all(self) -> list[AuditRecord]:
        return list(self._records)


# ---------------------------------------------------------------------------
# File reader — the local floor's tape (#300)
# ---------------------------------------------------------------------------

class FileTapeReader:
    """AuditTapeReader over the JSON-lines tape FileAuditSink writes.

    The shipped readers were in-memory and S3, so the one tape the local floor
    ACTUALLY writes had no reader at all: verifying it meant hand-rolling code
    around ``FileAuditSink(path).records()``. That is a strange gap to leave in a
    product whose payoff is "look at what the broker recorded" (#300).

    Parsing, torn-write tolerance and locking are deliberately NOT reimplemented
    here — they are the sink's, and a second parser is a second set of rules about
    what counts as a record. This delegates, which is what keeps a reader from
    disagreeing with the writer about the contents of the same file.

    **What verifying this proves, and what it does not.** At rung 1 the chain
    establishes SELF-CONSISTENCY: it detects an isolated edit or a deleted record.
    It is not tamper-evidence, because the chain is unkeyed SHA-256 and anyone who
    can write the file can recompute every hash. Real tamper-evidence needs
    off-device append-only durability (S3 Object Lock), which is rung 3. Any
    surface reporting this result has to say so — see `example-wrapper audit`.
    """

    def __init__(self, path: str) -> None:
        self._path = path

    def read_all(self) -> list[AuditRecord]:
        """Every complete record on disk, in seq order (which is file order).

        A missing tape reads as empty rather than raising: a project whose agent
        has made no brokered call yet has an absent file, and that is a legitimate
        state to report, not an error.
        """
        from safe_agents.broker.audit import FileAuditSink  # noqa: PLC0415 — cycle

        return FileAuditSink(self._path).records()


# ---------------------------------------------------------------------------
# S3 reader — production, lazy boto3 import
# ---------------------------------------------------------------------------

class S3TapeReader:
    """AuditTapeReader that lists and fetches records from S3.

    Uses the same key format written by S3ObjectLockSink:
        {key_prefix}{seq:010d}.json

    boto3 is imported lazily so callers that only use InMemoryTapeReader (e.g.,
    tests) do not pay the import cost.

    IAM note: this reader requires only s3:ListObjectsV2 and s3:GetObject on the
    audit bucket. It holds NO write permissions — a separate broker IAM identity
    holds PutObject; a separate auditor IAM identity holds read-only access.
    """

    def __init__(self, bucket_name: str, *, key_prefix: str = "audit/") -> None:
        self._bucket = bucket_name
        self._prefix = key_prefix
        self._client = None

    def _s3(self):
        if self._client is None:
            import boto3  # noqa: PLC0415 — intentional lazy import
            self._client = boto3.client("s3")
        return self._client

    def read_all(self) -> list[AuditRecord]:
        """List all objects under the prefix, fetch each, parse AuditRecord."""
        s3 = self._s3()
        keys: list[str] = []
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=self._prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])

        # Sort lexicographically — the zero-padded seq ensures this equals seq order.
        keys.sort()

        records: list[AuditRecord] = []
        for key in keys:
            body = s3.get_object(Bucket=self._bucket, Key=key)["Body"].read()
            records.append(AuditRecord.model_validate_json(body))
        return records
