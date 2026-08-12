"""AuditSink protocol and the in-memory fake used by tests.

The Protocol declares the append-only contract. The broker IAM identity holds
s3:PutObject on the backing store and nothing else — no s3:DeleteObject, no
overwrite. This interface models that constraint: only append() is exposed as a
write method; delete, remove, overwrite, and truncate have no representation here.

The agent process must NEVER call append(). Only the broker runtime (running under
a separate IAM identity) does.
"""

import threading
from contextlib import AbstractContextManager
from typing import Protocol, runtime_checkable

from safe_agents.broker.schemas import AuditRecord

from ._hash import GENESIS_PREV_HASH


@runtime_checkable
class AuditSink(Protocol):
    """Append-only write interface for AuditRecord objects.

    Permitted operations: append().
    Forbidden at every layer: delete, overwrite, truncate, clear.
    """

    def append(self, record: AuditRecord) -> None:
        """Append one AuditRecord to the chain.

        Called exactly once per broker decision, at the moment of the side effect —
        never buffered. Implementations must reject out-of-order seq values.
        """
        ...

    @property
    def last_hash(self) -> str:
        """Hash of the most recently appended record, or GENESIS_PREV_HASH if empty."""
        ...

    @property
    def next_seq(self) -> int:
        """Monotonic sequence number for the next record (0-indexed)."""
        ...

    @property
    def lock(self) -> AbstractContextManager:
        """Guards the read-then-append critical section (next_seq/last_hash → append).

        emit() acquires this so that under a ThreadingHTTPServer two concurrent /call
        requests cannot read the same next_seq and produce a colliding, gapped chain.

        Typed as a context manager rather than a ``threading.Lock`` because that is
        all emit() ever requires of it, and how WIDE the section must be is the
        implementation's business: an in-process lock suffices for a sink with one
        writer, while FileAuditSink's tape is shared by separate processes and needs
        a cross-process one that also re-reads the tail (#301). Narrowing this to
        threading.Lock would forbid the correct implementation.
        """
        ...


class InMemorySink:
    """Append-only in-memory sink for tests. No AWS required.

    Records are stored in a plain list. Once appended, a record cannot be modified
    or removed through this interface — there is no delete(), pop(), clear(), or
    overwrite() method. The only write surface is append().
    """

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def append(self, record: AuditRecord) -> None:
        expected = len(self._records)
        if record.seq != expected:
            raise ValueError(
                f"seq mismatch: expected {expected}, got {record.seq}"
            )
        self._records.append(record)

    @property
    def last_hash(self) -> str:
        if not self._records:
            return GENESIS_PREV_HASH
        return self._records[-1].hash

    @property
    def next_seq(self) -> int:
        return len(self._records)

    @property
    def lock(self) -> threading.Lock:
        return self._lock

    def records(self) -> list[AuditRecord]:
        """Return a snapshot of all appended records (read-only copy; for tests)."""
        return list(self._records)
