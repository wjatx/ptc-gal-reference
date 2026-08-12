"""Local-file audit sink — the honest local analog of the S3 Object Lock sink.

FileAuditSink appends each AuditRecord as one JSON line to a file on disk, keeping
the same hash-chain bookkeeping (seq / last_hash) as S3ObjectLockSink. It only ever
appends complete records; it has no delete or overwrite path.

IMPORTANT — this is NOT tamper-evident on its own. A local file can be edited or
truncated by anyone who can write to it, and the in-file hash chain only proves
*self*-consistency: an attacker who rewrites the whole file (recomputing hashes) is
undetectable. Real tamper-evidence requires off-device, append-only durability
(S3 Object Lock — GOVERNANCE mode as deployed, with the limits `_s3_sink.py` states —
or streaming each record to a separate identity as it is written, which is a witness
and is not built). Treat this sink as the local-arm stand-in for that durable store,
useful for SEEing the tape and verifying the chain within a single run — not as a
WORM guarantee.

Crash tolerance (sa#102): a crash mid-append can leave a partial, unterminated final
line. Because every complete record is written with a trailing newline, an unterminated
trailing segment is by definition a torn write that was never a committed record.
resuming() trims those bytes (crash recovery — not deletion of a record) and records()
skips them, both with a logged warning. A malformed line that IS newline-terminated is
real mid-file corruption and still raises — a partial line is only tolerated as the very
last, unterminated line.

MULTI-PROCESS (#301): unlike S3ObjectLockSink, whose writer is a single long-lived
broker, this sink's tape is a file two PROCESSES legitimately share. On the local
floor the gateway daemon and a ceremony CLI are separate processes by design — the
same premise sqlite_substrate.py runs in WAL mode for. An in-process threading.Lock
does not cover that: each process caches its own seq/last_hash, so the second writer
appends a record whose seq duplicates the first's and whose prevHash points at the
wrong parent. Nothing raises at write time; the damage surfaces later as
verify_chain() reporting a seq gap — i.e. an honest concurrent write is indistinguishable
from tampering, which is precisely the confusion the chain exists to resolve.

So the critical section is cross-process: ``lock`` takes an exclusive flock on the tape
AND re-derives seq/last_hash from what is actually on disk before emit() reads them.
The cached counters are therefore a fast path, never the authority — a non-empty file
always wins over the constructor's ``initial_seq``/``initial_last_hash``.

This is a correctness fix within posture 1, not tamper-evidence: it stops honest writers
from corrupting each other. Anyone who can write the file can still rewrite the whole
chain (see the IMPORTANT note above).

boto3 is never imported here; this sink is pure stdlib.
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading

from pydantic import ValidationError

from safe_agents.broker.schemas import AuditRecord

from ._hash import GENESIS_PREV_HASH

try:  # POSIX only — the local arm's platforms (macOS, Linux) all have it.
    import fcntl
except ImportError:  # pragma: no cover — non-POSIX host
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def _flocked(path: str, *, exclusive: bool):
    """Hold an advisory lock on an EXISTING tape file for the duration of the block.

    A missing file is a no-op: there is no other writer to race with yet, and
    creating one here would make a read path silently mint the tape it reads.
    On a host without fcntl the block still runs — degraded to in-process safety
    only, which is stated in the module docstring rather than hidden.
    """
    if fcntl is None or not os.path.exists(path):
        yield None
        return
    with open(path, "rb") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield handle
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _scan(path: str) -> tuple[list[AuditRecord], int, bool]:
    """Parse the audit file into records, tolerating a single torn trailing write.

    Returns ``(records, valid_bytes, torn)``:
      - ``records``     — every complete, valid record, in order.
      - ``valid_bytes`` — length of the file prefix that holds only complete,
                          newline-terminated valid records; any bytes past this are a
                          torn trailing write.
      - ``torn``        — True iff a non-empty, unterminated trailing segment was found.

    A malformed line that is newline-terminated (i.e. was fully committed) is treated
    as corruption and raises ``ValueError`` — only an unterminated trailing line is a
    tolerable torn write.
    """
    if not os.path.exists(path):
        return [], 0, False
    with open(path, "rb") as handle:
        data = handle.read()

    records: list[AuditRecord] = []
    valid_bytes = 0
    pos = 0
    length = len(data)
    while pos < length:
        nl = data.find(b"\n", pos)
        if nl == -1:
            # No terminating newline: an incomplete trailing line (torn write on crash).
            trailing = data[pos:].strip()
            return records, valid_bytes, bool(trailing)
        line = data[pos:nl].strip()
        if not line:
            # Blank line: keep it inside the valid prefix and move on.
            pos = nl + 1
            valid_bytes = pos
            continue
        try:
            records.append(AuditRecord.model_validate_json(line))
        except (ValidationError, ValueError, UnicodeDecodeError) as exc:
            # A fully written (newline-terminated) but malformed line is real corruption
            # in the body of the tape — never silently accepted.
            raise ValueError(
                f"corrupt audit record at byte offset {pos} in {path!r}: {exc}"
            ) from exc
        pos = nl + 1
        valid_bytes = pos
    return records, valid_bytes, False


class _TapeLock:
    """emit()'s critical section, widened to cover other PROCESSES (#301).

    ``emit()`` does ``with sink.lock:``, then reads ``next_seq``/``last_hash``,
    builds the record's hash from them, and calls ``append()``. Every step must
    see the same tape state, so entering this lock does three things in order:

    1. take the in-process lock (threads within this process),
    2. take an exclusive flock on the tape (other processes), and
    3. **refresh the cached counters from disk**, because another process may
       have appended since this sink last looked.

    Step 3 is the one that matters. Without it the flock would serialise the
    writes and still produce a duplicate seq, since each process would faithfully
    write its own stale counter.
    """

    def __init__(self, sink: FileAuditSink) -> None:
        self._sink = sink
        self._handle = None

    def __enter__(self) -> _TapeLock:
        self._sink._thread_lock.acquire()
        try:
            # "a+" creates the tape if absent — correct here, unlike the read
            # paths, because entering this lock means a write is imminent.
            self._handle = open(self._sink._path, "a+", encoding="utf-8")
            if fcntl is not None:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
            self._sink._refresh_from_disk()
        except BaseException:
            # Never strand the in-process lock when acquisition fails partway —
            # a mid-file-corruption ValueError from the refresh comes through here.
            self._release()
            raise
        return self

    def __exit__(self, *_exc: object) -> bool:
        self._release()
        return False

    def _release(self) -> None:
        try:
            if self._handle is not None:
                if fcntl is not None:
                    fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
                self._handle.close()
                self._handle = None
        finally:
            self._sink._thread_lock.release()


class FileAuditSink:
    """Append-only, hash-chained audit sink backed by a JSON-lines file.

    Each AuditRecord is written as one ``record.model_dump_json()`` line. The seq
    and last_hash counters mirror S3ObjectLockSink so emit() chains records the same
    way regardless of which sink is wired in.

    Constructor arguments:
        path: filesystem path to the JSON-lines audit file. The parent directory is
              created if absent. The file is opened in append mode on every write, so
              an existing file is never overwritten.
        initial_seq: seq to assign to the first record this instance appends. When
              resuming an existing file use ``FileAuditSink.resuming(path)`` instead,
              which derives this from the file's last record.
        initial_last_hash: prevHash for the first record this instance appends
              (default GENESIS_PREV_HASH for a fresh chain).

    Both ``initial_*`` values are a starting guess, not a pin: the tape on disk is
    the authority, and ``lock`` re-derives from it before every append (#301).
    """

    def __init__(
        self,
        path: str,
        *,
        initial_seq: int = 0,
        initial_last_hash: str = GENESIS_PREV_HASH,
    ) -> None:
        self._path = path
        self._seq = initial_seq
        self._last_hash = initial_last_hash
        self._thread_lock = threading.Lock()
        self._tape_lock = _TapeLock(self)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _refresh_from_disk(self) -> None:
        """Re-derive seq/last_hash from the tape. Call only while holding the flock.

        An empty or missing tape leaves a fresh chain's starting values alone, so
        a brand-new sink still begins at seq=0 / GENESIS_PREV_HASH.
        """
        records, _valid_bytes, _torn = _scan(self._path)
        if records:
            last = records[-1]
            self._seq = last.seq + 1
            self._last_hash = last.hash

    @classmethod
    def resuming(cls, path: str) -> FileAuditSink:
        """Build a sink that continues an existing audit file's chain.

        Reads the file (if present) to recover the next seq and the last record's
        hash, so a restarted broker process appends without breaking the chain. A
        missing or empty file starts a fresh chain at seq=0 / GENESIS_PREV_HASH.

        Crash recovery: if the file ends in a torn (unterminated) trailing write, those
        bytes are trimmed so the next append starts on a clean line — otherwise the new
        record would be concatenated onto the partial one, corrupting the tape. Trimming
        an uncommitted partial line is WAL recovery, not deletion of a committed record.

        Locked (#301): the trim is a truncate, and a concurrent writer's in-flight
        record looks exactly like a torn tail. Scanning and trimming under the tape
        lock is what keeps this recovery path from deleting another process's
        record as it is being written.
        """
        with _flocked(path, exclusive=True):
            records, valid_bytes, torn = _scan(path)
            if torn:
                logger.warning(
                    "FileAuditSink.resuming: trimming torn trailing write in %r "
                    "(crash recovery); %d byte(s) after the last complete record.",
                    path,
                    os.path.getsize(path) - valid_bytes,
                )
                with open(path, "r+b") as handle:
                    handle.truncate(valid_bytes)
        if records:
            last = records[-1]
            return cls(path, initial_seq=last.seq + 1, initial_last_hash=last.hash)
        return cls(path, initial_seq=0, initial_last_hash=GENESIS_PREV_HASH)

    def append(self, record: AuditRecord) -> None:
        """Append the record as one JSON line. Rejects out-of-order seq values."""
        if record.seq != self._seq:
            raise ValueError(f"seq mismatch: expected {self._seq}, got {record.seq}")
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")
        self._last_hash = record.hash
        self._seq += 1

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def next_seq(self) -> int:
        return self._seq

    @property
    def lock(self) -> _TapeLock:
        """Guards emit()'s read-then-append critical section (see AuditSink.lock).

        Cross-process, not merely cross-thread — see _TapeLock and the module
        docstring's MULTI-PROCESS note.
        """
        return self._tape_lock

    def records(self) -> list[AuditRecord]:
        """Return all complete records currently on disk, parsed into AuditRecord.

        Used by the prototype's debug /audit view and by verify_chain(). Reads the
        whole file each call; fine for the local arm's volumes. A torn (unterminated)
        trailing line is skipped with a logged warning; this reader never mutates the
        file (trimming is resuming()'s job). Mid-file corruption still raises.

        Taken under a SHARED lock (#301) so a reader never catches a concurrent
        writer's record half-written — otherwise `example-wrapper audit --verify` could report
        a broken chain that repairs itself on the next run, which is the worst
        possible behaviour for a tamper check.
        """
        with _flocked(self._path, exclusive=False):
            records, _valid_bytes, torn = _scan(self._path)
        if torn:
            logger.warning(
                "FileAuditSink.records: skipping torn trailing write in %r "
                "(crash artifact); it will be trimmed on the next resuming().",
                self._path,
            )
        return records
