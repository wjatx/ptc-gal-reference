"""broker.audit — tamper-evident AuditRecord emission.

The broker emits one AuditRecord per decision (allow / deny / transform /
require_approval / abstain / failure), written at the moment of the side effect to
an append-only, WORM-backed store the agent process has no credentials to modify.

Public surface:

    emit()              Build and append one AuditRecord (broker runtime only).
    verify_chain()      Detect mutation (broken hash) or deletion (seq gap).
    ChainError          Raised by verify_chain() on a broken or gapped chain.
    AuditSink           Protocol: append-only write interface (no delete, no overwrite).
    InMemorySink        Append-only in-memory fake for tests (no AWS required).
    FileAuditSink       Append-only local-file sink (local arm; not WORM on its own).
    S3ObjectLockSink    Production WORM sink backed by S3 Object Lock.
    GENESIS_PREV_HASH   Sentinel prevHash for the chain root record (seq=0).

Design constraints (load-bearing):
- The agent process must never call emit().
- The broker IAM identity holds s3:PutObject on the audit bucket and nothing else.
- args are always hashed (argsDigest) — raw args never reach the audit store.
- Records are written immediately; no buffering.
"""

from ._chain import ChainError, emit, verify_chain
from ._file_sink import FileAuditSink
from ._hash import GENESIS_PREV_HASH, hash_args, hash_stored_call
from ._s3_sink import S3ObjectLockSink
from ._sink import AuditSink, InMemorySink

__all__ = [
    "emit",
    "verify_chain",
    "ChainError",
    "AuditSink",
    "InMemorySink",
    "FileAuditSink",
    "S3ObjectLockSink",
    "GENESIS_PREV_HASH",
    "hash_args",
    "hash_stored_call",
]
