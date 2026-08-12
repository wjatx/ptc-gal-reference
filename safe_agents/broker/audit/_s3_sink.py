"""S3 Object Lock sink — the cloud floor's WORM audit store.

The broker IAM identity holds s3:PutObject + s3:GetObject on the objects and
s3:ListBucket on the bucket, and no delete of any kind. GetObject/ListBucket are
REQUIRED to resume the chain across a restart (sa#132/sa#104) — see resuming() below;
the broker reading back records it wrote itself is not an exfiltration channel
(`infra/lib/identity-stack.ts:162-182`).

WHAT THE BUCKET ENFORCES, AS DEPLOYED — and it is not COMPLIANCE
---------------------------------------------------------------
Object Lock is enabled in **GOVERNANCE** mode with a ~7-year default retention in
durable environments, deliberately, to preserve an `s3:BypassGovernanceRetention`
escape hatch for administrators (`infra/lib/state-stack.ts:152-178`). So the honest
claim is: no broker, agent or other modeled role can delete or overwrite a record
during the retention window, and an administrator holding that bypass permission
can. No role in this repo is granted it.

That is strictly weaker than COMPLIANCE mode, whose distinguishing property is that
not even the account root can shorten retention. Do not describe this bucket as
COMPLIANCE — four docs did until 2026-07-29, which claimed the stronger property.

Retention is also environment-dependent: `development` keeps Object Lock *enabled*
(it cannot be switched on after bucket creation) but sets NO default retention, and
append() sets no per-object retention, so on development nothing is actually locked.
WORM is a property of the durable environments' bucket configuration, never of this
sink.

boto3 is imported lazily so callers that only use InMemorySink (e.g., tests) do not
pay the import cost.
"""

from __future__ import annotations

import logging
import re
import threading

from safe_agents.broker.schemas import AuditRecord

from ._hash import GENESIS_PREV_HASH

logger = logging.getLogger(__name__)

# A record object's key is exactly ``{key_prefix}{seq:010d}.json``. The resume scan
# recovers seq by parsing the key name (never by trusting list order), so the pattern
# is anchored to the 10-zero-padded-digit + ".json" suffix under the prefix.
_KEY_SEQ_RE = re.compile(r"^(\d+)\.json$")


class S3ObjectLockSink:
    """Append-only S3 Object Lock (WORM) sink.

    Each AuditRecord is written as an individual S3 object whose key encodes seq,
    making each object uniquely addressable and ensuring PutObject never silently
    overwrites an existing record (Object Lock enforces this at the bucket level).

    Constructor arguments:
        bucket_name: the S3 bucket name (ImportValue from the StateStack CDK output
                     in sa#11 once that stack is deployed).
        key_prefix:  prefix for all record keys (default "audit/").
        initial_seq: the seq to assign to the first record this process emits.
                     In production, the startup read (performed by a separate role
                     with s3:ListObjectsV2 + s3:GetObject) supplies this value so
                     the in-process counter stays consistent with the durable store.
                     Use ``S3ObjectLockSink.resuming(bucket)`` to derive it from the
                     bucket's existing tape instead of supplying it explicitly.
        initial_last_hash: the prevHash to use for the first record (default:
                           GENESIS_PREV_HASH). Also supplied from the startup read.
    """

    def __init__(
        self,
        bucket_name: str,
        *,
        key_prefix: str = "audit/",
        initial_seq: int = 0,
        initial_last_hash: str = GENESIS_PREV_HASH,
    ) -> None:
        self._bucket = bucket_name
        self._key_prefix = key_prefix
        self._seq = initial_seq
        self._last_hash = initial_last_hash
        self._client = None  # lazily initialized on first append()
        self._lock = threading.Lock()

    @classmethod
    def resuming(cls, bucket_name: str, *, key_prefix: str = "audit/") -> S3ObjectLockSink:
        """Build a sink that continues an existing bucket's audit chain.

        The S3 analog of ``FileAuditSink.resuming(path)`` (sa#104). A long-lived broker
        that restarts must NOT reset ``seq`` to 0 — the fresh ``PutObject`` would collide
        with the existing ``{prefix}{seq:010d}.json`` object (Object Lock blocks the
        overwrite; versioning would otherwise mask it) and, worse, would restart the hash
        chain, silently forking the audit tape. This recovers the tape's head so the next
        append continues one contiguous, ``verify_chain``-valid chain.

        Recovery:
          - List every object under ``key_prefix`` and parse ``{seq:010d}.json`` from each
            KEY NAME, taking the MAX seq (never list order — S3 list order is unspecified).
          - GetObject that max-seq object, parse its AuditRecord, and start the in-process
            counter at ``seq + 1`` with ``last_hash`` = that record's hash.
          - No matching objects → fresh chain at seq=0 / GENESIS_PREV_HASH.

        The broker role itself holds s3:ListBucket + s3:GetObject for exactly this resume
        path, alongside s3:PutObject and no delete of any kind
        (`infra/lib/identity-stack.ts:162-182`).
        """
        client = cls._new_client()
        max_seq = -1
        max_key: str | None = None
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name, Prefix=key_prefix):
            for obj in page.get("Contents", ()):
                key = obj["Key"]
                remainder = key[len(key_prefix):]
                match = _KEY_SEQ_RE.match(remainder)
                if match is None:
                    # A stray object under the prefix that is not a record — never let it
                    # perturb the recovered seq. (The writing role only ever PutObjects
                    # record keys, so this is defensive.)
                    continue
                seq = int(match.group(1))
                if seq > max_seq:
                    max_seq = seq
                    max_key = key

        if max_key is None:
            logger.info(
                "S3ObjectLockSink.resuming: no records under %r in bucket %r; "
                "starting a fresh chain at seq=0.",
                key_prefix,
                bucket_name,
            )
            sink = cls(bucket_name, key_prefix=key_prefix)
            sink._client = client
            return sink

        body = client.get_object(Bucket=bucket_name, Key=max_key)["Body"].read()
        last = AuditRecord.model_validate_json(body)
        logger.info(
            "S3ObjectLockSink.resuming: continuing chain in bucket %r at seq=%d "
            "(max existing seq=%d, key=%r).",
            bucket_name,
            last.seq + 1,
            max_seq,
            max_key,
        )
        sink = cls(
            bucket_name,
            key_prefix=key_prefix,
            initial_seq=last.seq + 1,
            initial_last_hash=last.hash,
        )
        # Reuse the client built for the resume read so the first append() does not pay
        # a second boto3.client() construction.
        sink._client = client
        return sink

    @staticmethod
    def _new_client():
        import boto3  # noqa: PLC0415 — intentional lazy import

        return boto3.client("s3")

    def _s3(self):
        if self._client is None:
            self._client = self._new_client()
        return self._client

    def append(self, record: AuditRecord) -> None:
        """PutObject the record to S3. The key is unique per seq; no overwrite occurs."""
        if record.seq != self._seq:
            raise ValueError(
                f"seq mismatch: expected {self._seq}, got {record.seq}"
            )
        key = f"{self._key_prefix}{record.seq:010d}.json"
        body = record.model_dump_json().encode()
        # Object Lock (GOVERNANCE mode, durable environments only) enforces retention at
        # the bucket level independently of IAM — defence in depth, bypassable only by an
        # admin holding s3:BypassGovernanceRetention. The broker role holds no delete.
        self._s3().put_object(
            Bucket=self._bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
        )
        self._last_hash = record.hash
        self._seq += 1

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def next_seq(self) -> int:
        return self._seq

    @property
    def lock(self) -> threading.Lock:
        """Guards emit()'s read-then-PutObject critical section (see AuditSink.lock)."""
        return self._lock
