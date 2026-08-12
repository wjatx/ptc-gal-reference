"""moto-backed tests for S3 audit-chain resume-on-restart (sa#104).

Why this file exists
--------------------
``S3ObjectLockSink`` previously started every process at ``seq=0`` /
``GENESIS_PREV_HASH``. A long-lived broker that restarts would then collide seq
with the ``audit/NNNNNNNNNN.json`` objects already in the bucket — Object Lock
blocks the overwrite, versioning would otherwise mask it — and, worse, would
restart the hash chain, silently FORKING the audit tape. ``FileAuditSink`` already
solved the analogous problem with ``.resuming(path)``; ``S3ObjectLockSink.resuming``
is the S3 equivalent.

These tests run the real sink against **moto** (``mock_aws``) so the list/get/put
round-trip is exercised without a container or live AWS — the same style as
``broker/tests/test_dynamo_stores.py``. They prove a restarted broker continues one
contiguous, ``verify_chain``-valid tape (no fork, no gap, no duplicate seq) and that
a resumed sink's first append targets a brand-new key (never an overwrite).

moto/boto3 are guarded with ``importorskip`` so the suite still imports when the
``[dev]`` extra is absent.
"""

from __future__ import annotations

import os

import pytest

# moto needs credentials + a region present even though it never talks to AWS.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

pytest.importorskip("moto", reason="moto is required for the S3 audit-sink resume tests")
boto3 = pytest.importorskip("boto3", reason="boto3 is required for the S3 audit-sink resume tests")

from botocore.exceptions import ClientError  # noqa: E402
from moto import mock_aws  # noqa: E402

from safe_agents.broker.audit import (  # noqa: E402
    GENESIS_PREV_HASH,
    S3ObjectLockSink,
    emit,
    verify_chain,
)
from safe_agents.broker.schemas import AuditRecord, Envelope, compute_envelope_hash  # noqa: E402
from safe_agents.broker.schemas.common import Principal  # noqa: E402

REGION = "us-east-1"
BUCKET = "safe-agents-audit-test"
PREFIX = "audit/"

_PRINCIPAL = Principal(agentId="agent-1", skill="email", user="alice", tier="B")
# A real envelope content-hash to stamp into the emitted records (the value is
# irrelevant to chain verification here — this just avoids a placeholder literal).
_ENVELOPE_HASH = compute_envelope_hash(Envelope(polarity="abstain"))


@pytest.fixture
def bucket():
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET)
        yield BUCKET


def _s3():
    return boto3.client("s3", region_name=REGION)


def _emit(sink: S3ObjectLockSink, i: int) -> AuditRecord:
    """Emit one real, hash-chained record through the sink (reads next_seq/last_hash
    from the sink and appends — so the chain links exactly as production does)."""
    return emit(
        sink,
        principal=_PRINCIPAL,
        tool="email",
        op="send",
        args={"n": i},
        decision="allow",
        outcome="executed",
        envelope_hash=_ENVELOPE_HASH,
    )


def _read_all(prefix: str = PREFIX) -> list[AuditRecord]:
    """Read every record object under ``prefix`` from S3, parsed and ordered by seq.

    This is the reader's job (a separate identity in production); the sink itself is
    write-only. Used to verify_chain over the full durable tape.
    """
    s3 = _s3()
    records: list[AuditRecord] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
        for obj in page.get("Contents", ()):
            body = s3.get_object(Bucket=BUCKET, Key=obj["Key"])["Body"].read()
            records.append(AuditRecord.model_validate_json(body))
    records.sort(key=lambda r: r.seq)
    return records


# ---------------------------------------------------------------------------
# Fresh bucket → fresh chain.
# ---------------------------------------------------------------------------


def test_fresh_bucket_resumes_at_genesis(bucket):
    """No objects under the prefix → resume starts a fresh chain at seq=0 / GENESIS."""
    sink = S3ObjectLockSink.resuming(BUCKET, key_prefix=PREFIX)
    assert sink.next_seq == 0
    assert sink.last_hash == GENESIS_PREV_HASH


def test_fresh_prefix_ignores_objects_under_other_prefixes(bucket):
    """A populated but UNRELATED prefix must not leak into another prefix's resume."""
    seed = S3ObjectLockSink(BUCKET, key_prefix="other/")
    _emit(seed, 0)
    _emit(seed, 1)

    sink = S3ObjectLockSink.resuming(BUCKET, key_prefix=PREFIX)
    assert sink.next_seq == 0
    assert sink.last_hash == GENESIS_PREV_HASH


# ---------------------------------------------------------------------------
# Restart continues one contiguous, verify_chain-valid tape.
# ---------------------------------------------------------------------------


def test_restart_continues_contiguous_chain(bucket):
    """Append records, "restart" via resume, append more → the FULL combined tape is
    one intact chain (contiguous seq, correct linkage, no fork/gap/dup)."""
    sink1 = S3ObjectLockSink(BUCKET, key_prefix=PREFIX)
    first = [_emit(sink1, i) for i in range(3)]  # seqs 0,1,2

    # Restart: a new process constructs the sink via the resume path.
    sink2 = S3ObjectLockSink.resuming(BUCKET, key_prefix=PREFIX)
    assert sink2.next_seq == 3  # maxseq(2) + 1 — contiguous, no collision
    assert sink2.last_hash == first[-1].hash  # chain head recovered

    second = [_emit(sink2, i) for i in range(3, 6)]  # seqs 3,4,5

    all_records = _read_all()
    assert [r.seq for r in all_records] == [0, 1, 2, 3, 4, 5]  # no gap, no dup
    # The seam links: record 3's prevHash is record 2's hash (chain did not fork).
    assert second[0].prevHash == first[-1].hash
    # verify_chain over the WHOLE combined set — the load-bearing assertion.
    verify_chain(all_records)


def test_double_restart_still_one_chain(bucket):
    """Two restarts in a row keep one chain — resume is idempotent w.r.t. the tape."""
    s1 = S3ObjectLockSink(BUCKET, key_prefix=PREFIX)
    _emit(s1, 0)

    s2 = S3ObjectLockSink.resuming(BUCKET, key_prefix=PREFIX)
    _emit(s2, 1)

    s3 = S3ObjectLockSink.resuming(BUCKET, key_prefix=PREFIX)
    assert s3.next_seq == 2
    _emit(s3, 2)

    records = _read_all()
    assert [r.seq for r in records] == [0, 1, 2]
    verify_chain(records)


# ---------------------------------------------------------------------------
# Max-seq is parsed from key NAMES, not derived from list order.
# ---------------------------------------------------------------------------


def test_max_seq_computed_from_key_names_not_list_order(bucket):
    """Seed record objects in scrambled write order under a prefix; resume must still
    recover the numeric MAX seq (and its record's hash) by parsing the key names."""
    # Build a real 5-record chain to get valid, linked bodies.
    builder = S3ObjectLockSink(BUCKET, key_prefix=PREFIX)
    chain = [_emit(builder, i) for i in range(5)]  # seqs 0..4

    # Re-seed those exact record bodies into a fresh prefix in a deliberately
    # non-monotonic write order — a resume that took "the last written" or trusted
    # anything but the parsed key max would get the wrong head.
    scrambled_prefix = "scrambled/"
    s3 = _s3()
    for i in (2, 4, 0, 3, 1):
        rec = chain[i]
        s3.put_object(
            Bucket=BUCKET,
            Key=f"{scrambled_prefix}{rec.seq:010d}.json",
            Body=rec.model_dump_json().encode(),
        )

    sink = S3ObjectLockSink.resuming(BUCKET, key_prefix=scrambled_prefix)
    assert sink.next_seq == 5  # max parsed seq (4) + 1, regardless of write order
    assert sink.last_hash == chain[4].hash


def test_resume_ignores_non_record_objects_under_prefix(bucket):
    """A stray non-record object under the prefix must not perturb the recovered seq."""
    sink1 = S3ObjectLockSink(BUCKET, key_prefix=PREFIX)
    records = [_emit(sink1, i) for i in range(3)]

    # A stray object under the same prefix (defensive — the writing role only ever
    # PutObjects record keys, but resume must not choke on or be skewed by this).
    _s3().put_object(Bucket=BUCKET, Key=f"{PREFIX}README.txt", Body=b"not a record")

    sink2 = S3ObjectLockSink.resuming(BUCKET, key_prefix=PREFIX)
    assert sink2.next_seq == 3
    assert sink2.last_hash == records[-1].hash


# ---------------------------------------------------------------------------
# No overwriting PutObject — the resumed sink's first append is a brand-new key.
# (moto may not enforce Object Lock, so assert the sink never TARGETS an existing seq.)
# ---------------------------------------------------------------------------


def test_resumed_first_append_targets_new_key_no_overwrite(bucket):
    """A resumed sink's first append must be maxseq+1 — a key that did not exist —
    so it never issues an overwriting PutObject that Object Lock would reject."""
    sink1 = S3ObjectLockSink(BUCKET, key_prefix=PREFIX)
    for i in range(3):
        _emit(sink1, i)

    s3 = _s3()
    before = {
        obj["Key"]: s3.get_object(Bucket=BUCKET, Key=obj["Key"])["Body"].read()
        for obj in s3.list_objects_v2(Bucket=BUCKET, Prefix=PREFIX).get("Contents", ())
    }

    sink2 = S3ObjectLockSink.resuming(BUCKET, key_prefix=PREFIX)
    next_key = f"{PREFIX}{sink2.next_seq:010d}.json"
    assert sink2.next_seq == 3

    # The key the next append will write does NOT already exist — no overwrite.
    with pytest.raises(ClientError) as exc_info:
        s3.get_object(Bucket=BUCKET, Key=next_key)
    assert exc_info.value.response["Error"]["Code"] in ("NoSuchKey", "404")

    _emit(sink2, 3)

    # Every pre-existing object is byte-for-byte unchanged (nothing was overwritten).
    for key, body in before.items():
        assert s3.get_object(Bucket=BUCKET, Key=key)["Body"].read() == body
    # The new key now exists.
    assert s3.get_object(Bucket=BUCKET, Key=next_key)["Body"].read()


def test_append_rejects_stale_seq(bucket):
    """The sink refuses a record whose seq is not the expected next — defence against
    ever re-writing an already-committed seq (the append-side of the no-overwrite
    guarantee)."""
    sink = S3ObjectLockSink.resuming(BUCKET, key_prefix=PREFIX)
    good = _emit(sink, 0)  # seq 0, advances next_seq to 1

    stale = good.model_copy(update={"seq": 0})
    with pytest.raises(ValueError, match="seq mismatch"):
        sink.append(stale)
