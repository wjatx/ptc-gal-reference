"""moto-backed tests for tape_cli's S3 source (#42).

The cloud floor writes its tape as one object per record through
S3ObjectLockSink, and until #42 the only reader for it was a library class with no
command in front of it. These tests write records through the REAL sink (under
moto, the style of test_s3_sink_resume.py) and read them back through the command,
so writer and reader cannot drift apart on the key layout.

The honesty tests from test_tape_cli.py carry over with one addition: an S3 tape
is exactly the off-device storage the local caveat points to, so the S3 caveat has
to say that the lock is the bucket's retention and not this check, rather than let
"S3" read as "locked".
"""

from __future__ import annotations

import json
import os

import pytest

# moto needs credentials + a region present even though it never talks to AWS.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

pytest.importorskip("moto", reason="moto is required for the S3 tape_cli tests")
boto3 = pytest.importorskip("boto3", reason="boto3 is required for the S3 tape_cli tests")

from moto import mock_aws  # noqa: E402

from safe_agents.broker.audit import S3ObjectLockSink, emit  # noqa: E402
from safe_agents.broker.auditor import tape_cli  # noqa: E402
from safe_agents.broker.schemas.common import Principal  # noqa: E402

REGION = "us-east-1"
BUCKET = "safe-agents-development-audit"

PRINCIPAL = Principal(agentId="embedded-assistant", skill="research", user="local-developer", tier="C")

BASE_EMIT = dict(
    principal=PRINCIPAL,
    tool="search",
    op="query",
    args={"query": "PLAINTEXT-ARG-VALUE-MUST-NOT-BE-PRINTED"},
    envelope_hash="sha256:envelope",
    decision="allow",
    outcome="executed",
)


def _write_tape(prefix: str = tape_cli.DEFAULT_S3_PREFIX) -> None:
    """An allow then a refusal then an allow, written the way the broker writes them."""
    sink = S3ObjectLockSink.resuming(BUCKET, key_prefix=prefix)
    emit(sink, **BASE_EMIT)
    emit(sink, **{**BASE_EMIT, "tool": "notify", "op": "send", "decision": "deny",
                  "outcome": "denied", "reason": "tool not granted to this principal"})
    emit(sink, **BASE_EMIT)


@pytest.fixture
def bucket():
    with mock_aws():
        boto3.client("s3", region_name=REGION).create_bucket(Bucket=BUCKET)
        yield BUCKET


@pytest.fixture
def tape(bucket):
    _write_tape()
    return bucket


def test_reads_the_records_the_sink_wrote(tape, capsys):
    assert tape_cli.main(["--s3-bucket", tape]) == tape_cli.EXIT_OK

    out = capsys.readouterr().out
    assert f"s3://{tape}/audit/" in out
    assert "3 record(s)" in out
    assert "notify.send  deny/denied" in out
    assert "why  tool not granted to this principal" in out
    assert "PLAINTEXT-ARG-VALUE-MUST-NOT-BE-PRINTED" not in out


def test_verify_reports_consistency_with_the_s3_caveat(tape, capsys):
    assert tape_cli.main(["--s3-bucket", tape, "--verify"]) == tape_cli.EXIT_OK

    out = capsys.readouterr().out
    assert "CHAIN CONSISTENT — 3 records, seq 0..2" in out
    assert "NOT tamper-evidence" in out
    # The lock is the bucket's, and on development there is none.
    assert "does not inspect" in out
    assert "development sets none" in out
    for overclaim in ("untampered", "tamper-proof", "cannot be altered", "immutable", "compliance"):
        assert overclaim not in out.lower()


def test_json_output_names_the_source_and_carries_the_caveat(tape, capsys):
    assert tape_cli.main(["--s3-bucket", tape, "--verify", "--json"]) == tape_cli.EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload["s3"] == f"s3://{tape}/audit/"
    assert "path" not in payload
    assert payload["count"] == 3
    assert payload["verify"]["intact"] is True
    assert payload["verify"]["proves"] == tape_cli.S3_CHAIN_CAVEAT


def test_a_deleted_record_breaks_the_chain_where_the_gap_is(tape, capsys):
    # Development's bucket sets no default retention, so this delete succeeds on the
    # real floor too; that is the case the S3 caveat exists to name.
    boto3.client("s3", region_name=REGION).delete_object(Bucket=tape, Key="audit/0000000001.json")

    assert tape_cli.main(["--s3-bucket", tape, "--verify"]) == tape_cli.EXIT_BROKEN
    out = capsys.readouterr().out
    assert "CHAIN BROKEN at seq 1" in out
    assert "NOT tamper-evidence" in out


def test_the_prefix_selects_the_tape(bucket, capsys):
    _write_tape(prefix="other/")

    assert tape_cli.main(["--s3-bucket", bucket]) == tape_cli.EXIT_OK
    assert "no records yet" in capsys.readouterr().out

    assert tape_cli.main(["--s3-bucket", bucket, "--prefix", "other/", "--verify"]) == tape_cli.EXIT_OK
    assert "CHAIN CONSISTENT — 3 records" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ("missing-bucket", "could not be read"),
        ("foreign-object", "holds an object that is not a record"),
    ],
)
def test_an_unreadable_source_refuses_rather_than_verdicting(bucket, setup, message, capsys):
    target = bucket
    if setup == "missing-bucket":
        target = "no-such-audit-bucket"
    else:
        boto3.client("s3", region_name=REGION).put_object(
            Bucket=bucket, Key="audit/0000000000.json", Body=b'{"not": "a record"}'
        )

    assert tape_cli.main(["--s3-bucket", target, "--verify"]) == tape_cli.EXIT_REFUSED
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--path", "audit.jsonl", "--s3-bucket", BUCKET],
        ["--path", "audit.jsonl", "--prefix", "other/"],
    ],
)
def test_exactly_one_source_is_a_usage_rule(argv):
    with pytest.raises(SystemExit) as exc:
        tape_cli.main(argv)
    assert exc.value.code == 2
