"""moto-backed tests for LedgerConnector — the ledger.append durable sink (sa#131).

Unlike test_telegram_connector.py (live API, skipped without credentials), the
ledger sink is S3, so the REAL connector code runs against **moto** (``mock_aws``)
in CI — the same style as test_s3_sink_resume.py. moto 5.x enforces
``IfNoneMatch="*"`` conditional puts (verified below by the no-overwrite tests),
so the append-only invariant is exercised for real, not stubbed.

Coverage:
  - happy-path brief append + ledger_delta append (run_id and logical_date keys)
  - unknown op / bad kind / bad logical_date / bad key segments rejected
  - no-overwrite: a key collision retries at a content-hash-suffixed key; a
    byte-identical re-append is reported deduplicated with NO new object
  - non-redirectable target: bucket/prefix/key smuggled into args are ignored —
    the destination comes only from the broker-injected credential
  - full broker round-trip: registry -> decide(allow) -> doer -> durable object
    -> hash-chained AuditRecord (the CI-runnable analog of telegram's live test)

moto/boto3 are guarded with ``importorskip`` so the suite still imports when the
``[dev]`` extra is absent.
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

pytest.importorskip("moto", reason="moto is required for the ledger-connector tests")
boto3 = pytest.importorskip("boto3", reason="boto3 is required for the ledger-connector tests")

from moto import mock_aws  # noqa: E402

from safe_agents.broker.approval import InMemoryIntentStore  # noqa: E402
from safe_agents.broker.audit import InMemorySink, verify_chain  # noqa: E402
from safe_agents.broker.enforcement import InMemoryStore  # noqa: E402
from safe_agents.broker.manifest import CATALOG_TABLE  # noqa: E402
from safe_agents.broker.runtime import (  # noqa: E402
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
)
from safe_agents.broker.taint import build_trust_map  # noqa: E402
from safe_agents.broker.tests.scaffold import (  # noqa: E402
    ENVELOPE_HASH,
    PRINCIPAL,
    make_grant,
    make_pip,
)
from safe_agents.connectors import LedgerConnector  # noqa: E402

REGION = "us-east-1"
BUCKET = "safe-agents-ledger-test"
DECOY_BUCKET = "attacker-chosen-bucket"
PREFIX = "ledger/"

# The broker-injected credential: the ONLY source of the destination.
CREDENTIAL = json.dumps({"bucket": BUCKET, "prefix": PREFIX})


@pytest.fixture
def buckets():
    """The credential's bucket plus a decoy the connector must never write to."""
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET)
        s3.create_bucket(Bucket=DECOY_BUCKET)
        yield s3


def _keys(s3, bucket: str) -> list[str]:
    page = s3.list_objects_v2(Bucket=bucket)
    return sorted(obj["Key"] for obj in page.get("Contents", ()))


def _body(s3, key: str) -> str:
    return s3.get_object(Bucket=BUCKET, Key=key)["Body"].read().decode()


def _append(**overrides):
    args = {
        "kind": "brief",
        "logical_date": "2026-07-02",
        "content": "# Daily brief\n\nsignals-only test brief.",
        "agent": "example-agent",
    }
    args.update(overrides)
    return LedgerConnector().execute("ledger", "append", args, CREDENTIAL)


# ---------------------------------------------------------------------------
# Direct connector tests
# ---------------------------------------------------------------------------


def test_brief_append_happy_path(buckets):
    """A brief lands at <prefix><agent>/briefs/<logical_date>.md, byte-exact."""
    result = _append()
    assert result == {"key": "ledger/example-agent/briefs/2026-07-02.md", "deduplicated": False}
    assert _body(buckets, result["key"]) == "# Daily brief\n\nsignals-only test brief."


def test_digest_append_happy_path(buckets):
    """A digest lands at <prefix><agent>/digests/<logical_date>.md — its own subdir,
    so a same-day brief and digest never collide into each other's hash-fallback keys."""
    result = _append(kind="digest", content="Top 3: hold.")
    assert result == {"key": "ledger/example-agent/digests/2026-07-02.md", "deduplicated": False}
    assert _body(buckets, result["key"]) == "Top 3: hold."


def test_ledger_delta_append_uses_run_id(buckets):
    """A ledger delta keys by run_id — several runs per logical_date stay distinct."""
    result = _append(kind="ledger_delta", run_id="run-20260702T1200Z", content='{"p": 1}\n')
    assert result == {
        "key": "ledger/example-agent/deltas/run-20260702T1200Z.jsonl",
        "deduplicated": False,
    }
    assert _body(buckets, result["key"]) == '{"p": 1}\n'


def test_ledger_delta_falls_back_to_logical_date(buckets):
    """Without a run_id the delta keys by logical_date."""
    result = _append(kind="ledger_delta", content='{"p": 2}\n')
    assert result["key"] == "ledger/example-agent/deltas/2026-07-02.jsonl"


def test_rejects_unknown_op(buckets):
    """Structural guard: the connector itself has no path but 'append'."""
    with pytest.raises(ValueError, match="'append'"):
        LedgerConnector().execute("ledger", "delete", {"kind": "brief"}, CREDENTIAL)


@pytest.mark.parametrize(
    "description, overrides, expected_fragment",
    [
        ("unknown_kind", {"kind": "outcome"}, "kind"),
        ("missing_kind", {"kind": None}, "kind"),
        ("bad_date_format", {"logical_date": "07/02/2026"}, "logical_date"),
        ("date_not_a_string", {"logical_date": 20260702}, "logical_date"),
        ("empty_content", {"content": ""}, "content"),
        ("content_not_a_string", {"content": {"body": "x"}}, "content"),
        # Caller-supplied key segments must not traverse out of the credential's
        # prefix or hide keys — no "/", no leading ".".
        ("agent_traversal", {"agent": "../other-agent"}, "agent"),
        ("agent_slash", {"agent": "a/b"}, "agent"),
        ("run_id_traversal", {"kind": "ledger_delta", "run_id": "../../x"}, "run_id"),
    ],
)
def test_malformed_args_rejected(buckets, description, overrides, expected_fragment):
    with pytest.raises(ValueError, match=expected_fragment):
        _append(**overrides)
    # Fail-closed: nothing was written on any rejection path.
    assert _keys(buckets, BUCKET) == []


def test_no_overwrite_hash_suffix(buckets):
    """A second, DIFFERENT brief for the same logical_date never overwrites the
    first — it lands at a content-hash-suffixed key and both stay durable."""
    first = _append(content="original brief")
    second = _append(content="revised brief")

    assert second["key"] != first["key"]
    assert second["key"].startswith("ledger/example-agent/briefs/2026-07-02.")
    assert second["key"].endswith(".md")
    assert second["deduplicated"] is False
    # Append-only held: both contents durable, byte-exact.
    assert _body(buckets, first["key"]) == "original brief"
    assert _body(buckets, second["key"]) == "revised brief"


def test_byte_identical_reappend_is_deduplicated(buckets):
    """Once content sits at its hash-suffixed key, re-appending the SAME bytes is
    an idempotent no-op (the suffix is derived from the content)."""
    _append(content="same brief")           # -> natural key
    hashed = _append(content="same brief")  # -> hash-suffixed key
    third = _append(content="same brief")   # -> already durable

    assert third == {"key": hashed["key"], "deduplicated": True}
    assert len(_keys(buckets, BUCKET)) == 2  # no third object appeared


def test_destination_never_comes_from_args(buckets):
    """The non-redirectable-target invariant: bucket/prefix/key smuggled into args
    are simply never read — the write lands under the CREDENTIAL's destination and
    the attacker-chosen bucket stays empty."""
    result = _append(
        bucket=DECOY_BUCKET,
        prefix="exfil/",
        key="exfil/steal.md",
    )
    assert result["key"] == "ledger/example-agent/briefs/2026-07-02.md"
    assert _keys(buckets, BUCKET) == ["ledger/example-agent/briefs/2026-07-02.md"]
    assert _keys(buckets, DECOY_BUCKET) == []


# ---------------------------------------------------------------------------
# Full broker round-trip (CI-runnable analog of telegram's live integration test)
# ---------------------------------------------------------------------------


def test_ledger_append_broker_round_trip(buckets):
    """Full integration: registry -> decide(allow) -> doer executes LedgerConnector
    with the broker-injected credential -> the brief is durable in S3 -> audit."""
    sink = InMemorySink()
    doer = Doer(
        connectors={"ledger": LedgerConnector()},
        secrets=FakeSecretsProvider({"ledger": CREDENTIAL}),
    )
    runtime = BrokerRuntime(
        principal=PRINCIPAL,
        grants=[make_grant("ledger.append")],
        optable=CATALOG_TABLE,
        doer=doer,
        pip=make_pip(),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
    )

    registry = runtime.served_registry()
    assert [(t.tool, t.op) for t in registry] == [("ledger", "append")]

    response = runtime.handle_request(
        AgentRequest(
            tool="ledger",
            op="append",
            args={
                "kind": "brief",
                "logical_date": "2026-07-02",
                "content": "# Brief via broker\n",
                "agent": "example-agent",
            },
            idempotency_key="test:ledger-append-1",
        )
    )

    assert response.decision_kind == "allow"
    assert response.result == {
        "key": "ledger/example-agent/briefs/2026-07-02.md",
        "deduplicated": False,
    }
    assert _body(buckets, response.result["key"]) == "# Brief via broker\n"

    records = sink.records()
    assert len(records) == 1
    assert (records[0].tool, records[0].op) == ("ledger", "append")
    assert records[0].decision == "allow"
    assert records[0].outcome == "executed"
    verify_chain(records)
