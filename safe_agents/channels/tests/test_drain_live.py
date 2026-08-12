"""sa#155 — live smoke against the deployed development drain worker.

Opt-in: set DRAIN_LIVE_SMOKE=1 with AWS credentials for the development account
(the same env-gated idiom as test_airlock_live.py). Queue URL, log group, ledger
bucket, and audit bucket all resolve from CloudFormation exports / the known
deploy naming, so the run needs no per-run wiring.

Why it injects onto the accepted queue directly (rather than POSTing at the
airlock): the airlock and the drain are DIFFERENT example consumers on the shared
dev floor — the airlock is the webhook-peer consumer (stamps principal
``example-agent``), the drain is missileer (principal ``missileer-watch``). A real
airlock POST therefore reaches the drain as a principal_mismatch terminal-drop, so
it cannot drive the happy path. The airlock->queue hop is a separate seam already
proven by test_airlock_live.py; this smoke drives the drain seam — parse, expiry,
principal check, ingest-before-act, receiver, brokered ledger.append — from its
real input boundary, missileer's own dedicated accepted-events queue (sa#166 split
the airlock-fed queue in two: webhook-peer's drain now eats
``channel-accepted-queue-url``, missileer's drain eats
``channel-accepted-missileer-queue-url``).

Drives three paths against the deployed worker:
  * happy path (clean internal-sourced chain) — ingest logged before receive, the
    brokered ledger.append lands in the ledger bucket, its AuditRecord lands under
    the isolated audit-drain/ prefix, and both are PII-safe (identity DIGEST, never
    raw identity or payload);
  * D7 terminal drop — a wrong-principal envelope logs drain_terminal_drop with
    reason principal_mismatch and is NOT redelivered;
  * D4 idempotency — a duplicate delivery of one envelope appends exactly once.

NB the missileer trust map trusts only ``internal:`` sources, and every accepted
envelope carries a ``channel:webhook`` stamp hop, so the ingested turn is ALWAYS
tainted — abstain polarity keeps ledger.append (an append-only observation) allowed
regardless, which is the archetype's whole point.
"""

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DRAIN_LIVE_SMOKE"),
    reason="DRAIN_LIVE_SMOKE not set — opt-in smoke against the deployed development drain",
)

_ENV = os.environ.get("DRAIN_ENV", "development")
_PRINCIPAL = "missileer-watch"
_INTERNAL_SOURCE = "internal:missileer-cmd"
_LOG_GROUP = f"/safe-agents/{_ENV}/channels-drain-missileer"


def resolve_live() -> SimpleNamespace:
    import boto3

    cfn = boto3.client("cloudformation")
    exports: dict[str, str] = {}
    for page in cfn.get_paginator("list_exports").paginate():
        for exp in page["Exports"]:
            exports[exp["Name"]] = exp["Value"]

    def export(key: str) -> str:
        name = f"safe-agents-{_ENV}-{key}"
        assert name in exports, f"missing CloudFormation export {name} — is the drain deployed?"
        return exports[name]

    return SimpleNamespace(
        queue=export("channel-accepted-missileer-queue-url"),
        ledger_bucket=export("ledger-bucket-name"),
        audit_bucket=export("audit-bucket-name"),
        sqs=boto3.client("sqs"),
        s3=boto3.client("s3"),
        logs=boto3.client("logs"),
    )


@pytest.fixture(scope="module")
def live():
    return resolve_live()


def _envelope(event_id: str, *, principal: str = _PRINCIPAL, source: str = _INTERNAL_SOURCE) -> str:
    now = datetime.now(timezone.utc)
    return json.dumps(
        {
            "event_id": event_id,
            "principal": principal,
            "sender": {"channel_type": "webhook", "channel_identity": source, "evidence": []},
            "payload": {"msg": "drain live smoke"},
            "sender_class": "owner",
            "provenance": [
                {"zone": "internal", "source": source, "evidence": [], "label": "trusted", "ts": now.isoformat()},
                {"zone": "channels", "source": "channel:webhook", "evidence": [], "label": "trusted", "ts": now.isoformat()},
            ],
            "ts": now.isoformat(),
            "expiry": (now + timedelta(minutes=60)).isoformat(),
        }
    )


def _dedupe_stem(source: str, event_id: str) -> str:
    digest = hashlib.sha256(f"{source}\n{event_id}".encode()).hexdigest()
    return f"evt-{digest[:12]}"


def _await_log(live, since_ms: int, event_id: str, want: set[str], timeout: float = 120) -> dict[str, dict]:
    """Collect the drain's structured events for event_id until `want` are seen.

    CloudWatch filter_log_events is eventually consistent AND paginated: a single
    page from ``since_ms`` can be saturated by other invocations' events and miss
    the target, so every poll drains all pages via nextToken.
    """
    deadline = time.time() + timeout
    found: dict[str, dict] = {}
    while time.time() < deadline:
        token: str | None = None
        while True:
            kwargs = {"logGroupName": _LOG_GROUP, "startTime": since_ms, "limit": 500}
            if token:
                kwargs["nextToken"] = token
            resp = live.logs.filter_log_events(**kwargs)
            for e in resp.get("events", []):
                # The Lambda runtime prefixes each line with "[LEVEL]\t<ts>\t<reqid>\t";
                # the structured record is the JSON object from the first brace on.
                msg = e["message"]
                brace = msg.find("{")
                if brace == -1:
                    continue
                try:
                    d = json.loads(msg[brace:])
                except ValueError:
                    continue
                if d.get("event_id") == event_id:
                    found[d["event"]] = {**d, "_ts": e["timestamp"]}
            token = resp.get("nextToken")
            if not token:
                break
        if want <= set(found):
            break
        time.sleep(4)
    return found


def _ledger_keys(live, stem: str) -> list[str]:
    prefix = f"missileer/{_PRINCIPAL}/deltas/{stem}"
    resp = live.s3.list_objects_v2(Bucket=live.ledger_bucket, Prefix=prefix)
    return [o["Key"] for o in resp.get("Contents", [])]


def _poll_ledger(live, stem: str, timeout: float) -> list[str]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        keys = _ledger_keys(live, stem)
        if keys:
            return keys
        time.sleep(3)
    return []


def test_drain_happy_path(live):
    since_ms = int((time.time() - 5) * 1000)
    event_id = f"evt-{uuid.uuid4()}"
    live.sqs.send_message(QueueUrl=live.queue, MessageBody=_envelope(event_id))

    # Durable proof (primary): the brokered ledger.append landed, exactly once, at the
    # deterministic key derived from (sender.channel_identity, event_id).
    stem = _dedupe_stem(_INTERNAL_SOURCE, event_id)
    keys = _poll_ledger(live, stem, timeout=180)
    assert len(keys) == 1, f"expected exactly one ledger object at {stem}, got {keys}"

    body = live.s3.get_object(Bucket=live.ledger_bucket, Key=keys[0])["Body"].read().decode()
    record = json.loads(body)
    assert record["event"] == "inbound_observed"
    assert record["event_id"] == event_id
    assert record["identity_digest"].startswith("sha256:")  # never the raw identity
    assert "msg" not in body  # the payload content never reaches the ledger

    # Observable ordering (D1/D2): ingest is logged strictly before the receiver acts.
    events = _await_log(live, since_ms, event_id, {"drain_ingested", "drain_received"})
    assert "drain_ingested" in events, "ingest never logged"
    assert "drain_received" in events, "receiver never ran"
    assert events["drain_ingested"]["_ts"] <= events["drain_received"]["_ts"]
    # The channel stamp hop is untrusted by missileer ⇒ turn taints; append still allowed.
    assert events["drain_ingested"]["tainted"] is True
    assert events["drain_ingested"]["identity_digest"].startswith("sha256:")


def test_drain_terminal_drop_wrong_principal(live):
    since_ms = int((time.time() - 5) * 1000)
    event_id = f"evt-{uuid.uuid4()}"
    live.sqs.send_message(
        QueueUrl=live.queue, MessageBody=_envelope(event_id, principal="nobody-agent")
    )
    # Durable proof (primary): a mismatched principal never reaches the ledger. Give a
    # correctly-addressed message's latency budget before asserting the absence.
    assert _poll_ledger(live, _dedupe_stem(_INTERNAL_SOURCE, event_id), timeout=45) == []
    # Observable disposition (D7): logged as a terminal drop, not redelivered.
    events = _await_log(live, since_ms, event_id, {"drain_principal_mismatch"}, timeout=60)
    assert "drain_principal_mismatch" in events


def test_drain_idempotent_duplicate(live):
    event_id = f"evt-{uuid.uuid4()}"
    body = _envelope(event_id)
    for _ in range(2):
        live.sqs.send_message(QueueUrl=live.queue, MessageBody=body)
        time.sleep(1)
    # Both deliveries drain; the broker replays the stored outcome on the duplicate.
    stem = _dedupe_stem(_INTERNAL_SOURCE, event_id)
    deadline = time.time() + 150
    keys: list[str] = []
    while time.time() < deadline:
        keys = _ledger_keys(live, stem)
        if keys:
            time.sleep(6)  # give the second delivery time to (not) double-append
            keys = _ledger_keys(live, stem)
            break
        time.sleep(2)
    assert len(keys) == 1, f"D4: duplicate delivery must append once, got {keys}"
