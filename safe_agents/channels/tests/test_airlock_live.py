"""sa#152 — live smoke against the deployed development airlock.

Opt-in: set AIRLOCK_LIVE_SMOKE=1 with AWS credentials for the development
account (the same env-gated idiom as the live connector tests). Endpoint URL,
queue URL, and secret ARN all resolve from the CloudFormation exports the
Channels stack publishes, so the run needs no per-run wiring.

Drives the deployed endpoint through the gate matrix — bad token, unmapped
sender, expired envelope, the valid signal, and its replay — then proves
acceptance and end-to-end delivery from each seam's OWN output:

sa#166: since the drain worker went live, the accepted queue is consumed by
the webhook-peer drain's ESM — a test process can no longer win the race to
read it. The airlock's accept observable is now the structured
`channel_accepted` CloudWatch log event (PII-safe: event/identity_digest/
event_id only, no stamped EventTrigger recoverable live), and the end-to-end
proof is the webhook-peer receiver's `inbound_observed` ledger record landing
in the ledger bucket — the same pattern `test_peer_publish_live.py` uses for
the outbound half.
"""

import hashlib
import json
import os
import time
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AIRLOCK_LIVE_SMOKE"),
    reason="AIRLOCK_LIVE_SMOKE not set — opt-in smoke against the deployed development airlock",
)

_ENV = os.environ.get("AIRLOCK_ENV", "development")
_AIRLOCK_LOG_GROUP = f"/safe-agents/{_ENV}/channels-airlock"

# The example consumer wired on the dev floor (examples/webhook-peer).
_PEER = "peer:example"
_PRINCIPAL = "example-agent"
_TOKEN_HEADER = "x-airlock-token"


def resolve_live() -> SimpleNamespace:
    """Resolve the deployed wiring from CloudFormation exports (shared with the
    screened + peer-publish variants)."""
    import boto3

    cfn = boto3.client("cloudformation")
    exports: dict[str, str] = {}
    for page in cfn.get_paginator("list_exports").paginate():
        for exp in page["Exports"]:
            exports[exp["Name"]] = exp["Value"]

    def export(key: str) -> str:
        name = f"safe-agents-{_ENV}-{key}"
        assert name in exports, f"missing CloudFormation export {name} — is the stack deployed?"
        return exports[name]

    secret_arn = export("channels-webhook-secret-arn")
    token = boto3.client("secretsmanager").get_secret_value(SecretId=secret_arn)["SecretString"]
    return SimpleNamespace(
        url=export("airlock-url"),
        queue=export("channel-accepted-queue-url"),
        audit_bucket=export("audit-bucket-name"),
        ledger_bucket=export("ledger-bucket-name"),
        token=token,
        sqs=boto3.client("sqs"),
        s3=boto3.client("s3"),
        logs=boto3.client("logs"),
    )


@pytest.fixture(scope="module")
def live():
    return resolve_live()


def _post(live, body: str, token: str) -> dict:
    url = live.url.rstrip("/")
    if not url.endswith("/inbound"):
        url += "/inbound"
    req = urllib.request.Request(
        url,
        data=body.encode(),
        method="POST",
        headers={"content-type": "application/json", _TOKEN_HEADER: token},
    )
    # Generous timeout: the first hit pays the container cold start.
    with urllib.request.urlopen(req, timeout=30) as resp:
        return {"status": resp.status, "body": json.loads(resp.read().decode())}


def _envelope(
    event_id: str,
    *,
    identity: str = _PEER,
    expiry_minutes: int = 60,
    payload: dict | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    return json.dumps(
        {
            "event_id": event_id,
            "principal": _PRINCIPAL,
            "sender": {"channel_type": "webhook", "channel_identity": identity, "evidence": []},
            "payload": payload if payload is not None else {"msg": "live smoke"},
            "provenance": [
                {
                    "zone": "peer",
                    "source": _PEER,
                    "evidence": [],
                    "label": "trusted",
                    "ts": now.isoformat(),
                }
            ],
            "ts": now.isoformat(),
            "expiry": (now + timedelta(minutes=expiry_minutes)).isoformat(),
        }
    )


def _await_accept(logs, log_group: str, event_id: str, timeout: float) -> bool:
    """Poll `log_group` for a `channel_accepted` event keyed by event_id."""
    start = int((time.time() - 120) * 1000)
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = logs.filter_log_events(
            logGroupName=log_group,
            startTime=start,
            filterPattern='"channel_accepted"',
        )
        for event in resp.get("events", []):
            if event_id in event["message"]:
                return True
        time.sleep(3)
    return False


def _await_ledger(s3, bucket: str, key_prefix: str, timeout: float) -> list[str]:
    """Poll list_objects_v2 for `key_prefix`, returning the matching keys."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=key_prefix)
        keys = [o["Key"] for o in resp.get("Contents", [])]
        if keys:
            return keys
        time.sleep(3)
    return []


def _ledger_prefix(event_id: str) -> str:
    digest12 = hashlib.sha256(f"{_PEER}\n{event_id}".encode()).hexdigest()[:12]
    return f"webhook-peer/{_PRINCIPAL}/deltas/evt-{digest12}"


def test_deployed_airlock_gate_matrix(live):
    accepted_id = f"evt-{uuid.uuid4()}"
    accepted_body = _envelope(accepted_id)

    dropped_ids = []

    # Gate 1 — wrong token: silently acked, never enqueued.
    wrong_token_id = f"evt-{uuid.uuid4()}"
    resp = _post(live, _envelope(wrong_token_id), token="not-the-token")
    assert resp == {"status": 200, "body": {"ok": True}}
    dropped_ids.append(wrong_token_id)

    # Gate 5 — unmapped sender: same contentless ack.
    unmapped_id = f"evt-{uuid.uuid4()}"
    resp = _post(live, _envelope(unmapped_id, identity="peer:stranger"), live.token)
    assert resp["status"] == 200
    dropped_ids.append(unmapped_id)

    # Gate 4 — expired envelope from the mapped sender.
    expired_id = f"evt-{uuid.uuid4()}"
    resp = _post(live, _envelope(expired_id, expiry_minutes=-5), live.token)
    assert resp["status"] == 200
    dropped_ids.append(expired_id)

    # Gates 1-9 — the valid signal traverses and is accepted.
    resp = _post(live, accepted_body, live.token)
    assert resp == {"status": 200, "body": {"ok": True}}
    assert _await_accept(live.logs, _AIRLOCK_LOG_GROUP, accepted_id, timeout=30), (
        "accepted envelope never logged channel_accepted"
    )

    # None of the drops surface as accepted.
    for dropped_id in dropped_ids:
        assert not _await_accept(live.logs, _AIRLOCK_LOG_GROUP, dropped_id, timeout=15), (
            f"dropped envelope {dropped_id} unexpectedly logged channel_accepted"
        )

    # Gate 6 — the replay is a silent no-op.
    resp = _post(live, accepted_body, live.token)
    assert resp["status"] == 200

    # The end-to-end win: the accepted envelope's inbound_observed record lands
    # exactly once in the ledger bucket, under the webhook-peer receiver's prefix.
    prefix = _ledger_prefix(accepted_id)
    keys = _await_ledger(live.s3, live.ledger_bucket, prefix, timeout=60)
    assert len(keys) == 1, f"expected exactly one ledger object at {prefix}, got {keys}"

    body = live.s3.get_object(Bucket=live.ledger_bucket, Key=keys[0])["Body"].read().decode()
    record = json.loads(body)
    assert record["event"] == "inbound_observed"
    assert record["event_id"] == accepted_id
    assert record["identity_digest"].startswith("sha256:")  # never the raw identity
    assert "msg" not in body  # the payload content never reaches the ledger

    # The replay stays a no-op: still exactly one object at the prefix.
    keys = live.s3.list_objects_v2(Bucket=live.ledger_bucket, Prefix=prefix).get("Contents", [])
    assert len(keys) == 1, f"replay must not append a second ledger object, got {keys}"
