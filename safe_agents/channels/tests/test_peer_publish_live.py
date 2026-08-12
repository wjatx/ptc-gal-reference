"""sa#156 — live A2A smoke: the peer.publish SENDER path against the deployed airlock.

Opt-in: set PEER_PUBLISH_LIVE_SMOKE=1 with AWS credentials for the development
account. Reuses the deployed `webhook-peer` airlock (already wired on the dev
floor to admit `peer:example` → `example-agent`) and the same CloudFormation-export
resolution as `test_airlock_live.py`, so it needs no redeploy and no per-run wiring.

What this proves that the inbound smoke does not: the OUTBOUND half. A signal
built by `stamp_outbound` (broker-stamped provenance) and transported by the
reference `PeerConnector` (pure transport) produces an envelope the LIVE airlock
verifies, maps, and accepts as a peer sender — the real binding of the #156
sender path.

Observability note (2026-07-09): since the drain worker went live (sa#155) it is
the accepted queue's ESM consumer, so a test can no longer read the queue — the
Lambda wins the race. The airlock's structured `channel_accepted` log event
(keyed by event_id) is the observable that proves accept+enqueue. Full drain
observation is out of scope here anyway: the live drain is wired with missileer's
receiver (principal `missileer-watch`), so it correctly terminal-drops an
`example-agent` envelope — a cross-consumer wiring fact, not a #156 concern. The
taint derivation and the one-way rule are exhaustively proven offline
(`test_publish.py`); live, a tainted publish is likewise accepted (taint is
derived at ingestion, never a drop reason).
"""

import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from safe_agents.channels.publish import stamp_outbound

# Reuse the live resolver from the inbound smoke (importing the module is harmless
# — its pytestmark only skips ITS OWN tests).
from safe_agents.channels.tests.test_airlock_live import resolve_live

from safe_agents.connectors import PeerConnector

pytestmark = pytest.mark.skipif(
    not os.environ.get("PEER_PUBLISH_LIVE_SMOKE"),
    reason="PEER_PUBLISH_LIVE_SMOKE not set — opt-in outbound smoke against the deployed airlock",
)

_ENV = os.environ.get("AIRLOCK_ENV", "development")
_AIRLOCK_LOG_GROUP = f"/safe-agents/{_ENV}/channels-airlock"

# The receiver the dev floor already admits (examples/webhook-peer).
_PEER_IDENTITY = "peer:example"
_TARGET_PRINCIPAL = "example-agent"
_TOKEN_HEADER = "x-airlock-token"


@pytest.fixture(scope="module")
def live():
    return resolve_live()


@pytest.fixture(scope="module")
def logs():
    import boto3

    return boto3.client("logs")


def _credential(live) -> str:
    """The broker-held peer descriptor the connector transports with."""
    url = live.url.rstrip("/")
    if not url.endswith("/inbound"):
        url += "/inbound"
    return json.dumps({"url": url, "token_header": _TOKEN_HEADER, "token": live.token})


def _await_accept(logs, event_id: str, timeout: float) -> bool:
    """Poll the airlock log group for a `channel_accepted` event with `event_id`."""
    start = int((time.time() - 120) * 1000)
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = logs.filter_log_events(
            logGroupName=_AIRLOCK_LOG_GROUP,
            startTime=start,
            filterPattern='"channel_accepted"',
        )
        for event in resp.get("events", []):
            if event_id in event["message"]:
                return True
        time.sleep(3)
    return False


def _publish(live, *, event_id: str, turn_tainted: bool) -> dict:
    """Build via stamp_outbound, transport via the reference PeerConnector."""
    now = datetime.now(timezone.utc)
    envelope = stamp_outbound(
        zone="email-agent",
        agent_identity="email-agent",
        channel_type="webhook",           # must match the receiver adapter's type
        channel_identity=_PEER_IDENTITY,  # the identity the live trust map admits
        turn_tainted=turn_tainted,
        event_id=event_id,
        principal=_TARGET_PRINCIPAL,
        payload={"signal": "live-smoke", "tainted": turn_tainted},
        ts=now.isoformat(),
        expiry=(now + timedelta(minutes=60)).isoformat(),
    )
    return PeerConnector().execute(
        "peer", "publish", {"envelope": envelope.model_dump()}, _credential(live)
    )


def test_peer_publish_is_accepted_by_the_live_airlock(live, logs):
    # The SENDER path: stamp_outbound + PeerConnector → the live airlock verifies,
    # maps, and accepts as a peer sender (channel_accepted, keyed by event_id).
    accepted_id = f"pub-{uuid.uuid4()}"
    result = _publish(live, event_id=accepted_id, turn_tainted=False)
    assert result["status"] == "published"
    assert result["event_id"] == accepted_id
    assert result["http_status"] == 200

    assert _await_accept(logs, accepted_id, timeout=45), (
        "airlock never logged channel_accepted for the published envelope"
    )


def test_tainted_publish_is_also_accepted(live, logs):
    # A tainted sending turn: stamp_outbound stamps the peer hop `untrusted`. Taint
    # is derived at ingestion, never a drop reason, so the airlock accepts it too —
    # the sender-side gating (tainted publish → require_approval at the SENDER's
    # broker) and the receiver taint derivation are proven offline in test_publish.py.
    tainted_id = f"pub-tainted-{uuid.uuid4()}"
    result = _publish(live, event_id=tainted_id, turn_tainted=True)
    assert result["status"] == "published"

    assert _await_accept(logs, tainted_id, timeout=45), (
        "airlock never logged channel_accepted for the tainted published envelope"
    )
