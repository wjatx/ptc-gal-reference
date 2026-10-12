"""Clock skew at the channel receivers (PTC-49, #175).

An envelope's `expiry` is stamped under the SENDER's clock. Both receivers that
judge it, the airlock (dispatch gate 4) and the drain worker, apply their OWN
declared bound toward expiring early, never late:

  * `EventTrigger.is_expired` and `dispatch_outcome` apply the bound handed in;
  * the airlock handler hands in `ChannelsManifest.clock_skew_seconds`;
  * the drain hands in its `AgentManifest.clock_skew_seconds`;
  * nothing the envelope carries can set or widen it.

Each test id names the site, so a mutant at any one (bound ignored, bound
applied the wrong way, a symmetric leeway, the bound read from the envelope)
fails a row that says where.
"""

from __future__ import annotations

import datetime
import json

import pytest
from pydantic import ValidationError

import safe_agents.channels.airlock.handler as airlock
import safe_agents.channels.drain.handler as drain
from safe_agents.broker.schemas.clock_skew import MAX_CLOCK_SKEW_SECONDS
from safe_agents.channels.manifest import ChannelsManifest, build_airlock
from safe_agents.channels.tests import test_airlock_handler as ah
from safe_agents.channels.tests import test_dispatch_outcome as do
from safe_agents.channels.tests import test_drain_handler as dh

UTC = datetime.UTC
GAP = datetime.timedelta(seconds=10)
EXPIRY = datetime.datetime.fromisoformat(do._EXPIRY)

# (where, bound in seconds, expired?) — GAP is 10s. "inside" is GAP before the
# expiry, "outside" GAP after it. gate 4 compares strictly (`>`).
_MATRIX = [
    pytest.param("inside", 0, False, id="zero-bound-is-todays-comparison"),
    pytest.param("inside", 30, True, id="bound-expires-the-envelope-early"),
    pytest.param("inside", 5, False, id="a-bound-narrower-than-the-gap-changes-nothing"),
    # Just wider than GAP: only the FULL bound reaches past the expiry, so a
    # site applying part of it (half, say) keeps the envelope alive here.
    pytest.param("inside", 11, True, id="a-bound-just-wider-than-the-gap-expires-it"),
    pytest.param("outside", 30, True, id="no-symmetric-leeway-past-the-expiry"),
    pytest.param("outside", 0, True, id="past-the-expiry-with-no-bound"),
]


def _at(where: str) -> datetime.datetime:
    return EXPIRY - GAP if where == "inside" else EXPIRY + GAP


def _is_expired(at, bound) -> bool:
    return do._envelope().is_expired(at, bound)


def _gate4(at, bound) -> bool:
    drops: list = []
    outcome = do.dispatch_outcome(
        "request",
        adapter=do._Adapter(do._envelope()),
        trust_map=do._trust_map(mapped=True),
        screen=None,
        dedupe_store=set(),
        drops=drops,
        now=at,
        zone=do._ZONE,
        clock_skew=bound,
    )
    expired = [d for d in drops if d.reason == "expired"]
    assert (outcome.envelope is None) == bool(expired), drops
    return bool(expired)


_SITES = [
    pytest.param("EventTrigger.is_expired", _is_expired, id="EventTrigger.is_expired"),
    pytest.param("dispatch_outcome gate 4", _gate4, id="dispatch_outcome gate 4"),
]


@pytest.mark.parametrize("where,bound_s,expected", _MATRIX)
@pytest.mark.parametrize("name,site", _SITES)
def test_the_receiver_bound_expires_an_envelope_early_never_late(
    name, site, where, bound_s, expected
):
    got = site(_at(where), datetime.timedelta(seconds=bound_s))
    assert got is expected, (
        f"{name}: the sender-stamped expiry is judged at now + the receiver's bound; at "
        f"{where} ({_at(where).isoformat()}, expiry {EXPIRY.isoformat()}) with a {bound_s}s "
        f"bound, expected expired={expected}, got expired={got}"
    )


_US = datetime.timedelta(microseconds=1)


@pytest.mark.parametrize(
    "at,bound,expected",
    [
        # A zero bound is today's comparison exactly, and today's is strict: an
        # envelope is still live AT its expiry instant and expired one tick after.
        pytest.param(EXPIRY, datetime.timedelta(0), False, id="zero-bound-live-at-expiry"),
        pytest.param(EXPIRY + _US, datetime.timedelta(0), True, id="zero-bound-expired-after"),
        # The bound moves that edge by exactly its width: GAP before the expiry,
        # a bound of GAP lands on the edge, a microsecond more crosses it.
        pytest.param(EXPIRY - GAP, GAP - _US, False, id="bound-just-short-of-the-edge"),
        pytest.param(EXPIRY - GAP, GAP, False, id="bound-lands-on-the-edge"),
        pytest.param(EXPIRY - GAP, GAP + _US, True, id="bound-just-past-the-edge"),
    ],
)
@pytest.mark.parametrize("name,site", _SITES)
def test_the_bound_moves_the_strict_edge_by_exactly_its_width(name, site, at, bound, expected):
    got = site(at, bound)
    assert got is expected, (
        f"{name}: expired iff now + bound > expiry (strict, as with no bound); at "
        f"{at.isoformat()} with bound {bound} against expiry {EXPIRY.isoformat()}, expected "
        f"expired={expected}, got expired={got}"
    )


@pytest.mark.parametrize("name,site", _SITES)
def test_a_negative_bound_is_refused(name, site):
    with pytest.raises(ValueError, match="must not be negative"):
        site(_at("inside"), datetime.timedelta(seconds=-30))


def test_an_envelope_cannot_carry_a_bound():
    """The schema forbids the field, and a payload key of that name is inert."""
    with pytest.raises(ValidationError):
        do._envelope(clock_skew_seconds=3600)
    claims = do._envelope(payload={"clock_skew_seconds": 3600, "skew": 3600})
    assert claims.is_expired(_at("inside")) is False
    assert claims.is_expired(_at("inside"), datetime.timedelta(seconds=30)) is True


# --- the airlock reads ChannelsManifest.clock_skew_seconds ------------------


def test_the_airlock_bound_ships_off_and_refuses_a_negative():
    assert ChannelsManifest(zone="z").clock_skew_seconds == 0
    for bad in (-1, True, "30", MAX_CLOCK_SKEW_SECONDS + 1, 10**13):
        with pytest.raises(ValidationError, match="clock_skew_seconds"):
            ChannelsManifest(zone="z", clock_skew_seconds=bad)
    assert ChannelsManifest(
        zone="z", clock_skew_seconds=MAX_CLOCK_SKEW_SECONDS
    ).clock_skew_seconds == MAX_CLOCK_SKEW_SECONDS
    built = build_airlock(
        ChannelsManifest(zone="z", clock_skew_seconds=45), token=ah._WEBHOOK_SECRET
    )
    assert built.clock_skew == datetime.timedelta(seconds=45), "build_airlock"


@pytest.fixture
def airlock_with_bound(monkeypatch, tmp_path):
    """The real handler (manifest -> build_airlock -> dispatch) with AWS faked."""

    def wire(seconds: int):
        path = tmp_path / f"channels-{seconds}.yaml"
        path.write_text(ah._MANIFEST_YAML + f"clock_skew_seconds: {seconds}\n", encoding="utf-8")
        monkeypatch.setenv("CHANNELS_MANIFEST", str(path))
        monkeypatch.setenv("CHANNELS_DEDUPE_TABLE", "dedupe-table")
        monkeypatch.setenv("CHANNELS_DROP_BUCKET", "drop-bucket")
        monkeypatch.setenv("CHANNELS_ACCEPTED_QUEUE_URL", "https://sqs.example/accepted")
        monkeypatch.setenv("CHANNELS_WEBHOOK_SECRET_ARN", "arn:aws:secretsmanager:::secret/w")
        sqs = ah.FakeSqsClient()
        monkeypatch.setattr(airlock, "_dynamodb_client", ah.FakeDynamoClient)
        monkeypatch.setattr(airlock, "_s3_client", ah.FakeS3Client)
        monkeypatch.setattr(airlock, "_sqs_client", lambda: sqs)
        monkeypatch.setattr(airlock, "_fetch_webhook_token", lambda arn: ah._WEBHOOK_SECRET)
        monkeypatch.setattr(airlock, "_STATE", None)
        return sqs

    yield wire
    airlock._STATE = None


def _body_expiring_in(delta: datetime.timedelta, **payload) -> str:
    body = json.loads(ah._envelope_json())
    body["expiry"] = (datetime.datetime.now(UTC) + delta).isoformat()
    if payload:
        body["payload"] = payload
    return json.dumps(body)


@pytest.mark.parametrize("seconds,accepted", [(0, True), (3600, False)])
def test_the_airlock_handler_applies_its_manifest_bound(airlock_with_bound, seconds, accepted):
    sqs = airlock_with_bound(seconds)
    # Ten minutes left on the sender's clock: inside a one-hour bound.
    airlock.handler(ah._event(_body_expiring_in(datetime.timedelta(minutes=10))), None)
    assert (len(sqs.messages) == 1) is accepted, (
        f"airlock handler, manifest clock_skew_seconds={seconds}: enqueued {len(sqs.messages)}"
    )


@pytest.mark.parametrize(
    "seconds,claim,accepted",
    [
        pytest.param(3600, 0, False, id="a-claimed-zero-does-not-lower-the-bound"),
        pytest.param(0, 3600, True, id="a-claimed-bound-does-not-raise-it"),
    ],
)
def test_the_airlock_handler_ignores_a_bound_the_envelope_claims(
    airlock_with_bound, seconds, claim, accepted
):
    sqs = airlock_with_bound(seconds)
    body = _body_expiring_in(
        datetime.timedelta(minutes=10), clock_skew_seconds=claim, skew=claim
    )
    airlock.handler(ah._event(body), None)
    assert (len(sqs.messages) == 1) is accepted, (
        f"airlock handler: manifest bound {seconds}s, envelope claims {claim}s"
    )


# --- the drain reads its AgentManifest.clock_skew_seconds -------------------


@pytest.fixture
def drain_with_bound(monkeypatch, tmp_path):
    def wire(seconds: int):
        path = tmp_path / f"drain-{seconds}.yaml"
        path.write_text(dh._MANIFEST_YAML + f"clock_skew_seconds: {seconds}\n", encoding="utf-8")
        monkeypatch.setenv("CHANNELS_DRAIN_MANIFEST", str(path))
        monkeypatch.setenv("CHANNELS_DRAIN_RECEIVER", f"{dh.__name__}:SpyReceiver")
        monkeypatch.setattr(drain, "_build_runtime", lambda manifest: dh.FakeRuntime())
        monkeypatch.setattr(drain, "_STATE", None)
        dh.SpyReceiver.calls = []

    yield wire
    drain._STATE = None
    dh.SpyReceiver.calls = []


@pytest.mark.parametrize("claim", [None, 0, 3600])
@pytest.mark.parametrize("seconds,received", [(0, True), (3600, False)])
def test_the_drain_applies_its_manifest_bound(drain_with_bound, seconds, received, claim):
    """The drain's own manifest decides, whatever the envelope's payload claims."""
    drain_with_bound(seconds)
    expiry = (datetime.datetime.now(UTC) + datetime.timedelta(minutes=10)).isoformat()
    body = json.loads(dh._envelope_body(expiry=expiry))
    if claim is not None:
        body["payload"] = {"clock_skew_seconds": claim, "skew": claim}
    response = drain.handler(dh._sqs_event(json.dumps(body)), None)
    assert response == {"batchItemFailures": []}
    assert bool(dh.SpyReceiver.calls) is received, (
        f"drain handler, manifest clock_skew_seconds={seconds}: received "
        f"{len(dh.SpyReceiver.calls)}"
    )
