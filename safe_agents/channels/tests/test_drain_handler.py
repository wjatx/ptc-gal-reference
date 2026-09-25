"""sa#155 — the drain worker conformance suite (channels/DRAIN.md).

Drives the SQS Lambda handler end-to-end with a fake BrokerRuntime injected
through the ``_build_runtime`` seam and a spy Receiver injected through the
real provider-path loader (the test module itself is the "consumer image").
No AWS calls anywhere. Test names map to DRAIN.md's numbered clauses.
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import pytest

import safe_agents.channels.drain.handler as h
from safe_agents.broker.taint import TurnContext, build_trust_map
from safe_agents.channels.drain.receiver import ReceiverProviderError, load_receiver

_TS = "2026-07-09T00:00:00+00:00"
_FUTURE = "2099-01-01T00:00:00+00:00"
_PAST = "2001-01-01T00:00:00+00:00"

_MANIFEST_YAML = """\
principal:
  agentId: example-agent
  skill: demo
  user: demo-user
  tier: B
envelope:
  polarity: abstain
"""


@dataclass(frozen=True)
class _ProbeRequest:
    """The duck-typed request shape handle_request reads (like a consumer's)."""

    tool: str = "probe"
    op: str = "observe"
    args: Any = None
    idempotency_key: str | None = None


class FakeRuntime:
    """The surface the drain touches: session_turn() + handle_request().

    ``handle_request`` snapshots the broker-held turn's taint state at the
    moment of the call — the receiver-visible equivalent of "what taint was I
    decided under" — since the receiver itself no longer sees the turn (D2).
    """

    def __init__(self) -> None:
        self._turn: TurnContext | None = None
        self.requests: list[dict] = []

    def session_turn(self) -> TurnContext:
        if self._turn is None:
            self._turn = TurnContext(turn_id="turn:test")
        return self._turn

    def handle_request(self, request: Any) -> dict:
        turn = self.session_turn()
        self.requests.append(
            {
                "request": request,
                "tainted": turn.tainted,
                "sources": list(turn.to_taint().sources),
            }
        )
        return {"decision_kind": "allow"}


class SpyReceiver:
    """Consumer-side spy: records the facade it got and acts through it.

    ``calls`` is class-level so the zero-arg instance the loader constructs is
    still observable from the test; the fixture resets it.
    """

    calls: list[dict] = []
    trusted_prefixes: list[str] = ["peer:", "channel:"]

    def input_trust_map(self):
        return build_trust_map(trusted_prefixes=list(type(self).trusted_prefixes))

    def receive(self, envelope, runtime) -> None:
        type(self).calls.append({"event_id": envelope.event_id, "runtime": runtime})
        runtime.handle_request(_ProbeRequest())


class ExplodingReceiver(SpyReceiver):
    def receive(self, envelope, runtime) -> None:
        super().receive(envelope, runtime)
        raise RuntimeError("consumer action failed")


class NotAReceiver:
    """Satisfies nothing — for the protocol-check failure path."""


_SPY_PATH = f"{__name__}:SpyReceiver"


@pytest.fixture
def wired(monkeypatch, tmp_path):
    manifest_path = tmp_path / "drain-manifest.yaml"
    manifest_path.write_text(_MANIFEST_YAML, encoding="utf-8")
    monkeypatch.setenv("CHANNELS_DRAIN_MANIFEST", str(manifest_path))
    monkeypatch.setenv("CHANNELS_DRAIN_RECEIVER", _SPY_PATH)

    runtimes: list[FakeRuntime] = []

    def _fake_build_runtime(manifest):
        runtime = FakeRuntime()
        runtimes.append(runtime)
        return runtime

    monkeypatch.setattr(h, "_build_runtime", _fake_build_runtime)
    monkeypatch.setattr(h, "_STATE", None)
    SpyReceiver.calls = []
    SpyReceiver.trusted_prefixes = ["peer:", "channel:"]

    yield runtimes

    h._STATE = None
    SpyReceiver.calls = []


def _envelope_body(
    event_id: str = "evt-1",
    *,
    principal: str = "example-agent",
    source: str = "peer:example",
    label: str = "trusted",
    expiry: str = _FUTURE,
) -> str:
    return json.dumps(
        {
            "event_id": event_id,
            "principal": principal,
            "sender": {
                "channel_type": "webhook",
                "channel_identity": "peer:example",
                "evidence": ["sig:pass"],
            },
            "payload": {"msg": "hello"},
            "provenance": [
                {"zone": "peer", "source": source, "evidence": [], "label": label, "ts": _TS},
                {
                    "zone": "channels",
                    "source": "channel:webhook",
                    "evidence": ["token:pass"],
                    "label": "trusted",
                    "ts": _TS,
                },
            ],
            "sender_class": "peer-agent",
            "ts": _TS,
            "expiry": expiry,
        }
    )


def _sqs_event(*bodies: str) -> dict:
    return {
        "Records": [
            {"messageId": f"m{i}", "body": body} for i, body in enumerate(bodies, start=1)
        ]
    }


def _probe(runtime: FakeRuntime) -> dict:
    """The single probe call the SpyReceiver made through the facade."""
    [entry] = runtime.requests
    return entry


# --- D1 — ingest before act -------------------------------------------------

def test_ingest_precedes_receive(wired):
    resp = h.handler(_sqs_event(_envelope_body(label="untrusted")), None)

    assert resp == {"batchItemFailures": []}
    [runtime] = wired
    # The chain carried an untrusted origin hop; the receiver's brokered call
    # was decided under that taint — ingestion happened first.
    probe = _probe(runtime)
    assert probe["tainted"] is True
    assert "peer:example" in probe["sources"]


# --- D2 — one turn: ingest and action share the broker-held turn -------------

def test_ingest_and_action_share_one_turn(wired):
    h.handler(_sqs_event(_envelope_body()), None)

    [runtime] = wired
    # The facade forwards to the SAME runtime whose turn was ingested: the
    # receiver's probe call landed on it, decided under its single session
    # turn (FakeRuntime.handle_request snapshots that turn at call time).
    [entry] = runtime.requests
    assert isinstance(entry["request"], _ProbeRequest)


def test_receiver_gets_facade_without_turn_controls(wired):
    # D2's enforcement mechanism: the object handed to receive() exposes
    # handle_request and NO turn controls — the receiver cannot roll the
    # ingested taint away (new_turn) or reach the turn at all (session_turn).
    h.handler(_sqs_event(_envelope_body()), None)

    [call] = SpyReceiver.calls
    facade = call["runtime"]
    assert not isinstance(facade, FakeRuntime)
    assert callable(facade.handle_request)
    assert not hasattr(facade, "new_turn")
    assert not hasattr(facade, "session_turn")


# --- D1/label floor — receiver map is authoritative, labels only a floor -----

def test_trusted_label_and_trusted_map_leave_turn_clean(wired):
    h.handler(_sqs_event(_envelope_body(source="peer:example", label="trusted")), None)

    [runtime] = wired
    assert _probe(runtime)["tainted"] is False


def test_untrusted_label_taints_despite_trusting_map(wired):
    # The map trusts "peer:" — but the sender honestly labeled its hop
    # untrusted; the label floor taints anyway (one-way rule, consequence 2).
    h.handler(_sqs_event(_envelope_body(source="peer:example", label="untrusted")), None)

    [runtime] = wired
    assert _probe(runtime)["tainted"] is True


def test_trusted_label_earns_nothing_receiver_map_denies(wired, monkeypatch):
    # The peer stamps "trusted" on a source the receiver's own map does NOT
    # trust: launders nothing, the turn taints (the anti-laundering half).
    SpyReceiver.trusted_prefixes = []
    monkeypatch.setattr(h, "_STATE", None)

    h.handler(_sqs_event(_envelope_body(source="peer:example", label="trusted")), None)

    [runtime] = wired
    assert _probe(runtime)["tainted"] is True


# --- D3/D4 — trust the stamp; receiver owns idempotency ----------------------

def test_duplicate_records_both_delivered_receiver_owns_idempotency(wired):
    # No dedupe surface exists in the worker BY CONTRACT (D3): two deliveries
    # of the same event_id both reach the receiver, whose idempotency
    # obligation (D4) is what makes that safe — each on its OWN ephemeral turn.
    body = _envelope_body(event_id="evt-dup")
    resp = h.handler(_sqs_event(body, body), None)

    assert resp == {"batchItemFailures": []}
    assert [c["event_id"] for c in SpyReceiver.calls] == ["evt-dup", "evt-dup"]
    assert len(wired) == 2
    assert wired[0].session_turn() is not wired[1].session_turn()


# --- D5 — principal match ----------------------------------------------------

def test_principal_mismatch_drops_terminally_without_receive(wired, caplog):
    with caplog.at_level(logging.INFO, logger=h.logger.name):
        resp = h.handler(_sqs_event(_envelope_body(principal="someone-else")), None)

    # Terminal, not transient: NOT reported for redelivery (D7 — no DLQ, a
    # redelivered mismatch would just poison-loop), but loudly logged.
    assert resp == {"batchItemFailures": []}
    assert "drain_principal_mismatch" in caplog.text
    assert "drain_terminal_drop" in caplog.text
    assert SpyReceiver.calls == []
    assert wired == []  # no runtime was even built


# --- C6/D7 — expiry is a hard TTL, dropped terminally before ingest ----------

def test_expired_envelope_drops_terminally_before_ingest(wired, caplog):
    with caplog.at_level(logging.INFO, logger=h.logger.name):
        resp = h.handler(_sqs_event(_envelope_body(expiry=_PAST)), None)

    assert resp == {"batchItemFailures": []}
    assert "drain_expired" in caplog.text
    assert "drain_terminal_drop" in caplog.text
    assert SpyReceiver.calls == []
    assert wired == []  # dropped before any budget-spending step


def test_expired_drop_log_is_pii_safe(wired, caplog):
    with caplog.at_level(logging.INFO, logger=h.logger.name):
        h.handler(_sqs_event(_envelope_body(expiry=_PAST)), None)

    expired = [r for r in caplog.messages if "drain_expired" in r]
    assert expired
    payload = json.loads(expired[0])
    assert payload["identity_digest"].startswith("sha256:")
    assert "peer:example" not in expired[0]


# --- D6 — image-baked receiver injection, fail closed ------------------------

def test_missing_receiver_env_fails_whole_invocation(wired, monkeypatch):
    monkeypatch.delenv("CHANNELS_DRAIN_RECEIVER")
    monkeypatch.setattr(h, "_STATE", None)

    with pytest.raises(h.DrainConfigError):
        h.handler(_sqs_event(_envelope_body()), None)


def test_missing_manifest_env_fails_whole_invocation(wired, monkeypatch):
    monkeypatch.delenv("CHANNELS_DRAIN_MANIFEST")
    monkeypatch.setattr(h, "_STATE", None)

    with pytest.raises(h.DrainConfigError):
        h.handler(_sqs_event(_envelope_body()), None)


def test_bad_receiver_provider_path_fails_closed_typed(wired, monkeypatch):
    monkeypatch.setenv("CHANNELS_DRAIN_RECEIVER", "no.such.module:Nope")
    monkeypatch.setattr(h, "_STATE", None)

    with pytest.raises(ReceiverProviderError):
        h.handler(_sqs_event(_envelope_body()), None)


@pytest.mark.parametrize(
    "path",
    [
        "not-a-path",  # no colon
        f"{__name__}:NoSuchClass",  # missing attribute
        f"{__name__}:NotAReceiver",  # fails the protocol check
        f"{__name__}:SpyReceiver:extra",  # two colons
    ],
)
def test_load_receiver_rejects_bad_providers(path):
    with pytest.raises(ReceiverProviderError):
        load_receiver(path)


def test_load_receiver_yields_protocol_satisfying_instance():
    receiver = load_receiver(_SPY_PATH)
    assert isinstance(receiver, SpyReceiver)
    assert callable(receiver.input_trust_map())


# --- D7 — disposition: terminal drops vs transient batch failures ------------

def test_terminal_records_never_reported_transient_siblings_unaffected(wired):
    resp = h.handler(
        _sqs_event(
            _envelope_body(event_id="evt-ok-1"),
            _envelope_body(event_id="evt-bad", principal="someone-else"),
            _envelope_body(event_id="evt-ok-2"),
        ),
        None,
    )

    # The terminal record (m2) is dropped, not redelivered; siblings proceed.
    assert resp == {"batchItemFailures": []}
    assert [c["event_id"] for c in SpyReceiver.calls] == ["evt-ok-1", "evt-ok-2"]


def test_malformed_body_drops_terminally_without_killing_batch(wired, caplog):
    with caplog.at_level(logging.INFO, logger=h.logger.name):
        resp = h.handler(
            _sqs_event("{not json", _envelope_body(event_id="evt-ok")), None
        )

    assert resp == {"batchItemFailures": []}
    assert "drain_terminal_drop" in caplog.text
    assert [c["event_id"] for c in SpyReceiver.calls] == ["evt-ok"]


def test_receiver_exception_is_transient_fails_its_record_only(wired, monkeypatch):
    monkeypatch.setenv("CHANNELS_DRAIN_RECEIVER", f"{__name__}:ExplodingReceiver")
    monkeypatch.setattr(h, "_STATE", None)

    resp = h.handler(
        _sqs_event(_envelope_body(event_id="evt-a"), _envelope_body(event_id="evt-b")), None
    )

    assert resp == {
        "batchItemFailures": [{"itemIdentifier": "m1"}, {"itemIdentifier": "m2"}]
    }


def test_terminal_drop_log_carries_machine_reason(wired, caplog):
    with caplog.at_level(logging.INFO, logger=h.logger.name):
        h.handler(_sqs_event(_envelope_body(expiry=_PAST)), None)

    drops = [r for r in caplog.messages if "drain_terminal_drop" in r]
    assert drops
    payload = json.loads(drops[0])
    assert payload["reason"] == "expired"
    assert payload["message_id"] == "m1"


# --- cold-start HMAC key fetch (BROKER_HMAC_KEY_SECRET_ARN) -------------------

_ARN = "arn:aws:secretsmanager:us-east-1:111111111111:secret:grant-hmac"


def test_hmac_secret_arn_fetched_once_and_exported(wired, monkeypatch):
    monkeypatch.setenv("BROKER_HMAC_KEY_SECRET_ARN", _ARN)
    monkeypatch.setenv("BROKER_HMAC_KEY", "stale-value")  # registers env restore
    monkeypatch.setattr(h, "_STATE", None)
    fetched: list[str] = []

    def _fake_fetch(secret_arn: str) -> str:
        fetched.append(secret_arn)
        return "the-real-key"

    monkeypatch.setattr(h, "_fetch_hmac_key", _fake_fetch)

    h.handler(_sqs_event(_envelope_body()), None)

    assert fetched == [_ARN]
    assert os.environ["BROKER_HMAC_KEY"] == "the-real-key"
    # Warm invocation: state is cached, no second Secrets Manager round-trip.
    h.handler(_sqs_event(_envelope_body(event_id="evt-2")), None)
    assert fetched == [_ARN]


def test_hmac_secret_fetch_failure_fails_closed_and_never_logs_key(
    wired, monkeypatch, caplog
):
    monkeypatch.setenv("BROKER_HMAC_KEY_SECRET_ARN", _ARN)
    monkeypatch.setattr(h, "_STATE", None)
    key_marker = "super-secret-hmac-key-material"

    def _boom(secret_arn: str) -> str:
        raise RuntimeError(key_marker)

    monkeypatch.setattr(h, "_fetch_hmac_key", _boom)

    with caplog.at_level(logging.INFO, logger=h.logger.name):
        with pytest.raises(h.DrainConfigError) as excinfo:
            h.handler(_sqs_event(_envelope_body()), None)

    # Fail-closed and loud, but the typed error and the structured log carry
    # only the exception TYPE — never the fetch error's message or the key.
    assert key_marker not in str(excinfo.value)
    assert key_marker not in caplog.text
    assert "drain_config_error" in caplog.text


def test_no_hmac_secret_arn_means_no_fetch(wired, monkeypatch):
    monkeypatch.delenv("BROKER_HMAC_KEY_SECRET_ARN", raising=False)
    monkeypatch.setattr(h, "_STATE", None)

    def _must_not_run(secret_arn: str) -> str:
        raise AssertionError("no ARN set — the fetch seam must not be touched")

    monkeypatch.setattr(h, "_fetch_hmac_key", _must_not_run)

    resp = h.handler(_sqs_event(_envelope_body()), None)
    assert resp == {"batchItemFailures": []}


# --- D8 — PII-safe logging ----------------------------------------------------

def test_malformed_record_logs_no_payload(wired, caplog):
    secret_marker = "super-secret-payload-content"
    with caplog.at_level(logging.INFO, logger=h.logger.name):
        h.handler(_sqs_event('{"payload": "' + secret_marker + '" not json'), None)

    assert secret_marker not in caplog.text
    assert "drain_malformed" in caplog.text


def test_structured_logs_carry_digest_never_identity(wired, caplog):
    with caplog.at_level(logging.INFO, logger=h.logger.name):
        h.handler(_sqs_event(_envelope_body()), None)

    ingested = [r for r in caplog.messages if "drain_ingested" in r]
    assert ingested and "sha256:" in ingested[0]
    payload = json.loads(ingested[0])
    assert payload["identity_digest"].startswith("sha256:")
    assert "peer:example" not in ingested[0]
