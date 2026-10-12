"""The decision mouth's route, `/decide`, on the tool-event listener, SDK-free (#168).

`EventApp` is plain ASGI, so a request is three dicts and two coroutines, driven
against a real runtime built from the decision test manifest
(`test_harness_decision.py`) behind the same guard and token as `/events`. What
this pins (`broker/GATEWAY.md` G30 on):

- unauthenticated is the fixed 401 (G26), and nothing is decided;
- every authenticated request gets 200 and one of the two answers, never a 400
  or a 500: a malformed request is refused AND recorded, and a fault refuses;
- a permit is answered only once its record is on the tape;
- the text is base-owned and keyed on the answer kind;
- a decision enters the runtime only on the thread that built it, one at a time
  (G18, G27);
- `/events` answers as it always did beside it, and the launcher binds both.
"""

from __future__ import annotations

import asyncio
import json
import threading
from functools import partial
from pathlib import Path

import pytest

from safe_agents.broker.api import build_runtime, load_agent_manifest
from safe_agents.broker.audit import hash_args
from safe_agents.broker.gateway import GatewaySurface
from safe_agents.broker.gateway import __main__ as launcher
from safe_agents.broker.gateway.authn import LaunchToken, RefusalLedger
from safe_agents.broker.gateway.events import (
    DECIDE_PATH,
    EVENT_MOUTH_CODE,
    EVENTS_PATH,
    MAX_EVENT_BODY_BYTES,
    EventApp,
)
from safe_agents.broker.gateway.network import (
    ConnectionGuard,
    RuntimeEntryRefused,
    SerializedSurface,
)
from safe_agents.broker.gateway.server import EventMouth
from safe_agents.broker.runtime.harness_decision import (
    FAULT_REASON,
    HELD_SENTENCE,
    MALFORMED_REASON,
    REFUSED_SENTENCE,
)
from safe_agents.broker.runtime.pep import MOUTH_REFUSAL_TOOL
from safe_agents.broker.tests.test_gateway_authn import OTHER, TOKEN
from safe_agents.broker.tests.test_gateway_network import _BROKER_ENV, _drive, _scope
from safe_agents.broker.tests.test_harness_decision import CALL, INPUT, SUBJECT, _manifest, taint

REQUEST = {
    "harness": "example-harness",
    "tool_class": "shell",
    "locality": "project",
    "subject_digest": SUBJECT,
    "input_digest": INPUT,
    "call_digest": CALL,
}
AUTH = (b"authorization", f"Bearer {TOKEN}".encode())
ANSWER_KEYS = {"answer", "reason", "intent_id", "text"}


def _body(**changes) -> bytes:
    request = {**REQUEST, **changes}
    return json.dumps({k: v for k, v in request.items() if v is not ...}).encode()


def _status(sent: list[dict]) -> int:
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


def _payload(sent: list[dict]) -> dict:
    return json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))


def _decide(app, body: bytes, *, method: str = "POST", headers=(AUTH,)) -> list[dict]:
    sent, _ = _drive(app, _scope(method, headers=list(headers), path=DECIDE_PATH), body)
    return sent


@pytest.fixture
def mouth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A guarded `EventApp` serving both routes. Yields (app, runtime, sink)."""
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    made: list = []

    def build(*, held: tuple[str, ...] = ()):
        path = _manifest(tmp_path / f"m{len(made)}.yaml", held=held, trusted=())
        runtime, sink = build_runtime(load_agent_manifest(path))
        made.append(runtime)
        surface = SerializedSurface(GatewaySurface(runtime))
        ledger = RefusalLedger(partial(launcher._record_refusals, runtime, EVENT_MOUTH_CODE), window_s=1e9)
        app = ConnectionGuard(
            EventApp(
                partial(surface.observe, mouth=EVENT_MOUTH_CODE),
                partial(surface.decide, mouth=EVENT_MOUTH_CODE),
                partial(surface.refuse_decision, mouth=EVENT_MOUTH_CODE),
            ),
            LaunchToken(TOKEN),
            ledger,
        )
        return app, runtime, sink

    try:
        yield build
    finally:
        for runtime in made:
            runtime.close()


class TestAuthentication:
    @pytest.mark.parametrize("headers", [(), ((b"authorization", f"Bearer {OTHER}".encode()),)])
    def test_unauthenticated_is_the_fixed_401_and_nothing_is_decided(self, mouth, headers) -> None:
        app, runtime, sink = mouth()
        sent, reads = _drive(app, _scope("POST", headers=list(headers), path=DECIDE_PATH), _body())
        assert _status(sent) == 401
        assert reads == 0
        assert [(r.tool, r.op) for r in sink.records()] == [(MOUTH_REFUSAL_TOOL, EVENT_MOUTH_CODE)]
        assert all(r.outcome != "permitted" for r in sink.records())


class TestTheAnswer:
    def test_a_permit_is_answered_only_once_its_record_is_on_the_tape(self, mouth) -> None:
        app, _, sink = mouth()
        on_tape: list[list[str]] = []

        async def send(message: dict) -> None:
            if message["type"] == "http.response.start":
                on_tape.append([r.outcome for r in sink.records()])
            sent.append(message)

        async def receive() -> dict:
            return {"type": "http.request", "body": _body(), "more_body": False}

        sent: list[dict] = []
        asyncio.run(app(_scope("POST", headers=[AUTH], path=DECIDE_PATH), receive, send))
        assert _status(sent) == 200
        payload = _payload(sent)
        assert set(payload) == ANSWER_KEYS
        assert (payload["answer"], payload["intent_id"], payload["text"]) == ("permit", None, None)
        assert on_tape == [["permitted"]]

    def test_a_hold_answers_refuse_with_its_intent_id_and_the_held_sentence(self, mouth) -> None:
        app, runtime, _ = mouth(held=("shell",))
        taint(runtime)
        payload = _payload(_decide(app, _body()))
        assert payload["answer"] == "refuse"
        assert payload["intent_id"]
        assert payload["text"].startswith(HELD_SENTENCE.format(intent_id=payload["intent_id"]))
        assert payload["text"].endswith(f"Reason: {payload['reason']}")

    def test_a_refusal_carries_the_refused_sentence_and_the_broker_reason(self, mouth) -> None:
        app, _, _ = mouth()
        payload = _payload(_decide(app, _body(locality="home")))
        assert payload["answer"] == "refuse" and payload["intent_id"] is None
        assert payload["text"] == f"{REFUSED_SENTENCE} Reason: {payload['reason']}"

    def test_nothing_in_the_request_reaches_the_text(self, mouth) -> None:
        app, _, _ = mouth()
        payload = _payload(_decide(app, _body(harness="zz-request-text", locality="home")))
        assert "zz-request-text" not in payload["text"]
        assert "approve" not in payload["text"].replace("approved", "").replace("approval", "")


MALFORMED = [
    pytest.param("GET", b"", "bad-method", id="GET"),
    pytest.param("PUT", _body(), "bad-method", id="PUT"),
    pytest.param("POST", b"", "bad-body", id="empty body"),
    pytest.param("POST", b"{not json", "bad-body", id="not JSON"),
    pytest.param("POST", json.dumps([REQUEST]).encode(), "bad-body", id="an array"),
    pytest.param("POST", _body(extra="x"), "bad-body", id="an unknown key"),
    pytest.param("POST", _body(input_digest=...), "bad-body", id="no input digest"),
    pytest.param("POST", _body(call_digest=...), "bad-body", id="no call digest"),
    pytest.param("POST", _body(mouth="network-mcp"), "bad-body", id="a request naming its mouth"),
    pytest.param("POST", b'{"harness": "a", "harness": "b"}', "bad-body", id="a repeated key"),
    pytest.param("POST", _body(tool_class="bash"), "bad-field", id="an unknown class"),
    pytest.param("POST", _body(subject_digest="/etc/passwd"), "bad-field", id="a raw path"),
    pytest.param("POST", _body(input_digest="make install"), "bad-field", id="a raw input"),
]


class TestMalformedIsRefusedAndRecorded:
    @pytest.mark.parametrize(("method", "body", "cause"), MALFORMED)
    def test_never_a_400_and_always_one_record(self, mouth, method, body, cause) -> None:
        app, runtime, sink = mouth()
        sent = _decide(app, body, method=method)
        assert _status(sent) == 200
        payload = _payload(sent)
        assert (payload["answer"], payload["reason"], payload["intent_id"]) == (
            "refuse", MALFORMED_REASON, None,
        )
        assert payload["text"] == f"{REFUSED_SENTENCE} Reason: {MALFORMED_REASON}"
        (record,) = sink.records()
        assert (record.tool, record.op, record.decision, record.outcome) == (
            MOUTH_REFUSAL_TOOL, EVENT_MOUTH_CODE, "deny", "denied",
        )
        assert record.argsDigest == hash_args({"cause": cause})
        assert runtime.session_turn().tainted is False

    def test_a_body_declared_too_large_is_refused_unread_and_recorded(self, mouth) -> None:
        app, _, sink = mouth()
        headers = [AUTH, (b"content-length", str(MAX_EVENT_BODY_BYTES + 1).encode())]
        sent, reads = _drive(app, _scope("POST", headers=headers, path=DECIDE_PATH), _body())
        assert (_status(sent), _payload(sent)["answer"], reads) == (200, "refuse", 0)
        (record,) = sink.records()
        assert record.argsDigest == hash_args({"cause": "too-large"})

    def test_a_malformed_request_whose_record_fails_is_still_refused(self, mouth, monkeypatch) -> None:
        app, _, sink = mouth()
        monkeypatch.setattr(sink, "append", lambda _r: (_ for _ in ()).throw(OSError("unwritable")))
        sent = _decide(app, b"{not json")
        assert (_status(sent), _payload(sent)["answer"]) == (200, "refuse")


class TestFaultsAnswerRefuse:
    def test_a_sink_failure_on_a_permit_answers_refuse(self, mouth, monkeypatch) -> None:
        app, _, sink = mouth()
        monkeypatch.setattr(sink, "append", lambda _r: (_ for _ in ()).throw(OSError("unwritable")))
        sent = _decide(app, _body())
        assert (_status(sent), _payload(sent)["answer"], _payload(sent)["reason"]) == (
            200, "refuse", FAULT_REASON,
        )

    def test_a_decide_that_raises_answers_refuse(self) -> None:
        def broken(**_kw):
            raise RuntimeError("the runtime is gone")

        app = EventApp(lambda **_kw: None, broken, lambda **_kw: None)
        sent, _ = _drive(app, _scope("POST", path=DECIDE_PATH), _body())
        assert (_status(sent), _payload(sent)["answer"], _payload(sent)["reason"]) == (
            200, "refuse", FAULT_REASON,
        )

    def test_a_decide_that_answers_anything_else_is_refused(self) -> None:
        app = EventApp(lambda **_kw: None, lambda **_kw: {"answer": "permit"}, lambda **_kw: None)
        sent, _ = _drive(app, _scope("POST", path=DECIDE_PATH), _body())
        assert _payload(sent)["answer"] == "refuse"


class TestSerializedOntoTheRuntimeThread:
    """G18, G27: a decision enters the runtime on the thread that built it, one at a time.

    Overlapping decisions can drop one's taint or decide before a sibling's read has
    tainted the turn, and both fail open.
    """

    @staticmethod
    def _off_thread(target) -> list[BaseException]:
        caught: list[BaseException] = []

        def run() -> None:
            try:
                target()
            except BaseException as exc:  # noqa: BLE001
                caught.append(exc)

        worker = threading.Thread(target=run)
        worker.start()
        worker.join()
        return caught

    def test_a_decide_from_another_thread_is_refused_before_the_runtime(self, mouth) -> None:
        _, runtime, sink = mouth()
        surface = SerializedSurface(GatewaySurface(runtime))
        caught = self._off_thread(lambda: surface.decide(mouth=EVENT_MOUTH_CODE, **REQUEST))
        assert len(caught) == 1 and isinstance(caught[0], RuntimeEntryRefused), (
            "a decision from another thread reached the runtime: /decide is not "
            f"serialized onto the runtime's thread ({caught})"
        )
        assert sink.records() == []

    def test_a_decide_while_another_call_is_inside_is_refused(self, mouth) -> None:
        _, runtime, sink = mouth()
        surface = SerializedSurface(GatewaySurface(runtime))
        surface._busy.acquire()
        try:
            with pytest.raises(RuntimeEntryRefused, match="another call"):
                surface.decide(mouth=EVENT_MOUTH_CODE, **REQUEST)
        finally:
            surface._busy.release()
        assert sink.records() == [], "an overlapping decision reached the runtime"

    def test_a_malformed_refusal_from_another_thread_is_refused_before_the_runtime(
        self, mouth
    ) -> None:
        _, runtime, sink = mouth()
        surface = SerializedSurface(GatewaySurface(runtime))
        caught = self._off_thread(
            lambda: surface.refuse_decision(mouth=EVENT_MOUTH_CODE, cause="bad-body")
        )
        assert len(caught) == 1 and isinstance(caught[0], RuntimeEntryRefused), (
            "a malformed-request refusal from another thread reached the runtime: the "
            f"refusal entry of /decide is not serialized onto the runtime's thread ({caught})"
        )
        assert sink.records() == []

    def test_a_malformed_refusal_while_another_call_is_inside_is_refused(self, mouth) -> None:
        _, runtime, sink = mouth()
        surface = SerializedSurface(GatewaySurface(runtime))
        surface._busy.acquire()
        try:
            with pytest.raises(RuntimeEntryRefused, match="another call"):
                surface.refuse_decision(mouth=EVENT_MOUTH_CODE, cause="bad-body")
        finally:
            surface._busy.release()
        assert sink.records() == [], "an overlapping malformed-request refusal reached the runtime"

    def test_the_route_driven_from_another_thread_permits_nothing(self, mouth) -> None:
        app, _, sink = mouth()
        results: list[list[dict]] = []
        caught = self._off_thread(lambda: results.append(_decide(app, _body())))
        assert caught == []
        (sent,) = results
        assert (_status(sent), _payload(sent)["answer"]) == (200, "refuse")
        assert not any(r.outcome == "permitted" for r in sink.records()), (
            "a decision from another thread was permitted: /decide bypassed the serialized surface"
        )


class TestBesideTheEventsRoute:
    def test_events_still_answers_a_malformed_report_with_its_fixed_400(self, mouth) -> None:
        app, _, sink = mouth()
        sent, _ = _drive(app, _scope("POST", headers=[AUTH], path=EVENTS_PATH), b"{not json")
        assert (_status(sent), _payload(sent)) == (400, {"error": "bad request"})
        assert sink.records() == []

    def test_without_decide_bound_the_path_is_not_served(self) -> None:
        sent, _ = _drive(EventApp(lambda **_kw: None), _scope("POST", path=DECIDE_PATH), _body())
        assert _status(sent) == 404

    def test_decide_and_its_refusal_are_bound_together(self) -> None:
        with pytest.raises(ValueError):
            EventApp(lambda **_kw: None, lambda **_kw: None)

    def test_the_event_mouth_binds_both_routes_with_its_own_code(self) -> None:
        calls: list[tuple[str, dict]] = []

        class _Recording:
            def observe(self, **kw):
                calls.append(("observe", kw))

            def decide(self, **kw):
                calls.append(("decide", kw))
                raise RuntimeError("recorded")

            def refuse_decision(self, **kw):
                calls.append(("refuse_decision", kw))

        mouth = EventMouth.__new__(EventMouth)
        mouth._surface = _Recording()
        app = mouth._application()
        _drive(app, _scope("POST", path=DECIDE_PATH), _body())
        _drive(app, _scope("GET", path=DECIDE_PATH), b"")
        assert [(name, kw["mouth"]) for name, kw in calls] == [
            ("decide", EVENT_MOUTH_CODE), ("refuse_decision", EVENT_MOUTH_CODE),
        ]
