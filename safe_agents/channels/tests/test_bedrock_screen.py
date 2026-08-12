"""sa#152 Slice B — the reference Bedrock classifier screen.

The screen is reference-tier (docs/contract-vs-reference.md); these tests prove
it satisfies the gate-7 clauses of channels/SCREENING.md with a fake Converse
client, never touching AWS. The screen uses FORCED TOOL USE — the model must
call the `verdict` tool — so the fakes return tool-use-shaped Converse
responses. The screening contract itself is proved in test_screening.py; this
suite is about the one concrete screen.
"""

import logging

import pytest
from pydantic import ValidationError

from safe_agents.channels.dispatch import dispatch
from safe_agents.channels.manifest import ChannelsManifest, ScreenConfig, build_airlock
from safe_agents.channels.screening import INJECTION_SUSPECTED, SCREEN_ERROR
from safe_agents.channels.screens.bedrock_classifier import (
    BedrockClassifierParams,
    BedrockClassifierScreen,
)
from safe_agents.channels.tests.test_adapters import (
    _NOW,
    StubInboundAdapter,
    _digest,
    _envelope,
)
from safe_agents.channels.trust_map import ChannelTrustMap, TrustMapEntry

_TOKEN = "example-token"
_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
# A distinctive string placed in a payload; no exception or record may echo it.
_SENTINEL = "SENTINEL_PAYLOAD_do_not_leak_9f3a"


# --- Converse response builders (tool-use shaped) ---------------------------


def _response(content_blocks: list) -> dict:
    return {"output": {"message": {"role": "assistant", "content": content_blocks}}}


def _tool_block(*, name: str = "verdict", tool_input: dict) -> dict:
    return {"toolUse": {"toolUseId": "tu-1", "name": name, "input": tool_input}}


def _verdict_response(injection: bool) -> dict:
    return _response([_tool_block(tool_input={"injection": injection})])


class _FakeConverse:
    """A stand-in bedrock-runtime client: records the request, returns a canned response."""

    def __init__(self, response: dict) -> None:
        self._response = response
        self.last_user_text: str | None = None
        self.last_tool_config: dict | None = None
        self.calls = 0

    def converse(self, *, modelId, system, messages, inferenceConfig, toolConfig=None, **kwargs):  # noqa: N803
        self.calls += 1
        self.last_user_text = messages[0]["content"][0]["text"]
        self.last_tool_config = toolConfig
        return self._response


class _RaisingConverse:
    """A client whose Converse call fails — exercises the dispatcher's seam backstop."""

    def converse(self, **kwargs):
        raise RuntimeError("bedrock unavailable")


def _screen(response: dict, *, max_chars: int = 4096) -> BedrockClassifierScreen:
    return BedrockClassifierScreen(
        BedrockClassifierParams(model_id=_MODEL_ID, max_chars=max_chars),
        client=_FakeConverse(response),
    )


def _trust_map_for(identity: str) -> ChannelTrustMap:
    return ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=identity,
                principal="test-principal",
                sender_class="peer-agent",
            )
        ]
    )


# --- Deterministic verdict mapping -----------------------------------------


def test_injection_true_refuses_with_injection_suspected():
    verdict = _screen(_verdict_response(True))(_envelope())
    assert bool(verdict) is False
    assert verdict.reason == INJECTION_SUSPECTED


def test_injection_false_passes_contentless():
    verdict = _screen(_verdict_response(False))(_envelope())
    assert bool(verdict) is True
    assert verdict.reason is None


@pytest.mark.parametrize(
    "content_blocks",
    [
        [{"text": "no injection here"}],  # text only, no tool-use block
        [],  # no blocks at all
        [  # two tool-use blocks
            _tool_block(tool_input={"injection": True}),
            _tool_block(tool_input={"injection": False}),
        ],
        [_tool_block(name="something_else", tool_input={"injection": True})],  # wrong tool name
        [_tool_block(tool_input={"injection": False, "confidence": 0.9})],  # extra keys
        [_tool_block(tool_input={"injection": "true"})],  # value is a string, not a bool
        [_tool_block(tool_input={})],  # missing the injection key
    ],
)
def test_malformed_response_raises_without_leaking_content(content_blocks):
    envelope = _envelope(payload={"message": _SENTINEL})
    with pytest.raises(ValueError) as exc_info:
        _screen(_response(content_blocks))(envelope)
    # Exception text carries only shape facts — never payload content.
    assert _SENTINEL not in str(exc_info.value)


def test_non_converse_shape_raises():
    envelope = _envelope(payload={"message": _SENTINEL})
    with pytest.raises(ValueError) as exc_info:
        _screen({"unexpected": "shape"})(envelope)
    assert _SENTINEL not in str(exc_info.value)


def test_request_forces_verdict_tool_use():
    fake = _FakeConverse(_verdict_response(False))
    screen = BedrockClassifierScreen(BedrockClassifierParams(model_id=_MODEL_ID), client=fake)
    screen(_envelope())

    # Pin the forcing, not just the response handling: toolChoice must force `verdict`.
    assert fake.last_tool_config is not None
    assert fake.last_tool_config["toolChoice"] == {"tool": {"name": "verdict"}}
    tools = fake.last_tool_config["tools"]
    assert len(tools) == 1
    spec = tools[0]["toolSpec"]
    assert spec["name"] == "verdict"
    schema = spec["inputSchema"]["json"]
    assert schema["required"] == ["injection"]
    assert schema["properties"]["injection"]["type"] == "boolean"
    assert schema["additionalProperties"] is False


def test_payload_is_truncated_to_max_chars():
    fake = _FakeConverse(_verdict_response(False))
    screen = BedrockClassifierScreen(
        BedrockClassifierParams(model_id=_MODEL_ID, max_chars=32), client=fake
    )
    screen(_envelope(payload={"text": "x" * 1000}))
    assert fake.last_user_text is not None
    assert len(fake.last_user_text) <= 32


def test_lazy_client_never_imports_boto3_until_called():
    # Constructing the screen with no injected client must not create a boto3
    # client (or hit AWS); only a call would. Building is enough here.
    screen = BedrockClassifierScreen(BedrockClassifierParams(model_id=_MODEL_ID))
    assert screen._client is None


def test_screen_error_logs_type_name_only(caplog):
    envelope = _envelope(payload={"message": _SENTINEL})
    screen = _screen(_response([{"text": "prose, no tool call"}]))
    logger_name = "safe_agents.channels.screens.bedrock_classifier"
    with caplog.at_level(logging.WARNING, logger=logger_name), pytest.raises(ValueError):
        screen(envelope)

    lines = [r.getMessage() for r in caplog.records if r.name == logger_name]
    assert len(lines) == 1
    # Structured line carries the exception TYPE only — no message, no content.
    assert '"event": "screen_error"' in lines[0]
    assert '"error": "ValueError"' in lines[0]
    assert _SENTINEL not in lines[0]


# --- End-to-end through the dispatcher --------------------------------------


def _dispatch_with(screen, *, identity: str, payload: dict, verdicts=None, drops=None):
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
        payload=payload,
    )
    return (
        dispatch(
            "request",
            adapter=StubInboundAdapter(identity=identity, envelope=envelope),
            trust_map=_trust_map_for(identity),
            screen=screen,
            verdicts=verdicts,
            dedupe_store=set(),
            drops=drops if drops is not None else [],
            now=_NOW,
            zone="test-zone",
        ),
        envelope,
    )


def test_dispatch_refusing_screen_drops_and_does_not_emit():
    drops = []
    result, _ = _dispatch_with(
        _screen(_verdict_response(True)),
        identity="chat:bedrock-refuse",
        payload={"message": _SENTINEL},
        drops=drops,
    )
    assert result is None
    assert len(drops) == 1
    assert drops[0].reason == "screen_refused"
    assert drops[0].detail == INJECTION_SUSPECTED


def test_dispatch_raising_screen_fails_closed_as_screen_error():
    screen = BedrockClassifierScreen(
        BedrockClassifierParams(model_id=_MODEL_ID), client=_RaisingConverse()
    )
    drops = []
    result, _ = _dispatch_with(
        screen, identity="chat:bedrock-boom", payload={"k": "v"}, drops=drops
    )
    assert result is None
    assert len(drops) == 1
    assert drops[0].reason == "screen_refused"
    assert drops[0].detail == SCREEN_ERROR


def test_dispatch_passing_screen_emits_envelope_unchanged():
    payload = {"message": "an ordinary, benign notification"}
    result, envelope = _dispatch_with(
        _screen(_verdict_response(False)), identity="chat:bedrock-pass", payload=payload
    )
    assert result is not None
    # The screen never mutates content: the emitted payload is byte-for-byte the input.
    assert result.payload == payload == envelope.payload


# --- Registry resolution ----------------------------------------------------


def test_build_airlock_resolves_bedrock_kind_after_lazy_import():
    manifest = ChannelsManifest(
        screen=ScreenConfig(kind="bedrock_classifier", params={"model_id": _MODEL_ID})
    )
    rt = build_airlock(manifest, token=_TOKEN)
    assert isinstance(rt.screen, BedrockClassifierScreen)
    # Lazy construction: nothing hit AWS — the client seam is still unopened.
    assert rt.screen._client is None


def test_build_airlock_bedrock_missing_model_id_raises_validation_error():
    manifest = ChannelsManifest(screen=ScreenConfig(kind="bedrock_classifier", params={}))
    with pytest.raises(ValidationError):
        build_airlock(manifest, token=_TOKEN)


# --- Verdict sink -----------------------------------------------------------


def test_verdict_sink_records_one_per_invocation_pass_and_refuse():
    passing_verdicts = []
    result, _ = _dispatch_with(
        _screen(_verdict_response(False)),
        identity="chat:bedrock-sink-pass",
        payload={"k": "v"},
        verdicts=passing_verdicts,
    )
    assert result is not None
    assert len(passing_verdicts) == 1
    assert passing_verdicts[0].passed is True
    assert passing_verdicts[0].reason is None
    assert passing_verdicts[0].identity_digest == _digest("chat:bedrock-sink-pass")

    refusing_verdicts = []
    result2, _ = _dispatch_with(
        _screen(_verdict_response(True)),
        identity="chat:bedrock-sink-refuse",
        payload={"k": "v"},
        verdicts=refusing_verdicts,
    )
    assert result2 is None
    assert len(refusing_verdicts) == 1
    assert refusing_verdicts[0].passed is False
    assert refusing_verdicts[0].reason == INJECTION_SUSPECTED
