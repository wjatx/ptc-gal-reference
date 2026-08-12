"""sa#58 — the reference Bedrock evidence reviewer + its ceremony/commands wiring.

The reviewer is reference-tier (docs/contract-vs-reference.md); the normative
seam is CheckerProtocol in grants/ceremony.py (findings-attach-NEVER-gate).
These tests prove the one concrete reviewer with a fake Converse client, never
touching AWS, mirroring channels/tests/test_bedrock_screen.py.

Coverage:
- Build-time config: missing/unknown params raise ValidationError; a same
  model family as the maker (bare id, region-prefixed, case-insensitive) is
  structurally unbuildable (ReviewerConfigError); empty maker family and an
  unparseable model id also refuse at build time; model_family() parses the
  Bedrock id grammar (bare, geo-prefixed, ARN, lowercased).
- Verdict mapping is deterministic and closed-vocabulary: [] -> the
  contentless no_concerns verdict; codes -> sorted, deduped, comma-joined with
  suspicion raised; ANY off-contract tool input or response shape raises
  ValueError whose text never echoes evidence or tool-input values.
- The request pins the forcing: configured modelId, toolChoice forces the
  findings tool, temperature 0.0, content truncated to max_chars, and the
  system prompt marks the bundle as untrusted data.
- Ceremony seam backstop: a RAISING reviewer degrades to a recorded
  reviewer_error:<Type> finding (suspicious) — the gate outcome is unchanged
  (never a gate flip in either direction); a real reviewer's suspicious codes
  land in the signed predicate text. (A favorable verdict cannot license —
  already proved by test_grants_ceremony.test_predicate_fail_blocks_promotion,
  not duplicated here.)
- _resolve_reviewer: unset/blank env -> None (the shipping default); unknown
  kind, bad JSON, non-object JSON, and invalid params (incl. same-family) all
  refuse loudly with RunnerConfigError; a valid different-family config
  returns the reviewer with the client seam unopened.
"""

import json

import pytest
from pydantic import ValidationError

from safe_agents.broker.grants import commands
from safe_agents.broker.grants.ceremony import CheckerVerdict
from safe_agents.broker.grants.reviewers.bedrock_reviewer import (
    CONCERN_CODES,
    KIND,
    NO_CONCERNS,
    BedrockEvidenceReviewer,
    BedrockReviewerParams,
    ReviewerConfigError,
    build,
    model_family,
)
from safe_agents.broker.grants.runner import RunnerConfigError
from safe_agents.broker.tests.test_grants_ceremony import (
    PASSING_METRICS,
    _make_ceremony,
    _make_proposal,
    _seed_grant,
)

# The maker's family and a reviewer from a DIFFERENT family (sa#58 rule).
_MAKER_FAMILY = "anthropic"
_REVIEWER_MODEL_ID = "us.amazon.nova-pro-v1:0"
# A distinctive string placed in evidence/tool input; no exception, record, or
# predicate text may echo it.
_SENTINEL = "SENTINEL_EVIDENCE_do_not_leak_7c1e"


# --- Converse response builders (tool-use shaped) ---------------------------


def _response(content_blocks: list) -> dict:
    return {"output": {"message": {"role": "assistant", "content": content_blocks}}}


def _tool_block(*, name: str = "findings", tool_input) -> dict:
    return {"toolUse": {"toolUseId": "tu-1", "name": name, "input": tool_input}}


def _concerns_response(concerns: list) -> dict:
    return _response([_tool_block(tool_input={"concerns": concerns})])


class _FakeConverse:
    """A stand-in bedrock-runtime client: records the request, returns a canned response."""

    def __init__(self, response: dict) -> None:
        self._response = response
        self.last_kwargs: dict | None = None
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        self.last_kwargs = kwargs
        return self._response


class _RaisingConverse:
    """A client whose Converse call fails — exercises the ceremony's seam backstop."""

    def converse(self, **kwargs):
        raise RuntimeError(f"bedrock unavailable while reviewing {_SENTINEL}")


def _params(**overrides) -> BedrockReviewerParams:
    kwargs = dict(model_id=_REVIEWER_MODEL_ID, maker_model_family=_MAKER_FAMILY)
    kwargs.update(overrides)
    return BedrockReviewerParams(**kwargs)


def _reviewer(response: dict, **param_overrides) -> BedrockEvidenceReviewer:
    return BedrockEvidenceReviewer(_params(**param_overrides), client=_FakeConverse(response))


# --- Build-time config: params validation ------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"maker_model_family": _MAKER_FAMILY},  # missing model_id
        {"model_id": _REVIEWER_MODEL_ID},  # missing maker_model_family
        {  # unknown extra key: extra="forbid"
            "model_id": _REVIEWER_MODEL_ID,
            "maker_model_family": _MAKER_FAMILY,
            "unknown_key": 1,
        },
    ],
    ids=["empty", "missing-model-id", "missing-maker-family", "extra-key"],
)
def test_build_invalid_params_block_raises_validation_error(params):
    """A params block missing a required field or carrying an unknown key
    fails at build time — never at first review."""
    with pytest.raises(ValidationError):
        build(params)


@pytest.mark.parametrize(
    "model_id, maker_family",
    [
        ("anthropic.claude-x-v1:0", "anthropic"),  # bare model id
        ("us.anthropic.claude-x-v1:0", "anthropic"),  # region-prefixed profile id
        ("us.anthropic.claude-x-v1:0", "Anthropic"),  # case-insensitive
    ],
    ids=["bare", "region-prefixed", "case-insensitive"],
)
def test_same_model_family_is_structurally_unbuildable(model_id, maker_family):
    """The reviewer must come from a DIFFERENT family than the maker (sa#58):
    a same-family pair raises ReviewerConfigError at construction."""
    with pytest.raises(ReviewerConfigError, match="family"):
        build({"model_id": model_id, "maker_model_family": maker_family})


@pytest.mark.parametrize("maker_family", ["", "   "], ids=["empty", "whitespace"])
def test_empty_maker_family_raises(maker_family):
    """An empty maker family would make the family check vacuous — refused."""
    with pytest.raises(ReviewerConfigError, match="non-empty"):
        build({"model_id": _REVIEWER_MODEL_ID, "maker_model_family": maker_family})


@pytest.mark.parametrize("model_id", ["claude", ""], ids=["no-family-segment", "empty"])
def test_unparseable_model_id_raises(model_id):
    """An id outside the '<family>.<model>' grammar must fail at build time,
    not degrade into a vacuous family check."""
    with pytest.raises(ReviewerConfigError, match="cannot parse"):
        build({"model_id": model_id, "maker_model_family": _MAKER_FAMILY})


def test_different_family_builds_with_client_seam_unopened():
    """A cross-family config builds; nothing touches boto3/AWS until a call."""
    reviewer = build(
        {"model_id": _REVIEWER_MODEL_ID, "maker_model_family": _MAKER_FAMILY}
    )
    assert isinstance(reviewer, BedrockEvidenceReviewer)
    assert reviewer._client is None


@pytest.mark.parametrize(
    "model_id, family",
    [
        ("anthropic.claude-x-v1:0", "anthropic"),
        ("us.anthropic.claude-x-v1:0", "anthropic"),
        ("eu.anthropic.claude-x-v1:0", "anthropic"),
        ("apac.amazon.nova-lite-v1:0", "amazon"),
        (
            "arn:aws:bedrock:us-east-1:123456789012:inference-profile/"
            "us.anthropic.claude-x-v1:0",
            "anthropic",
        ),
        ("Anthropic.Claude-X-v1:0", "anthropic"),  # lowercased
    ],
    ids=["bare", "us-prefix", "eu-prefix", "apac-prefix", "arn", "lowercasing"],
)
def test_model_family_parses_bedrock_id_grammar(model_id, family):
    assert model_family(model_id) == family


# --- Deterministic verdict mapping -------------------------------------------


def test_empty_concerns_is_the_contentless_no_concerns_verdict():
    """[] maps to no_concerns with NO suspicion — a pass never blesses."""
    verdict = _reviewer(_concerns_response([])).check("evidence-ref", {})
    assert verdict == CheckerVerdict(findings=NO_CONCERNS, suspicious=False)


@pytest.mark.parametrize(
    "concerns, findings",
    [
        (["insufficient_window"], "insufficient_window"),
        (  # multiple codes: sorted, comma-joined
            ["metric_inconsistency", "distribution_anomaly"],
            "distribution_anomaly,metric_inconsistency",
        ),
        (  # duplicates deduped
            ["insufficient_window", "insufficient_window"],
            "insufficient_window",
        ),
    ],
    ids=["one-code", "sorted-multi", "deduped"],
)
def test_concern_codes_map_to_sorted_deduped_findings_with_suspicion(concerns, findings):
    verdict = _reviewer(_concerns_response(concerns)).check("evidence-ref", {})
    assert verdict == CheckerVerdict(findings=findings, suspicious=True)


@pytest.mark.parametrize(
    "tool_input",
    [
        {"concerns": [_SENTINEL]},  # code outside the closed vocabulary
        {"concerns": [42]},  # non-string in the list
        {"concerns": [], "note": _SENTINEL},  # extra keys
        {},  # missing "concerns"
        {"concerns": "insufficient_window"},  # non-list concerns
    ],
    ids=["unknown-code", "non-string", "extra-key", "missing-concerns", "non-list"],
)
def test_off_contract_tool_input_raises_without_leaking_values(tool_input):
    """Anything but exactly {"concerns": [<known codes>]} raises; the message
    carries only shape facts — never a tool-input value (the predicate text it
    could otherwise reach is a trusted, signed surface)."""
    reviewer = _reviewer(_response([_tool_block(tool_input=tool_input)]))
    with pytest.raises(ValueError) as exc_info:
        reviewer.check(_SENTINEL, {"detail": _SENTINEL})
    assert _SENTINEL not in str(exc_info.value)


@pytest.mark.parametrize(
    "content_blocks",
    [
        [],  # zero tool-use blocks
        [  # two tool-use blocks
            _tool_block(tool_input={"concerns": []}),
            _tool_block(tool_input={"concerns": []}),
        ],
        [_tool_block(name="verdict", tool_input={"concerns": []})],  # wrong tool name
        [{"text": _SENTINEL}],  # text-only response
    ],
    ids=["zero-tool-uses", "two-tool-uses", "wrong-tool-name", "text-only"],
)
def test_malformed_response_shape_raises_without_leaking_content(content_blocks):
    reviewer = _reviewer(_response(content_blocks))
    with pytest.raises(ValueError) as exc_info:
        reviewer.check(_SENTINEL, {})
    assert _SENTINEL not in str(exc_info.value)


@pytest.mark.parametrize(
    "response",
    [
        {"unexpected": "shape"},
        {"output": {"message": {"content": "not-a-block-list"}}},
    ],
    ids=["not-converse", "content-not-a-list"],
)
def test_non_converse_shape_raises(response):
    with pytest.raises(ValueError) as exc_info:
        _reviewer(response).check(_SENTINEL, {})
    assert _SENTINEL not in str(exc_info.value)


# --- Request assertions: the forcing, not just the response handling ---------


def test_request_pins_model_forced_findings_tool_and_zero_temperature():
    fake = _FakeConverse(_concerns_response([]))
    BedrockEvidenceReviewer(_params(), client=fake).check("evidence-ref", {"k": "v"})

    kwargs = fake.last_kwargs
    assert kwargs is not None
    assert kwargs["modelId"] == _REVIEWER_MODEL_ID
    assert kwargs["inferenceConfig"]["temperature"] == 0.0
    # toolChoice must FORCE `findings` — the model cannot answer in prose.
    tool_config = kwargs["toolConfig"]
    assert tool_config["toolChoice"] == {"tool": {"name": "findings"}}
    tools = tool_config["tools"]
    assert len(tools) == 1
    spec = tools[0]["toolSpec"]
    assert spec["name"] == "findings"
    schema = spec["inputSchema"]["json"]
    assert schema["required"] == ["concerns"]
    assert schema["properties"]["concerns"]["items"]["enum"] == list(CONCERN_CODES)
    assert schema["additionalProperties"] is False


def test_evidence_content_is_truncated_to_max_chars():
    fake = _FakeConverse(_concerns_response([]))
    reviewer = BedrockEvidenceReviewer(_params(max_chars=32), client=fake)
    reviewer.check("x" * 1000, {"context": "y" * 1000})
    user_text = fake.last_kwargs["messages"][0]["content"][0]["text"]
    assert len(user_text) <= 32


def test_system_prompt_marks_the_bundle_as_untrusted_data():
    fake = _FakeConverse(_concerns_response([]))
    BedrockEvidenceReviewer(_params(), client=fake).check("evidence-ref", {})
    assert "UNTRUSTED DATA" in fake.last_kwargs["system"][0]["text"]


# --- Ceremony seam backstop: reviewer failure is a finding, never a gate flip


class _RaisingChecker:
    """A checker whose check() raises — the ceremony must degrade, not abort."""

    def __init__(self) -> None:
        self.call_count = 0

    def check(self, evidence_bundle: str, context: dict) -> CheckerVerdict:
        self.call_count += 1
        raise RuntimeError(f"reviewer infrastructure down: {_SENTINEL}")


def test_raising_checker_degrades_to_recorded_finding_never_a_gate_flip():
    """A raising reviewer must not abort the ceremony (a de-facto veto): the
    failure is recorded as reviewer_error:<Type> with suspicion raised, the
    gate outcome is unchanged, and only the exception TYPE — never its message
    — reaches the signed predicate text."""
    checker = _RaisingChecker()
    ceremony, grant_store, record_store = _make_ceremony(checker=checker)
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)

    result = ceremony.execute(proposal, ratifier_id="checker-model-id")

    assert result.status == "ratified"
    assert checker.call_count == 1
    assert result.checker_verdict == CheckerVerdict(
        findings="reviewer_error:RuntimeError", suspicious=True
    )
    predicate = record_store.records[0].predicate
    assert "[suspicion raised]" in predicate
    assert "reviewer_error:RuntimeError" in predicate
    assert _SENTINEL not in predicate


def test_bedrock_reviewer_failure_degrades_end_to_end():
    """The real reviewer wired into the ceremony with a failing Converse
    client: the RuntimeError propagates out of check() and the seam backstop
    records it — ratified, reviewer_error:RuntimeError, no content leak."""
    reviewer = BedrockEvidenceReviewer(_params(), client=_RaisingConverse())
    ceremony, grant_store, record_store = _make_ceremony(checker=reviewer)
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)

    result = ceremony.execute(proposal, ratifier_id="checker-model-id")

    assert result.status == "ratified"
    assert result.checker_verdict == CheckerVerdict(
        findings="reviewer_error:RuntimeError", suspicious=True
    )
    assert _SENTINEL not in record_store.records[0].predicate


def test_bedrock_reviewer_suspicious_codes_reach_the_record_end_to_end():
    """The real reviewer's closed-vocabulary codes land in the record's
    predicate text with suspicion raised — recorded, never gated on."""
    reviewer = _reviewer(_concerns_response(["evidence_grooming_suspected"]))
    ceremony, grant_store, record_store = _make_ceremony(checker=reviewer)
    _seed_grant(grant_store)
    proposal = _make_proposal(metrics=PASSING_METRICS)

    result = ceremony.execute(proposal, ratifier_id="checker-model-id")

    assert result.status == "ratified"
    assert result.checker_verdict == CheckerVerdict(
        findings="evidence_grooming_suspected", suspicious=True
    )
    predicate = record_store.records[0].predicate
    assert "[suspicion raised]" in predicate
    assert "evidence_grooming_suspected" in predicate


# --- _resolve_reviewer: env-selected from the CLOSED catalog ------------------


_VALID_PARAMS_JSON = json.dumps(
    {"model_id": _REVIEWER_MODEL_ID, "maker_model_family": _MAKER_FAMILY}
)


def _set_reviewer_env(monkeypatch, kind: str | None, params: str | None = None) -> None:
    for env, value in (
        (commands.REVIEWER_KIND_ENV, kind),
        (commands.REVIEWER_PARAMS_ENV, params),
    ):
        if value is None:
            monkeypatch.delenv(env, raising=False)
        else:
            monkeypatch.setenv(env, value)


@pytest.mark.parametrize("kind", [None, "", "   "], ids=["unset", "empty", "whitespace"])
def test_resolve_reviewer_off_by_default(monkeypatch, kind):
    """Unset/blank GRANTS_REVIEWER_KIND is the shipping default: checker None,
    byte-for-byte the reviewer-less ceremony."""
    _set_reviewer_env(monkeypatch, kind)
    assert commands._resolve_reviewer() is None


def test_resolve_reviewer_unknown_kind_names_the_closed_catalog(monkeypatch):
    """An unknown kind refuses loudly, naming the closed catalog — config
    selects, it never names code."""
    _set_reviewer_env(monkeypatch, "no_such_reviewer")
    with pytest.raises(RunnerConfigError) as exc_info:
        commands._resolve_reviewer()
    assert KIND in str(exc_info.value)


@pytest.mark.parametrize(
    "params_json, fragment",
    [
        ("not json{", "not valid JSON"),
        ('["a-list"]', "JSON object"),
        ("{}", "invalid for kind"),  # valid JSON object, invalid params
        (  # same family as the maker: the sa#58 conformance rule at wiring level
            json.dumps(
                {"model_id": "us.anthropic.claude-x-v1:0", "maker_model_family": "anthropic"}
            ),
            "invalid for kind",
        ),
    ],
    ids=["bad-json", "json-list", "missing-fields", "same-family"],
)
def test_resolve_reviewer_bad_params_raise_runner_config_error(
    monkeypatch, params_json, fragment
):
    """A misconfigured reviewer must fail at startup (config error != runtime
    failure) — every bad-params shape maps onto RunnerConfigError."""
    _set_reviewer_env(monkeypatch, KIND, params_json)
    with pytest.raises(RunnerConfigError, match=fragment):
        commands._resolve_reviewer()


def test_resolve_reviewer_valid_config_returns_reviewer_lazily(monkeypatch):
    """A valid different-family config resolves to the Bedrock reviewer with
    the client seam still unopened (no boto3, no AWS)."""
    _set_reviewer_env(monkeypatch, KIND, _VALID_PARAMS_JSON)
    reviewer = commands._resolve_reviewer()
    assert isinstance(reviewer, BedrockEvidenceReviewer)
    assert reviewer._client is None
