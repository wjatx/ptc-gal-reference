"""#205 — unit tests for the config-assert comparison/refusal core.

The live binding (``test_airlock_config_live.py``) stays opt-in; these prove the
pure logic: refuse-on-unnamed-expectation, actual-vs-expected mismatch reporting,
and the end-to-end shape against a mocked lambda client.
"""

from __future__ import annotations

import pytest

from safe_agents.channels.config_assert import (
    ABSENT,
    EXPECT_ABSENT,
    ConfigAssertRefusal,
    Mismatch,
    compare_env,
    format_mismatches,
    require_expectation,
)


class TestRequireExpectation:
    def test_returns_declared_value(self):
        env = {"AIRLOCK_EXPECTED_MANIFEST": "agents/owner-example.yaml"}
        assert (
            require_expectation("AIRLOCK_EXPECTED_MANIFEST", environ=env)
            == "agents/owner-example.yaml"
        )

    @pytest.mark.parametrize("env", [{}, {"AIRLOCK_EXPECTED_MANIFEST": ""}, {"AIRLOCK_EXPECTED_MANIFEST": "   "}])
    def test_unset_or_empty_refuses(self, env):
        with pytest.raises(ConfigAssertRefusal) as exc:
            require_expectation("AIRLOCK_EXPECTED_MANIFEST", environ=env)
        # The refusal names the var and tells the operator what to do.
        assert "AIRLOCK_EXPECTED_MANIFEST" in str(exc.value)
        assert "refusing" in str(exc.value)

    def test_absent_sentinel_is_a_declared_value(self):
        # "@absent" is an explicit declaration, not an unset expectation.
        env = {"AIRLOCK_EXPECTED_MANIFEST": EXPECT_ABSENT}
        assert require_expectation("AIRLOCK_EXPECTED_MANIFEST", environ=env) == EXPECT_ABSENT


class TestCompareEnv:
    EXPECTED = {
        "CHANNELS_MANIFEST": "agents/owner-example.yaml",
        "CHANNELS_DEDUPE_TABLE": "safe-agents-development-channel-dedupe",
    }

    def test_exact_match_is_clean(self):
        actual = dict(self.EXPECTED, EXTRA_KEY="ignored")
        assert compare_env(actual, self.EXPECTED) == []

    def test_wrong_value_reports_actual_vs_expected(self):
        actual = dict(self.EXPECTED, CHANNELS_MANIFEST="agents/webhook-peer.yaml")
        mismatches = compare_env(actual, self.EXPECTED)
        assert mismatches == [
            Mismatch(
                key="CHANNELS_MANIFEST",
                expected="agents/owner-example.yaml",
                actual="agents/webhook-peer.yaml",
            )
        ]

    def test_missing_key_reports_absent(self):
        actual = {"CHANNELS_MANIFEST": self.EXPECTED["CHANNELS_MANIFEST"]}
        mismatches = compare_env(actual, self.EXPECTED)
        assert mismatches == [
            Mismatch(
                key="CHANNELS_DEDUPE_TABLE",
                expected="safe-agents-development-channel-dedupe",
                actual=ABSENT,
            )
        ]

    def test_multiple_mismatches_sorted_by_key(self):
        mismatches = compare_env({}, self.EXPECTED)
        assert [m.key for m in mismatches] == [
            "CHANNELS_DEDUPE_TABLE",
            "CHANNELS_MANIFEST",
        ]

    def test_empty_string_differs_from_absent(self):
        mismatches = compare_env({"CHANNELS_MANIFEST": ""}, {"CHANNELS_MANIFEST": "x"})
        assert mismatches[0].actual == ""

    def test_absent_sentinel_passes_when_key_absent(self):
        # A deliberately-manifestless deploy: expectation @absent, env has no key.
        assert compare_env({"OTHER": "x"}, {"CHANNELS_MANIFEST": EXPECT_ABSENT}) == []

    def test_absent_sentinel_fails_when_key_present(self):
        mismatches = compare_env(
            {"CHANNELS_MANIFEST": "agents/owner-example.yaml"},
            {"CHANNELS_MANIFEST": EXPECT_ABSENT},
        )
        assert mismatches == [
            Mismatch(
                key="CHANNELS_MANIFEST",
                expected=EXPECT_ABSENT,
                actual="agents/owner-example.yaml",
            )
        ]

    def test_absent_sentinel_fails_even_on_empty_present_value(self):
        # Present-but-empty is still present — the sentinel demands genuine absence.
        mismatches = compare_env({"CHANNELS_MANIFEST": ""}, {"CHANNELS_MANIFEST": EXPECT_ABSENT})
        assert mismatches == [
            Mismatch(key="CHANNELS_MANIFEST", expected=EXPECT_ABSENT, actual="")
        ]


class TestFormatMismatches:
    def test_operator_debuggable_output(self):
        text = format_mismatches(
            "safe-agents-development-airlock",
            [Mismatch(key="CHANNELS_MANIFEST", expected="a.yaml", actual=ABSENT)],
        )
        assert "safe-agents-development-airlock" in text
        assert "CHANNELS_MANIFEST" in text
        assert "expected='a.yaml'" in text
        assert "actual='<absent>'" in text


class _FakeLambda:
    """Mocked lambda client: GetFunctionConfiguration shape only."""

    def __init__(self, envs: dict[str, dict[str, str]]):
        self._envs = envs

    def get_function_configuration(self, FunctionName: str):
        return {"Environment": {"Variables": self._envs[FunctionName]}}


class TestEndToEndShape:
    """The live test's flow, exercised against a mocked client + exports map."""

    FN = "safe-agents-development-airlock"

    def _run(self, deployed_env: dict[str, str], expected: dict[str, str]):
        lam = _FakeLambda({self.FN: deployed_env})
        actual = lam.get_function_configuration(FunctionName=self.FN)["Environment"]["Variables"]
        return compare_env(actual, expected)

    def test_matching_deploy_passes(self):
        expected = {
            "CHANNELS_MANIFEST": "agents/owner-example.yaml",
            "CHANNELS_ACCEPTED_QUEUE_URL": "https://sqs/q",
            "CHANNELS_WEBHOOK_SECRET_ARN": "arn:aws:secretsmanager:...:secret:x",
        }
        assert self._run(dict(expected), expected) == []

    def test_improvised_manifest_is_caught(self):
        """The retro scenario: a deploy shipped a different manifest path."""
        expected = {"CHANNELS_MANIFEST": "agents/owner-example.yaml"}
        deployed = {"CHANNELS_MANIFEST": "agents/example.yaml"}
        mismatches = self._run(deployed, expected)
        assert len(mismatches) == 1
        assert "agents/example.yaml" in format_mismatches(self.FN, mismatches)
