"""Tests for reliability.loud_failure — assert_artifact and require_evidence.

Both directions (pass and fail) are verified. Data-driven where it reads well.
"""

import json

import pytest

from reliability.loud_failure import assert_artifact, require_evidence


# ------------------------------------------------------------------
# assert_artifact — data-driven pass/fail
# ------------------------------------------------------------------

ASSERT_CASES = [
    # (predicate,        label,                     should_pass)
    (True,               "audit row written",        True),
    (False,              "audit row written",        False),
    (lambda: True,       "bucket reachable",         True),
    (lambda: False,      "bucket reachable",         False),
]


@pytest.mark.parametrize("predicate, label, should_pass", ASSERT_CASES)
def test_assert_artifact_pass_and_fail(predicate, label, should_pass, capsys):
    if should_pass:
        assert_artifact(predicate, label)  # must return normally
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""
    else:
        with pytest.raises(SystemExit) as exc_info:
            assert_artifact(predicate, label)
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        record = json.loads(captured.err.strip())
        assert record["invariant"] == label
        assert record["level"] == "ERROR"
        assert "observed" in record
        assert "component" in record
        assert "ts" in record


def test_assert_artifact_failure_is_single_json_line(capsys):
    """Failure output must be exactly one parseable JSON line (machine-parseable)."""
    with pytest.raises(SystemExit):
        assert_artifact(False, "S3 audit bucket reachable")

    captured = capsys.readouterr()
    lines = [ln for ln in captured.err.splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected 1 JSON line, got {len(lines)}"
    record = json.loads(lines[0])
    assert set(record.keys()) >= {"level", "invariant", "observed", "component", "ts"}


def test_assert_artifact_custom_component(capsys):
    with pytest.raises(SystemExit):
        assert_artifact(False, "grant table locked", component="broker.pdp")

    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    assert record["component"] == "broker.pdp"


def test_assert_artifact_custom_observed(capsys):
    with pytest.raises(SystemExit):
        assert_artifact(False, "row count > 0", observed="got 0 rows from DynamoDB scan")

    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    assert record["observed"] == "got 0 rows from DynamoDB scan"


def test_assert_artifact_ts_is_iso8601(capsys):
    """Timestamp in the failure record must be a valid UTC ISO-8601 string."""
    import datetime

    with pytest.raises(SystemExit):
        assert_artifact(False, "ts format check")

    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    # fromisoformat accepts "+00:00" suffix (Python 3.7+)
    ts = datetime.datetime.fromisoformat(record["ts"])
    assert ts.tzinfo is not None


# ------------------------------------------------------------------
# require_evidence decorator
# ------------------------------------------------------------------

def test_require_evidence_passes_truthy():
    @require_evidence("check returned non-empty list")
    def good_check():
        return ["item1", "item2"]

    result = good_check()
    assert result == ["item1", "item2"]


def test_require_evidence_fails_falsy(capsys):
    @require_evidence("check returned non-empty list")
    def empty_check():
        return []

    with pytest.raises(SystemExit) as exc_info:
        empty_check()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    assert record["invariant"] == "check returned non-empty list"
    assert "empty_check" in record["component"]


def test_require_evidence_fails_none(capsys):
    @require_evidence("row written")
    def returns_none():
        return None

    with pytest.raises(SystemExit):
        returns_none()


def test_require_evidence_uses_fn_qualname_as_component(capsys):
    @require_evidence("some invariant")
    def my_check():
        return False

    with pytest.raises(SystemExit):
        my_check()

    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    assert "my_check" in record["component"]


def test_require_evidence_custom_component(capsys):
    @require_evidence("bucket reachable", component="audit.verifier")
    def check():
        return None

    with pytest.raises(SystemExit):
        check()

    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    assert record["component"] == "audit.verifier"


def test_require_evidence_preserves_return_value():
    @require_evidence("S3 bucket has objects")
    def check():
        return {"Count": 5, "Keys": ["a", "b"]}

    result = check()
    assert result["Count"] == 5


def test_require_evidence_preserves_function_name():
    @require_evidence("some label")
    def my_named_fn():
        return True

    assert my_named_fn.__name__ == "my_named_fn"
