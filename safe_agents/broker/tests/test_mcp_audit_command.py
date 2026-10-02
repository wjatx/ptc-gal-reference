"""The audit door, over a store that holds admitted MCP tools.

`python -m safe_agents.broker.grants.audit_command --sqlite PATH` is the one
auditor a local operator can run. These tests cover what it says about the MCP
registry: the counts, the exit code, and what it admits it did not check.

The case this file exists for is a store with admitted tools and no grants.
Before the registry rode this door, that store printed zero violations over
zero grants and exited 0, which was accurate and covered none of the items the
deployment depends on.
"""

from __future__ import annotations

import json

import pytest

from safe_agents.broker.grants.audit import AuditReport
from safe_agents.broker.grants.audit_command import (
    ANNOTATION_MCP_NOT_AUDITED,
    EXIT_CLEAN,
    EXIT_NOT_RUN,
    EXIT_VIOLATIONS,
    AuditTarget,
    main,
    render_text,
    report_to_dict,
    run_store_audit,
)
from safe_agents.broker.mcp.audit import (
    HMAC_RULES,
    ORPHAN_ROW,
    RECORD_SIGNATURE_VERIFIES,
    ROW_HMAC_INTACT,
    SIGNATURE_RULES,
)
from safe_agents.broker.mcp.proposals import KIND_ADMISSION
from safe_agents.broker.tests.test_grants_audit_command import _seed_clean
from safe_agents.broker.tests import mcp_audit_store as edits
from safe_agents.broker.tests.mcp_audit_store import (
    HISTORY,
    HMAC_KEY,
    ISSUER_KEY_ID,
    QUOTE,
    SERVER_ID,
    Tamper,
    admit,
    build_honest_store,
    make_issuer,
)

_KEY_ENV = (
    "BROKER_HMAC_KEY",
    "ISSUER_VERIFY_KEYS_PARAM",
    "ISSUER_VERIFY_KEYS_FILE",
    "EVALUATOR_VERIFY_KEYS_PARAM",
    "EVALUATOR_VERIFY_KEYS_FILE",
    "RECORD_SIGNING_EPOCH",
)


@pytest.fixture(autouse=True)
def _no_ambient_key_material(monkeypatch):
    """Every test names its own mode; a developer's shell must not pick it."""
    for name in _KEY_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def issuer():
    return make_issuer()


@pytest.fixture
def db_path(tmp_path, monkeypatch, issuer):
    path = tmp_path / "broker.db"
    build_honest_store(path, monkeypatch, tmp_path, issuer.signer)
    return path


@pytest.fixture
def keyed(tmp_path, monkeypatch, issuer):
    """The local operator's keyed mode: the HMAC key and a verify-keys FILE."""
    keys_file = tmp_path / "issuer-verify-keys.json"
    keys_file.write_text(json.dumps({ISSUER_KEY_ID: issuer.public_pem}), encoding="utf-8")
    monkeypatch.setenv("BROKER_HMAC_KEY", HMAC_KEY.decode())
    monkeypatch.setenv("ISSUER_VERIFY_KEYS_FILE", str(keys_file))
    return keys_file


def _json(db_path, capsys) -> tuple[int, dict]:
    code = main(["--sqlite", str(db_path), "--json"])
    return code, json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# The three store shapes
# ---------------------------------------------------------------------------


def test_clean_store_exits_zero_and_reports_what_it_examined(db_path, keyed, capsys):
    assert main(["--sqlite", str(db_path)]) == EXIT_CLEAN
    out = capsys.readouterr().out

    assert "mcp registry examined: 2 rows, 3 admission records, 3 proposals" in out
    assert "0 violations" in out
    # Keyed on both counts, so the registry's rules all ran.
    assert "MCP_" not in out


def test_a_finding_exits_one_and_names_the_rule(db_path, keyed, issuer, capsys):
    edits.row_hmac_replaced(Tamper(db_path, issuer))

    assert main(["--sqlite", str(db_path)]) == EXIT_VIOLATIONS
    out = capsys.readouterr().out

    assert f"VIOLATION [{ROW_HMAC_INTACT}] {SERVER_ID}/{HISTORY}" in out
    assert "1 violations" in out


def test_admitted_tools_and_zero_grants_is_not_a_bare_clean(db_path, keyed, capsys):
    """The #143 shape. The store holds no grant at all, and the report has to
    show that the result covers the registry items rather than nothing."""
    assert main(["--sqlite", str(db_path)]) == EXIT_CLEAN
    out = capsys.readouterr().out

    assert "grants examined: 0 grants, 0 records, 0 proposals, 0 envelopes" in out
    assert "mcp registry examined: 2 rows, 3 admission records, 3 proposals" in out

    code, payload = _json(db_path, capsys)
    assert code == EXIT_CLEAN
    assert payload["clean"] is True
    assert payload["examined"] == {
        "grants": 0,
        "records": 0,
        "proposals": 0,
        "envelopes": 0,
        "mcp_rows": 2,
        "mcp_records": 3,
        "mcp_proposals": 3,
    }


def test_a_planted_orphan_row_turns_a_tools_only_store_red(db_path, keyed, issuer, capsys):
    """#143's own done criterion: red, and with no MCP rule skipped."""
    edits.all_records_erased(Tamper(db_path, issuer))

    code, payload = _json(db_path, capsys)

    assert code == EXIT_VIOLATIONS
    assert payload["clean"] is False
    assert [v["rule"] for v in payload["violations"]] == [ORPHAN_ROW]
    assert not [rule for rule in payload["skipped_rules"] if rule.startswith("MCP_")]


def test_grants_and_registry_are_audited_from_the_same_file(db_path, capsys):
    """One run, one read, both halves counted. Keyless, because the grants
    fixture store and this one are seeded under different HMAC keys."""
    _seed_clean(db_path)

    code, payload = _json(db_path, capsys)

    assert code == EXIT_CLEAN
    assert payload["violations"] == []
    assert payload["examined"]["grants"] == 1
    assert payload["examined"]["records"] == 1
    assert payload["examined"]["mcp_rows"] == 2
    assert payload["examined"]["mcp_records"] == 3


# ---------------------------------------------------------------------------
# Mode: keyless is loud, keyed comes from the environment, bad keys refuse
# ---------------------------------------------------------------------------


def test_keyless_run_prints_the_registry_rules_it_skipped(db_path, capsys):
    assert main(["--sqlite", str(db_path)]) == EXIT_CLEAN
    out = capsys.readouterr().out

    skipped_line = next(line for line in out.splitlines() if "SKIPPED (not run, not passed)" in line)
    for rule in (*HMAC_RULES, *SIGNATURE_RULES):
        assert rule in skipped_line
    assert "NOTE: mcp-record-signatures-unchecked" in out


def test_keyless_json_carries_the_skipped_registry_rules(db_path, capsys):
    _code, payload = _json(db_path, capsys)

    assert set(payload["skipped_rules"]) >= set(HMAC_RULES) | set(SIGNATURE_RULES)
    assert payload["clean"] is True


def test_a_keyless_run_does_not_see_the_tamper_a_keyed_run_does(db_path, issuer, keyed, capsys, monkeypatch):
    edits.row_hmac_replaced(Tamper(db_path, issuer))

    assert main(["--sqlite", str(db_path)]) == EXIT_VIOLATIONS
    capsys.readouterr()

    monkeypatch.delenv("BROKER_HMAC_KEY")
    assert main(["--sqlite", str(db_path)]) == EXIT_CLEAN
    assert ROW_HMAC_INTACT in capsys.readouterr().out  # named as skipped


def test_a_record_signed_by_a_key_outside_the_verify_file_is_a_finding(db_path, keyed, issuer, capsys):
    edits.record_signed_by_an_unknown_key(Tamper(db_path, issuer))

    code, payload = _json(db_path, capsys)

    assert code == EXIT_VIOLATIONS
    (violation,) = payload["violations"]
    assert violation["rule"] == RECORD_SIGNATURE_VERIFIES
    assert "admission_signer_unknown" in violation["detail"]


def test_evaluator_keys_alone_do_not_verify_the_admission_ledger(db_path, tmp_path, monkeypatch, capsys):
    """Only the issuer signs admissions. With the evaluator's keys configured
    and the issuer's absent, the registry's signature rules are skipped, not
    quietly run against the wrong role's keys."""
    keys_file = tmp_path / "evaluator-verify-keys.json"
    keys_file.write_text(json.dumps({"evaluator:B": make_issuer().public_pem}), encoding="utf-8")
    monkeypatch.setenv("EVALUATOR_VERIFY_KEYS_FILE", str(keys_file))

    _code, payload = _json(db_path, capsys)

    assert set(payload["skipped_rules"]) >= set(SIGNATURE_RULES)
    assert payload["violations"] == []


def test_an_unreadable_verify_keys_file_exits_two(db_path, tmp_path, monkeypatch, capsys):
    """A named key source that cannot be read is 'could not run', never a
    skipped rule and never a clean result."""
    monkeypatch.setenv("ISSUER_VERIFY_KEYS_FILE", str(tmp_path / "missing.json"))

    assert main(["--sqlite", str(db_path)]) == EXIT_NOT_RUN
    assert "audit could not run" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The dynamo arm: not audited is said, and is never zero
# ---------------------------------------------------------------------------


def test_a_report_without_the_registry_says_it_was_not_audited():
    grants_only = AuditReport(
        violations=(), skipped_rules=(), grants_examined=4, records_examined=4, proposals_examined=0
    )

    payload = report_to_dict(grants_only, AuditTarget("dynamo", "some-grants-table"))

    assert payload["examined"]["mcp_rows"] is None
    assert payload["examined"]["mcp_records"] is None
    assert payload["examined"]["mcp_proposals"] is None
    assert any(note.startswith(ANNOTATION_MCP_NOT_AUDITED) for note in payload["annotations"])
    assert "mcp registry examined: NOT AUDITED" in render_text(payload)


def test_the_sqlite_arm_always_carries_a_registry_report(tmp_path):
    """Even over an empty file: zero items examined is a count, not an absence."""
    audit = run_store_audit(AuditTarget("sqlite", str(tmp_path / "empty.db")))

    assert audit.mcp is not None
    assert (audit.mcp.rows_examined, audit.mcp.records_examined) == (0, 0)


def test_one_admitted_tool_is_enough_to_be_counted(tmp_path, monkeypatch, issuer, keyed, capsys):
    path = tmp_path / "one.db"
    admit(path, monkeypatch, tmp_path, issuer.signer, QUOTE,
          description="return a quote", kind=KIND_ADMISSION, minute=0)

    assert main(["--sqlite", str(path)]) == EXIT_CLEAN
    assert "mcp registry examined: 1 rows, 1 admission records, 1 proposals" in capsys.readouterr().out
