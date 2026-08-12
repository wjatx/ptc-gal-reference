"""#252 item 2 — the audit's invocation path, and the contract posture parses.

Until this module the auditor had no caller outside a test: CI ran it as a
pytest invocation and nothing else could reach it. These tests cover the door
rather than the rules — the rules have their own suite.

What gets asserted here is mostly about **honesty under failure**, because that
is where an audit surface goes wrong: an unreadable target must not look like a
clean floor, a keyless run must not look like a full one, and the exit code a
caller keys on must distinguish "dirty" from "nobody looked".
"""

from __future__ import annotations

import inspect
import json

import pytest

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.grants import audit_command
from safe_agents.broker.grants.audit import HMAC_RULES, RECORD_SIGNATURE_VERIFIES
from safe_agents.broker.grants.audit_command import (
    EXIT_CLEAN,
    EXIT_NOT_RUN,
    EXIT_VIOLATIONS,
    AuditTarget,
    main,
    report_to_dict,
    run_grants_audit,
)
from safe_agents.broker.tests.test_grants_audit import (
    _GRANT_PK,
    ACTION_CLASS,
    HMAC_KEY,
    _grant_item,
    _make_grant,
    _make_record,
)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "broker.db"


@pytest.fixture(autouse=True)
def _no_ambient_key_material(monkeypatch):
    """Every test names its own mode. Ambient env would let a developer's shell
    silently change which rules ran."""
    monkeypatch.delenv("BROKER_HMAC_KEY", raising=False)
    monkeypatch.delenv("ISSUER_VERIFY_KEYS_PARAM", raising=False)


def _plant(db_path, items) -> None:
    conn = substrate.open_connection(db_path)
    try:
        with substrate.transaction(conn):
            for item in items:
                attrs = {k: v for k, v in item.items() if k not in ("pk", "sk")}
                substrate.put_new_item(conn, item["pk"], item["sk"], attrs)
    finally:
        conn.close()


def _seed_clean(db_path) -> None:
    """A grant with its earning ledger record — clean under every rule that can
    run without key material."""
    from safe_agents.broker.grants.sqlite_store import (
        SqliteGrantStore,
        SqlitePromotionRecordStore,
    )

    SqliteGrantStore(hmac_key=HMAC_KEY, db_path=db_path).put_grant(_make_grant())
    SqlitePromotionRecordStore(db_path).put_record(_make_record())


# ---------------------------------------------------------------------------
# Exit codes — the contract a caller keys on
# ---------------------------------------------------------------------------


def test_clean_store_exits_zero(db_path, capsys):
    _seed_clean(db_path)

    assert main(["--sqlite", str(db_path)]) == EXIT_CLEAN


def test_violations_exit_one(db_path, capsys):
    # A grant with no ledger record behind it — LEDGER_COUNTERPART fires with
    # no key material at all, so this is a violation any caller can reach.
    _plant(db_path, [_grant_item()])

    assert main(["--sqlite", str(db_path)]) == EXIT_VIOLATIONS
    assert "LEDGER_COUNTERPART" in capsys.readouterr().out


def test_unreadable_target_exits_two_not_one(db_path, capsys, monkeypatch):
    """The distinction the whole exit-code contract exists for.

    A caller that treated an unrunnable audit as a violation would at least be
    loud; one that treated it as clean would report an unaudited store as a
    sound one. Exit 2 is neither.
    """
    monkeypatch.setenv("ISSUER_VERIFY_KEYS_PARAM", "/does/not/resolve")
    monkeypatch.setattr(
        "safe_agents.broker.grants.issuer_keys._fetch_parameter",
        lambda name: (_ for _ in ()).throw(RuntimeError("no such parameter")),
    )
    _seed_clean(db_path)

    assert main(["--sqlite", str(db_path)]) == EXIT_NOT_RUN
    assert "audit could not run" in capsys.readouterr().err


def test_a_target_must_be_named(capsys):
    """No default target: auditing a defaulted path would open a fresh empty
    database and report a spotless floor."""
    with pytest.raises(SystemExit):
        main([])


def test_sqlite_and_table_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit):
        main(["--sqlite", "a.db", "--table", "some-table"])


# ---------------------------------------------------------------------------
# The JSON contract — what example-wrapper posture parses
# ---------------------------------------------------------------------------


def test_json_payload_is_parseable_and_carries_the_honesty_fields(db_path, capsys):
    _seed_clean(db_path)

    main(["--sqlite", str(db_path), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["backend"] == "sqlite"
    assert payload["location"] == str(db_path)
    assert payload["clean"] is True
    assert payload["violations"] == []
    assert payload["examined"]["grants"] == 1
    # The load-bearing one: a clean report must still say what did NOT run.
    assert set(payload["skipped_rules"]) >= set(HMAC_RULES) | {RECORD_SIGNATURE_VERIFIES}


def test_violation_detail_survives_into_json(db_path, capsys):
    _plant(db_path, [_grant_item()])

    main(["--sqlite", str(db_path), "--json"])
    payload = json.loads(capsys.readouterr().out)

    (violation,) = payload["violations"]
    assert violation["rule"] == "LEDGER_COUNTERPART"
    assert violation["coordinate"] == f"{_GRANT_PK.removeprefix('GRANT#')}#{ACTION_CLASS}"
    assert violation["detail"]  # a rule name without its detail is not a finding


def test_clean_is_not_the_same_claim_as_nothing_skipped(db_path, monkeypatch, capsys):
    """A keyed run and a keyless run over the same clean store both report
    clean=True — and must be distinguishable, which is what skipped_rules is
    for. Collapsing them is the overclaim the audit exists to prevent."""
    _seed_clean(db_path)

    keyless = report_to_dict(run_grants_audit(AuditTarget("sqlite", str(db_path))),
                             AuditTarget("sqlite", str(db_path)))
    monkeypatch.setenv("BROKER_HMAC_KEY", HMAC_KEY.decode())
    keyed = report_to_dict(run_grants_audit(AuditTarget("sqlite", str(db_path))),
                           AuditTarget("sqlite", str(db_path)))

    assert keyless["clean"] is keyed["clean"] is True
    assert set(keyed["skipped_rules"]) < set(keyless["skipped_rules"])


def test_keyed_mode_comes_from_the_environment_not_a_flag(db_path, monkeypatch):
    """No flag may ask for a quieter audit — mode follows what the invoking
    identity holds, the same rule the live test and demotion runner follow."""
    _seed_clean(db_path)
    monkeypatch.setenv("BROKER_HMAC_KEY", HMAC_KEY.decode())

    report = run_grants_audit(AuditTarget("sqlite", str(db_path)))

    assert not set(HMAC_RULES) & set(report.skipped_rules)
    assert "--hmac" not in inspect.getsource(audit_command)


def test_empty_store_reports_zero_examined_rather_than_clean_silence(db_path, capsys):
    """An audit of nothing exits 0, and the counts are what reveal it — the
    reason report_to_dict carries `examined` at all."""
    assert main(["--sqlite", str(db_path), "--json"]) == EXIT_CLEAN
    payload = json.loads(capsys.readouterr().out)
    assert payload["examined"] == {"grants": 0, "records": 0, "proposals": 0, "envelopes": 0}


# ---------------------------------------------------------------------------
# Read-only guard — extended to the door, not just the room behind it
# ---------------------------------------------------------------------------


def test_audit_command_source_names_no_write_api():
    """`audit.py` has carried this guard since #62 and `audit_command.py` is a
    new module in the same trust position — a guard whose teeth stop at one
    file is the #267 shape, which this session already paid for once.
    """
    source = inspect.getsource(audit_command)
    for forbidden in ("put_item", "update_item", "delete_item", "batch_writer", "put_new_item"):
        assert forbidden not in source, (
            f"audit_command.py must never write: found {forbidden!r} in the source"
        )


def test_backend_catalog_is_closed():
    """The backend is a string from a closed catalog resolved in ONE place, not
    an import path — docs/config-provenance.md."""
    with pytest.raises(audit_command.AuditTargetError):
        audit_command.load_target(AuditTarget("postgres", "somewhere"))  # type: ignore[arg-type]
