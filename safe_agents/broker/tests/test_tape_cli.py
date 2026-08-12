"""Tests for the local audit-tape surface — FileTapeReader + tape_cli (#300).

The tape is the payoff of the architecture and it was reachable only by someone who
had read the source: the product wrapper contained no occurrence of the string "audit", and the
shipped readers were in-memory and S3, so verifying the one tape the local floor
actually writes meant hand-rolling code around the sink.

The load-bearing tests here are the HONESTY ones. A verify command that implied
tamper-evidence would be the most expensive possible place to overclaim — the chain
is unkeyed SHA-256, so anyone who can write the file can rewrite it whole. Those
tests assert the caveat travels with every verdict and that the word "untampered"
never appears.
"""

from __future__ import annotations

import json

import pytest

from safe_agents.broker.audit import FileAuditSink, emit
from safe_agents.broker.auditor import FileTapeReader, check_chain_integrity
from safe_agents.broker.auditor import tape_cli
from safe_agents.broker.schemas.common import Principal

PRINCIPAL = Principal(agentId="agent:claude-code", skill="code", user="maintainer", tier="B")

BASE_EMIT = dict(
    principal=PRINCIPAL,
    tool="memory",
    op="create_entities",
    # A distinctive value, so "did a raw arg leak into the output" is a question
    # the tests can actually answer rather than a substring that also appears in
    # an op name.
    args={"note": "PLAINTEXT-ARG-VALUE-MUST-NOT-BE-PRINTED"},
    envelope_hash="sha256:envelope",
    decision="allow",
    outcome="executed",
)


@pytest.fixture
def tape(tmp_path):
    """A three-record tape, written the way the broker writes one."""
    path = str(tmp_path / "audit.jsonl")
    sink = FileAuditSink.resuming(path)
    emit(sink, **{**BASE_EMIT, "op": "read_graph"})
    emit(sink, **{**BASE_EMIT, "decision": "require_approval", "outcome": "held",
                  "reason": "in-loop write", "intent_id": "intent-abc"})
    emit(sink, **{**BASE_EMIT, "approved_by": "local-solo:maintainer@macbook#owner",
                  "intent_id": "intent-abc"})
    return path


# ---------------------------------------------------------------------------
# 1. FileTapeReader — the reader the local floor never had
# ---------------------------------------------------------------------------


def test_reader_returns_the_records_in_seq_order(tape):
    records = FileTapeReader(tape).read_all()

    assert [r.seq for r in records] == [0, 1, 2]
    assert check_chain_integrity(FileTapeReader(tape)).intact is True


def test_a_missing_tape_reads_as_empty_not_an_error(tmp_path):
    """A project whose agent has made no brokered call yet has no file, and that
    is a legitimate state to report rather than a fault."""
    assert FileTapeReader(str(tmp_path / "never-written.jsonl")).read_all() == []


def test_reader_detects_an_edited_record(tape):
    """The chain's actual guarantee: an isolated in-place edit is caught."""
    lines = open(tape).read().splitlines()
    record = json.loads(lines[1])
    record["op"] = "delete_entities"  # rewrite one field, leave the hash alone
    lines[1] = json.dumps(record)
    with open(tape, "w") as handle:
        handle.write("\n".join(lines) + "\n")

    finding = check_chain_integrity(FileTapeReader(tape))
    assert finding.intact is False


def test_reader_detects_a_deleted_record(tape):
    lines = open(tape).read().splitlines()
    with open(tape, "w") as handle:
        handle.write("\n".join([lines[0], lines[2]]) + "\n")

    finding = check_chain_integrity(FileTapeReader(tape))
    assert finding.intact is False
    # broken_seq names the seq that SHOULD have been there — the gap is reported
    # at the point the sequence stops being dense, not at the surviving record.
    assert finding.broken_seq == 1
    assert "seq gap" in finding.error


def test_a_wholesale_rewrite_verifies_clean(tape):
    """The LIMIT of the guarantee, pinned as a test so it cannot be forgotten.

    An attacker who rewrites the whole tape and recomputes every hash is
    undetectable here. This passing is not a bug — it is the reason the command
    says "self-consistent" and never "untampered", and the reason posture 3 exists.
    """
    fresh = str(tape) + ".rewritten"
    sink = FileAuditSink.resuming(fresh)
    emit(sink, **{**BASE_EMIT, "op": "something_the_agent_never_asked_for"})

    assert check_chain_integrity(FileTapeReader(fresh)).intact is True


# ---------------------------------------------------------------------------
# 2. The command — and what it is allowed to claim
# ---------------------------------------------------------------------------


def test_names_the_path_and_the_records(tape, capsys):
    assert tape_cli.main(["--path", tape]) == tape_cli.EXIT_OK

    out = capsys.readouterr().out
    assert tape in out
    assert "memory.read_graph" in out
    assert "3 record(s)" in out


def test_verify_reports_consistency_and_never_claims_tamper_evidence(tape, capsys):
    assert tape_cli.main(["--path", tape, "--verify"]) == tape_cli.EXIT_OK

    out = capsys.readouterr().out
    assert "CHAIN CONSISTENT" in out
    # The caveat rides WITH the verdict, not in a footnote somewhere else.
    assert "NOT tamper-evidence" in out
    for overclaim in ("untampered", "tamper-proof", "cannot be altered", "immutable"):
        assert overclaim not in out.lower()


def test_a_broken_chain_exits_nonzero_and_says_where(tape, capsys):
    lines = open(tape).read().splitlines()
    with open(tape, "w") as handle:
        handle.write("\n".join([lines[0], lines[2]]) + "\n")

    assert tape_cli.main(["--path", tape, "--verify"]) == tape_cli.EXIT_BROKEN

    out = capsys.readouterr().out
    assert "CHAIN BROKEN" in out
    assert "NOT tamper-evidence" in out


def test_an_empty_tape_is_reported_not_refused(tmp_path, capsys):
    missing = str(tmp_path / "audit.jsonl")

    assert tape_cli.main(["--path", missing]) == tape_cli.EXIT_OK
    assert "no records yet" in capsys.readouterr().out


def test_an_unreadable_tape_refuses_rather_than_verdicting(tmp_path, capsys):
    """Mid-file corruption means the tape cannot be READ. That is a refusal, not
    a clean "chain broken" answer — reporting a verdict over bytes we could not
    parse would be inventing one."""
    path = tmp_path / "audit.jsonl"
    path.write_text("this-is-not-json\n", encoding="utf-8")

    assert tape_cli.main(["--path", str(path), "--verify"]) == tape_cli.EXIT_REFUSED
    assert "not a readable tape" in capsys.readouterr().err


def test_the_held_record_says_why_it_was_held(tape, capsys):
    """#300 item 3: a held record used to carry reason: null, so the tape could
    show that a call was held and never say what held it."""
    tape_cli.main(["--path", tape])

    out = capsys.readouterr().out
    assert "why  in-loop write" in out


def test_the_release_is_visibly_joined_to_its_hold(tape, capsys):
    """The demo the tape exists to support: held, then released, by whom."""
    tape_cli.main(["--path", tape])

    out = capsys.readouterr().out
    assert "require_approval/held" in out
    assert "approved by local-solo:maintainer@macbook#owner" in out
    assert out.count("intent-abc") == 2  # the hold and the release


def test_raw_args_never_reach_the_rendering(tape, capsys):
    """The broker hashes args on the way in so the audit does not become a PII
    store; the renderer must not undo that by printing them."""
    tape_cli.main(["--path", tape])

    out = capsys.readouterr().out
    assert "PLAINTEXT-ARG-VALUE-MUST-NOT-BE-PRINTED" not in out
    assert "sha256:" in out  # the digest is what stands in for them


def test_json_output_carries_the_caveat_too(tape, capsys):
    assert tape_cli.main(["--path", tape, "--verify", "--json"]) == tape_cli.EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 3
    assert payload["verify"]["intact"] is True
    # A machine reader must not be able to consume the verdict without the limit.
    assert "NOT tamper-evidence" in payload["verify"]["proves"]
