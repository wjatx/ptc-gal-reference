"""
Pytest tests for the PTC/GAL conformance-clause extraction harness (#359).

These pin the exit predicate against the real specs, so a spec edit that breaks
extraction fails here rather than silently shrinking the inventory the
implemented-vs-unbuilt pass works from:

  1. 78 rows total — 43 PTC + 35 GAL, no numbering gaps, no duplicates.
  2. Exactly three rows carry an implementation-status marker at
     conformance-clause scope: PTC-25 (inline, #358), GAL-34 (blockquote, #255),
     GAL-35 (blockquote, #256).
  3. The marker traps hold: the convention-defining prose and the field/verb
     table rows elsewhere in both documents are NOT conformance-row markers, and
     an inline-only marker is still a marker.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from safe_agents.contract.spec_clauses import (
    EXPECTED_MARKED,
    EXPECTED_ROW_COUNTS,
    EXPECTED_TOTAL_ROWS,
    GAL_SPEC_FILENAME,
    MARKER_FORM_BLOCKQUOTE,
    MARKER_FORM_INLINE,
    MARKER_STATE_MARKED,
    MARKER_STATE_UNMARKED,
    PTC_SPEC_FILENAME,
    SPEC_GAL,
    SPEC_PTC,
    ClauseRow,
    SpecFormatError,
    extract_all,
    extract_gal,
    extract_ptc,
    verify_extraction,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_DIR = REPO_ROOT / "spec"

# Conditional for the same reason as the drift suite: the specifications live at
# https://github.com/wjatx/ptc-gal-standards and are not vendored into the reference implementation.
pytestmark = pytest.mark.skipif(
    not SPEC_DIR.is_dir(),
    reason="specifications not present; they live at https://github.com/wjatx/ptc-gal-standards",
)


@pytest.fixture(scope="module")
def rows() -> list[ClauseRow]:
    return extract_all(SPEC_DIR)


def _by_id(rows: list[ClauseRow], clause_id: str) -> ClauseRow:
    return next(r for r in rows if r.clause_id == clause_id)


# ---------------------------------------------------------------------------
# The exit predicate
# ---------------------------------------------------------------------------

def test_all_self_checks_pass(rows: list[ClauseRow]) -> None:
    failures = [(r.name, r.reason) for r in verify_extraction(rows) if not r.passed]
    assert not failures, f"harness self-checks failed: {failures}"


def test_total_row_count(rows: list[ClauseRow]) -> None:
    assert len(rows) == EXPECTED_TOTAL_ROWS


@pytest.mark.parametrize(("spec", "expected"), sorted(EXPECTED_ROW_COUNTS.items()))
def test_per_spec_row_count_and_numbering(
    rows: list[ClauseRow], spec: str, expected: int
) -> None:
    numbers = sorted(r.number for r in rows if r.spec == spec)
    assert numbers == list(range(1, expected + 1)), (
        f"{spec} numbering is not exactly {spec}-1..{expected} with no repeats"
    )


def test_exactly_three_marked_rows_with_forms_and_issues(rows: list[ClauseRow]) -> None:
    marked = {
        r.clause_id: (r.marker_form, r.marker_tracking_issue)
        for r in rows if r.marker_state == MARKER_STATE_MARKED
    }
    assert marked == EXPECTED_MARKED


# ---------------------------------------------------------------------------
# Marker-detection traps
# ---------------------------------------------------------------------------

def test_ptc25_marker_is_inline_not_blockquote(rows: list[ClauseRow]) -> None:
    """A blockquote-only parser reports PTC as having zero marked rows."""
    row = _by_id(rows, "PTC-25")
    assert row.marker_state == MARKER_STATE_MARKED
    assert row.marker_form == MARKER_FORM_INLINE
    assert row.marker_tracking_issue == "#358"
    assert "not yet implemented" in row.clause_text


@pytest.mark.parametrize(("clause_id", "issue"), [("GAL-34", "#255"), ("GAL-35", "#256")])
def test_gal_appended_clauses_are_blockquote_marked(
    rows: list[ClauseRow], clause_id: str, issue: str
) -> None:
    row = _by_id(rows, clause_id)
    assert row.marker_form == MARKER_FORM_BLOCKQUOTE
    assert row.marker_tracking_issue == issue
    # The marker line itself is not folded into the normative clause text.
    assert "Implementation status" not in row.clause_text


@pytest.mark.parametrize("clause_id", ["PTC-1", "PTC-4", "PTC-26", "PTC-34", "GAL-3", "GAL-30", "GAL-32"])
def test_neighbouring_clauses_are_unmarked(rows: list[ClauseRow], clause_id: str) -> None:
    """
    A marker binds only its own clause, and a scope leak shows up here.

    The neighbours were re-picked on 2026-08-08 when the #359 findings were
    marked: the previous set named PTC-24 and GAL-33, and both are now marked
    themselves, so they could no longer witness containment. Each id below is
    unmarked and sits beside at least one marked clause — PTC-1/PTC-4 bracket
    PTC-2 and PTC-3, PTC-26 and PTC-34 sit beside the inline cases PTC-25 and
    PTC-33/35, GAL-3 abuts GAL-4, and GAL-30/GAL-32 precede the blockquote
    cases. This test matters MORE at 23 markers than it did at three: with most
    of the table marked, an over-greedy pattern would be invisible in the counts.
    """
    row = _by_id(rows, clause_id)
    assert row.marker_state == MARKER_STATE_UNMARKED
    assert row.marker_form is None
    assert row.marker_tracking_issue is None


def test_out_of_section_markers_are_not_picked_up(rows: list[ClauseRow]) -> None:
    """
    Both specs carry the literal marker in convention prose and on field/verb
    table rows outside the conformance sections. None of those is a conformance
    row, so none of them may reach the extracted inventory.

    The comparison is against the BLOCKQUOTE-form markers only, which is the
    correction made 2026-08-08. The old assertion compared the literal count to
    the whole expected set, which held while the set was three blockquotes and
    broke the moment inline markers outnumbered it — the inline form does not
    use this literal at all, so the two were never like-for-like.
    """
    marker_lines = sum(
        line.count("**Implementation status:**")
        for name in (PTC_SPEC_FILENAME, GAL_SPEC_FILENAME)
        for line in (SPEC_DIR / name).read_text(encoding="utf-8").splitlines()
    )
    blockquote_markers = sum(
        1 for form, _ in EXPECTED_MARKED.values() if form == MARKER_FORM_BLOCKQUOTE
    )
    assert marker_lines > blockquote_markers, (
        "expected out-of-section marker literals to exist; if they are gone this "
        "test no longer proves scoping"
    )
    assert len([r for r in rows if r.marker_state == MARKER_STATE_MARKED]) == len(EXPECTED_MARKED)


# ---------------------------------------------------------------------------
# Shape of the extracted rows
# ---------------------------------------------------------------------------

def test_roles_come_from_the_section_the_clause_falls_under(rows: list[ClauseRow]) -> None:
    """GAL-34 and GAL-35 are appended out of numeric order; role follows position."""
    assert _by_id(rows, "GAL-34").role == "Enforcer"
    assert _by_id(rows, "GAL-35").role == "Audit"
    assert {r.role for r in rows if r.spec == SPEC_GAL} == {"Issuer", "Enforcer", "Audit"}
    assert {r.role for r in rows if r.spec == SPEC_PTC} == {
        "All", "Producer", "Receiver", "Receiver (gate)", "Tool Host", "Observer",
    }


def test_every_row_has_text_origin_and_a_source_line(rows: list[ClauseRow]) -> None:
    thin = [
        r.clause_id for r in rows
        if not r.clause_text.strip() or not r.origin.strip() or r.source_line <= 0
    ]
    assert not thin, f"rows missing clause text, origin, or source line: {thin}"


def test_source_lines_point_at_the_clause(rows: list[ClauseRow]) -> None:
    for spec, filename in ((SPEC_PTC, PTC_SPEC_FILENAME), (SPEC_GAL, GAL_SPEC_FILENAME)):
        lines = (SPEC_DIR / filename).read_text(encoding="utf-8").splitlines()
        for row in (r for r in rows if r.spec == spec):
            assert row.clause_id in lines[row.source_line - 1], (
                f"{filename}:{row.source_line} does not contain {row.clause_id}"
            )


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------

def test_missing_section_is_a_loud_error(tmp_path: Path) -> None:
    stub = tmp_path / PTC_SPEC_FILENAME
    stub.write_text("# PTC\n\n### 8.9 Something else\n", encoding="utf-8")
    with pytest.raises(SpecFormatError, match="section heading not found"):
        extract_ptc(stub)


def test_gal_missing_origin_table_is_a_loud_error(tmp_path: Path) -> None:
    stub = tmp_path / GAL_SPEC_FILENAME
    stub.write_text("# GAL\n\n### 7.2 Issuer clauses\n\n- **GAL-1** Something.\n", encoding="utf-8")
    with pytest.raises(SpecFormatError, match="section heading not found"):
        extract_gal(stub)
