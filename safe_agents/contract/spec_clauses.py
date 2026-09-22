"""
Conformance-clause extraction harness for the PTC and GAL specifications.

Extracts every normative conformance row from spec/PTC-SPEC.md §8.2 and
spec/GAL-SPEC.md §7.2–§7.4, joins each row to its origin pointer, and records
whether the clause carries an implementation-status marker. It EXTRACTS ONLY —
it never adjudicates whether a clause is implemented (#359 owns that pass); it
produces the row inventory that pass works against.

Both specs make marker ABSENCE load-bearing ("absence of the marker means the
clause is implemented in the reference implementation" — PTC §2, GAL §3), so the
marker column is the reason this harness exists. Two marker forms mean the same
thing: a blockquote line following the clause, and the short inline form inside
the clause's own text. Only markers at conformance-clause scope count — the same
literal appears in the convention-defining prose and on field/verb table rows
elsewhere in both documents, and neither is a conformance-row marker.

Self-checks run on every invocation, so a spec edit that breaks extraction fails
loudly instead of silently returning a short inventory.

Usage:
    python3 -m safe_agents.contract.spec_clauses [--summary|--pics|--pics-ri] [--spec-dir DIR]

Or import and call extract_all(spec_dir) / verify_extraction(rows) from pytest.
Stdlib only: CheckResult mirrors the shape used by harness.py rather than
importing it, so this module carries no yaml dependency.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# --- Vocabulary ------------------------------------------------------------

SPEC_PTC = "PTC"
SPEC_GAL = "GAL"

MARKER_STATE_MARKED = "marked"        # normative, NOT YET IMPLEMENTED
MARKER_STATE_EXCEEDED = "exceeded"    # normative, SATISFIED BY A STRONGER MECHANISM
MARKER_STATE_UNMARKED = "unmarked"
MARKER_FORM_BLOCKQUOTE = "blockquote"
MARKER_FORM_INLINE = "inline"

# --- Violation names — printed verbatim on failure -------------------------
# The first two are raised as SpecFormatError (parsing gave up); the rest are
# self-check results over an inventory that did parse.

SPEC_SECTION_NOT_FOUND = "SPEC_SECTION_NOT_FOUND"
SPEC_ROW_MALFORMED     = "SPEC_ROW_MALFORMED"
ROW_COUNT_MISMATCH     = "ROW_COUNT_MISMATCH"
TOTAL_ROW_COUNT        = "TOTAL_ROW_COUNT"
CLAUSE_NUMBERING_GAP   = "CLAUSE_NUMBERING_GAP"
DUPLICATE_CLAUSE_ID    = "DUPLICATE_CLAUSE_ID"
MARKED_SET_MISMATCH    = "MARKED_SET_MISMATCH"
EXCEEDED_SET_MISMATCH  = "EXCEEDED_SET_MISMATCH"
ORIGIN_MISSING         = "ORIGIN_MISSING"

# --- Where the clauses live ------------------------------------------------
# Headings are matched verbatim so a section rename is a loud
# SPEC_SECTION_NOT_FOUND rather than a silent zero-row extraction.

PTC_SPEC_FILENAME = "PTC-SPEC.md"
GAL_SPEC_FILENAME = "GAL-SPEC.md"

PTC_CLAUSE_HEADING = "### 8.2 Conformance clauses"
# §8.3 "Origin-mapping coverage" is a DIFFERENT table (coverage of origin clause
# sets by PTC row) and is deliberately not read here.

GAL_CLAUSE_HEADINGS = (
    "### 7.2 Issuer clauses",
    "### 7.3 Enforcer clauses",
    "### 7.4 Audit clauses",
)
GAL_ORIGIN_HEADING = "### 7.5 Clause origin mapping (non-normative)"

# PTC carries its origin pointer inline as the 4th table column.
PTC_TABLE_COLUMNS = 4
GAL_ORIGIN_TABLE_COLUMNS = 2

# --- Exit predicate (#359), asserted by verify_extraction on every run -----

EXPECTED_ROW_COUNTS = {SPEC_PTC: 43, SPEC_GAL: 39}
EXPECTED_TOTAL_ROWS = 82

# clause_id -> (marker_form, tracking issue)
#
# Grew from 3 to 23 on 2026-08-08, when the #359 conformance audit's findings
# were marked. That jump is the honest number, not a regression: every one of
# these clauses was ALREADY unimplemented, and marker absence had been claiming
# otherwise in a published document. Every marker is SCOPED — it names the one
# unbuilt conjunct rather than retracting a row whose other conjuncts ship,
# which is why the clause text still reads as a requirement.
#
# Three tracking ids appear more than once, and each is one defect across
# several rows rather than a filing error: #315 (PTC-7/8/9, outbound stamping),
# #372 (GAL-4/GAL-14, the runtime bootstrap path).
EXPECTED_MARKED: dict[str, tuple[str, str]] = {
    # #359 PTC findings
    "PTC-2":  (MARKER_FORM_INLINE, "#17"),
    "PTC-3":  (MARKER_FORM_INLINE, "#18"),
    "PTC-6":  (MARKER_FORM_INLINE, "#19"),
    "PTC-7":  (MARKER_FORM_INLINE, "#15"),
    "PTC-8":  (MARKER_FORM_INLINE, "#15"),
    "PTC-9":  (MARKER_FORM_INLINE, "#15"),
    "PTC-14": (MARKER_FORM_INLINE, "#20"),
    "PTC-22": (MARKER_FORM_INLINE, "#21"),
    "PTC-24": (MARKER_FORM_INLINE, "#22"),
    "PTC-25": (MARKER_FORM_INLINE, "#16"),
    "PTC-28": (MARKER_FORM_INLINE, "#23"),
    "PTC-33": (MARKER_FORM_INLINE, "#24"),
    "PTC-35": (MARKER_FORM_INLINE, "#25"),
    "PTC-42": (MARKER_FORM_INLINE, "#26"),
    # #359 GAL findings
    "GAL-4":  (MARKER_FORM_INLINE, "#27"),
    "GAL-14": (MARKER_FORM_INLINE, "#27"),
    "GAL-26": (MARKER_FORM_INLINE, "#28"),
    "GAL-28": (MARKER_FORM_INLINE, "#29"),
    "GAL-29": (MARKER_FORM_INLINE, "#30"),
    # Obligations the 2026-08-08 amendments CREATED: the clause now states a
    # requirement the code does not yet meet, which is the marker's whole point.
    "GAL-5":  (MARKER_FORM_INLINE, "#32"),
    "GAL-33": (MARKER_FORM_INLINE, "#31"),
    # Predates the audit. GAL-34 (#255) left this set on 2026-09-19 when the
    # lapse arc shipped.
    "GAL-35": (MARKER_FORM_BLOCKQUOTE, "#14"),
    # Renumbered 2026-09-21: every marker now cites an issue in the PUBLIC
# reference implementation. They previously cited the private tracker, so a
# reader of the published specification could not reach any of them, while
# GAL §3 promised "#NNN is the reference implementation's public tracking
# issue for the work". The marker's credibility is the reachable pointer.
# Added by GAL 0.2.7-draft. The derivation lifecycle rule was stated in
    # 0.2.5 prose and deliberately NOT made a clause, on the grounds that no
    # conforming implementation had a derived grant to apply it to -- which set
    # the specification's requirement to the RI's coverage. This marker is the
    # correct form of that honesty: fully normative, and openly not yet built.
    "GAL-39": (MARKER_FORM_BLOCKQUOTE, "#11"),
}

# Clauses the reference implementation has OUTGROWN. Pinned separately from
# EXPECTED_MARKED because the two mean opposite things about the code, and a
# clause sliding between the two sets is exactly the drift worth failing on.
#
# EMPTY ON PURPOSE, and the reason is worth keeping. The inverse marker is for a
# clause we cannot revise yet; while no version is frozen, the honest move is to
# amend the clause to state its property rather than carry a marker toward a
# revision we could do the same day (§3 says so: the end state is a property
# clause and the marker comes off). GAL-19, GAL-24, GAL-7 and PTC-34 were all
# resolved that way on 2026-08-08. This set fills the moment a version is
# ratified and the text stops being ours to change.
EXPECTED_EXCEEDED: dict[str, tuple[str, str]] = {}

# --- Patterns --------------------------------------------------------------

HEADING_RE = re.compile(r"^#{1,6}\s")
ROLE_HEADING_RE = re.compile(r"^#{1,6}\s+[\d.]+\s+(?P<role>.+?)\s+clauses\s*$")
# Split markdown table cells on unescaped pipes only.
CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")
PTC_ROW_RE = re.compile(r"^\|\s*PTC-(\d+)\s*\|")
GAL_BULLET_RE = re.compile(r"^-\s+\*\*GAL-(\d+)\*\*\s+(.*)$")
GAL_ORIGIN_ROW_RE = re.compile(r"^\|\s*GAL-(\d+)\s*\|")
# The INVERSE marker (spec behind the code). It MUST be tested before the
# generic pattern below, which also matches this line — a wrong order classifies
# an outgrown clause as unbuilt, which is the opposite of what it means and the
# single most damaging way this harness could be wrong.
STRONGER_BLOCKQUOTE_RE = re.compile(
    r"\*\*Implementation status:\*\*\s*NORMATIVE,\s*SATISFIED BY A STRONGER MECHANISM"
    r".*?\(tracking:\s*(#\d+)\)"
)
STRONGER_INLINE_RE = re.compile(
    r"\([^()]*?stronger mechanism\s*[—–-]\s*(#\d+)\)"
)
BLOCKQUOTE_MARKER_RE = re.compile(
    r"\*\*Implementation status:\*\*.*?\(tracking:\s*(#\d+)\)"
)
# The inline form is a parenthetical. It may carry a prefix naming which part of
# the clause is unbuilt — PTC-25 reads "(argument clamping: not yet implemented
# — #358)" — so the prefix is allowed, but the parentheses are still required:
# without them the convention-defining prose that quotes the form would match.
INLINE_MARKER_RE = re.compile(
    r"\([^()]*?not yet implemented\s*[—–-]\s*(#\d+)\)"
)


class SpecFormatError(RuntimeError):
    """The spec no longer matches the shape this harness parses."""


# --- Row type --------------------------------------------------------------

@dataclass(frozen=True)
class ClauseRow:
    spec: str                              # SPEC_PTC | SPEC_GAL
    clause_id: str                         # e.g. "PTC-25"
    number: int
    role: str                              # conformance role this clause binds
    clause_text: str
    marker_state: str                      # MARKER_STATE_*
    marker_tracking_issue: Optional[str]   # e.g. "#358", else None
    marker_form: Optional[str]             # MARKER_FORM_*, else None
    origin: str                            # the contract pointer
    source_line: int                       # 1-based line in the spec file


@dataclass
class CheckResult:
    name: str    # violation name (always one of the constants above)
    passed: bool
    reason: str


# --- Parsing helpers -------------------------------------------------------

def _slice_section(lines: list[str], heading: str, path: Path) -> list[tuple[int, str]]:
    """Return [(1-based lineno, text)] under `heading`, up to the next heading."""
    start = next((i for i, ln in enumerate(lines) if ln.strip() == heading), None)
    if start is None:
        raise SpecFormatError(
            f"{SPEC_SECTION_NOT_FOUND}: {path}: section heading not found: {heading!r}. "
            "The spec was renamed or restructured; update the heading constant "
            "in safe_agents/contract/spec_clauses.py rather than loosening the match."
        )
    block: list[tuple[int, str]] = []
    for i in range(start + 1, len(lines)):
        if HEADING_RE.match(lines[i]):
            break
        block.append((i + 1, lines[i]))
    return block


def _cells(text: str, expected: int, path: Path, lineno: int) -> list[str]:
    """Split a markdown table row into its `expected` cells."""
    parts = [c.replace("\\|", "|").strip() for c in CELL_SPLIT_RE.split(text)]
    if parts and not parts[0]:
        parts = parts[1:]
    if parts and not parts[-1]:
        parts = parts[:-1]
    if len(parts) != expected:
        raise SpecFormatError(
            f"{SPEC_ROW_MALFORMED}: {path}:{lineno}: expected {expected} table cells, "
            f"got {len(parts)}: {text!r}"
        )
    return parts


def _detect_marker(
    clause_text: str, block: list[str]
) -> tuple[str, Optional[str], Optional[str]]:
    """
    Resolve the implementation-status marker at THIS clause's scope.

    Returns (marker_state, marker_form, tracking_issue). Two marker kinds exist
    and they mean opposite things about the code: MARKED is normative-but-unbuilt,
    EXCEEDED is normative-but-outgrown. The stronger-mechanism patterns are tested
    first because the generic ones also match those lines.

    `block` is only the lines belonging to this clause (between it and the next
    clause), so a marker elsewhere in the document cannot bind here. The
    blockquote form wins if both are present.
    """
    for line in block:
        stripped = line.strip()
        if not stripped.startswith(">"):
            continue
        found = STRONGER_BLOCKQUOTE_RE.search(stripped)
        if found:
            return MARKER_STATE_EXCEEDED, MARKER_FORM_BLOCKQUOTE, found.group(1)
        found = BLOCKQUOTE_MARKER_RE.search(stripped)
        if found:
            return MARKER_STATE_MARKED, MARKER_FORM_BLOCKQUOTE, found.group(1)
    found = STRONGER_INLINE_RE.search(clause_text)
    if found:
        return MARKER_STATE_EXCEEDED, MARKER_FORM_INLINE, found.group(1)
    found = INLINE_MARKER_RE.search(clause_text)
    if found:
        return MARKER_STATE_MARKED, MARKER_FORM_INLINE, found.group(1)
    return MARKER_STATE_UNMARKED, None, None


def _make_row(
    *, spec: str, number: int, role: str, clause_text: str, origin: str,
    lineno: int, state: str, form: Optional[str], issue: Optional[str],
) -> ClauseRow:
    return ClauseRow(
        spec=spec,
        clause_id=f"{spec}-{number}",
        number=number,
        role=role,
        clause_text=clause_text,
        marker_state=state,
        marker_tracking_issue=issue,
        marker_form=form,
        origin=origin,
        source_line=lineno,
    )


# --- Extraction ------------------------------------------------------------

def extract_ptc(path: Path) -> list[ClauseRow]:
    """PTC §8.2 — one table, `| PTC-N | Role | Clause | Origin |`."""
    lines = path.read_text(encoding="utf-8").splitlines()
    block = _slice_section(lines, PTC_CLAUSE_HEADING, path)
    starts = [i for i, (_, text) in enumerate(block) if PTC_ROW_RE.match(text)]

    rows: list[ClauseRow] = []
    for pos, i in enumerate(starts):
        lineno, text = block[i]
        number = int(PTC_ROW_RE.match(text).group(1))
        _, role, clause_text, origin = _cells(text, PTC_TABLE_COLUMNS, path, lineno)
        end = starts[pos + 1] if pos + 1 < len(starts) else len(block)
        state, form, issue = _detect_marker(clause_text, [t for _, t in block[i + 1:end]])
        rows.append(_make_row(
            spec=SPEC_PTC, number=number, role=role, clause_text=clause_text,
            origin=origin, lineno=lineno, state=state, form=form, issue=issue,
        ))
    return rows


def _gal_origins(lines: list[str], path: Path) -> dict[int, str]:
    """GAL §7.5 — the separate, non-normative `| GAL-N | Origin |` table."""
    origins: dict[int, str] = {}
    for lineno, text in _slice_section(lines, GAL_ORIGIN_HEADING, path):
        if not GAL_ORIGIN_ROW_RE.match(text):
            continue
        clause_id, origin = _cells(text, GAL_ORIGIN_TABLE_COLUMNS, path, lineno)
        origins[int(GAL_ORIGIN_ROW_RE.match(text).group(1))] = origin
    return origins


def extract_gal(path: Path) -> list[ClauseRow]:
    """
    GAL §7.2–§7.4 — a bullet list per role section.

    The role is derived from the section heading the clause actually falls
    under, not from its number: GAL-34 and GAL-36 are appended to the end of
    §7.3 and GAL-35 to §7.4 rather than sitting in numeric order.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    origins = _gal_origins(lines, path)

    rows: list[ClauseRow] = []
    for heading in GAL_CLAUSE_HEADINGS:
        role_match = ROLE_HEADING_RE.match(heading)
        if not role_match:
            raise SpecFormatError(f"cannot derive a role from heading {heading!r}")
        role = role_match.group("role")

        block = _slice_section(lines, heading, path)
        starts = [i for i, (_, text) in enumerate(block) if GAL_BULLET_RE.match(text)]
        for pos, i in enumerate(starts):
            lineno, text = block[i]
            bullet = GAL_BULLET_RE.match(text)
            number = int(bullet.group(1))
            end = starts[pos + 1] if pos + 1 < len(starts) else len(block)
            body = [t for _, t in block[i + 1:end]]
            # Continuation lines are clause text; blockquotes are marker candidates.
            continuation = [
                t.strip() for t in body
                if t.strip() and not t.strip().startswith(">")
            ]
            clause_text = " ".join([bullet.group(2).strip(), *continuation]).strip()
            state, form, issue = _detect_marker(clause_text, body)
            rows.append(_make_row(
                spec=SPEC_GAL, number=number, role=role, clause_text=clause_text,
                origin=origins.get(number, ""), lineno=lineno, state=state,
                form=form, issue=issue,
            ))
    return rows


def extract_all(spec_dir: Path) -> list[ClauseRow]:
    """Extract every conformance row from both specs, PTC first."""
    return (
        extract_ptc(spec_dir / PTC_SPEC_FILENAME)
        + extract_gal(spec_dir / GAL_SPEC_FILENAME)
    )


# --- Self-checks -----------------------------------------------------------

def marked_rows(rows: list[ClauseRow]) -> dict[str, tuple[Optional[str], Optional[str]]]:
    """clause_id -> (marker_form, tracking issue) for every NOT-YET-IMPLEMENTED row."""
    return {
        r.clause_id: (r.marker_form, r.marker_tracking_issue)
        for r in rows if r.marker_state == MARKER_STATE_MARKED
    }


def exceeded_rows(rows: list[ClauseRow]) -> dict[str, tuple[Optional[str], Optional[str]]]:
    """clause_id -> (marker_form, tracking issue) for every OUTGROWN row."""
    return {
        r.clause_id: (r.marker_form, r.marker_tracking_issue)
        for r in rows if r.marker_state == MARKER_STATE_EXCEEDED
    }


# --- Implementation Conformance Statement (ISO/IEC 9646-7) -----------------

PICS_SUPPORTED = "Y"
PICS_NOT_SUPPORTED = "N"
PICS_NOT_APPLICABLE = "N-A"


def pics_answer(row: ClauseRow) -> str:
    """The reference implementation's support answer for one clause.

    DERIVED from the marker, never authored (GAL §7.6 / PTC §8.4): an unmarked
    clause answers Y, a NOT-YET-IMPLEMENTED clause answers N. Deriving is the
    control — a hand-written statement drifts from the markers, and the markers
    are themselves extracted from the clause list, so all three move together.

    EXCEEDED answers Y. A clause the implementation has outgrown is satisfied;
    that its mechanism differs is a fact about the clause's shape, not a gap in
    support, and PICS has no vocabulary for it because a well-formed proforma
    item states a capability rather than a means.
    """
    if row.marker_state == MARKER_STATE_MARKED:
        return PICS_NOT_SUPPORTED
    return PICS_SUPPORTED


def pics_proforma(rows: list[ClauseRow], *, filled: bool) -> str:
    """Render the proforma as markdown, blank or with the RI's answers.

    `filled=False` is the artifact an independent implementer completes;
    `filled=True` is ours, and belongs with the reference-implementation
    document rather than in the specification.
    """
    out: list[str] = []
    for spec in (SPEC_PTC, SPEC_GAL):
        spec_rows = [r for r in rows if r.spec == spec]
        out.append(f"\n## {spec} — implementation conformance statement\n")
        by_role: dict[str, list[ClauseRow]] = {}
        for r in spec_rows:
            by_role.setdefault(r.role, []).append(r)
        for role, group in by_role.items():
            answered = sum(1 for r in group if pics_answer(r) == PICS_SUPPORTED)
            head = f"### Role: {role} ({len(group)} clauses"
            out.append(f"{head}, {answered} supported)\n" if filled else f"{head})\n")
            out.append("| Clause | Status | Support | Note |")
            out.append("|---|---|---|---|")
            for r in sorted(group, key=lambda x: x.number):
                support = pics_answer(r) if filled else ""
                note = ""
                if filled and r.marker_state == MARKER_STATE_MARKED:
                    note = f"not yet implemented — {r.marker_tracking_issue}"
                out.append(f"| {r.clause_id} | M | {support} | {note} |")
            out.append("")
    return "\n".join(out)


def verify_extraction(rows: list[ClauseRow]) -> list[CheckResult]:
    """Assert the #359 exit predicate over an extracted inventory."""
    results: list[CheckResult] = []

    def check(name: str, ok: bool, bad: str, good: str) -> None:
        results.append(CheckResult(name, ok, good if ok else bad))

    for spec, expected in EXPECTED_ROW_COUNTS.items():
        numbers = sorted(r.number for r in rows if r.spec == spec)
        missing = sorted(set(range(1, expected + 1)) - set(numbers))
        dupes = sorted({n for n in numbers if numbers.count(n) > 1})
        check(ROW_COUNT_MISMATCH, len(numbers) == expected,
              f"{spec}: extracted {len(numbers)} rows, expected {expected}",
              f"{spec}: extracted {expected} rows")
        check(CLAUSE_NUMBERING_GAP, not missing,
              f"{spec}: missing clause numbers {missing}",
              f"{spec}: {spec}-1..{expected} all present")
        check(DUPLICATE_CLAUSE_ID, not dupes,
              f"{spec}: duplicated clause numbers {dupes}",
              f"{spec}: no duplicated clause ids")

    marked = marked_rows(rows)
    no_origin = [r.clause_id for r in rows if not r.origin]
    check(TOTAL_ROW_COUNT, len(rows) == EXPECTED_TOTAL_ROWS,
          f"{len(rows)} rows total, expected {EXPECTED_TOTAL_ROWS}",
          f"{EXPECTED_TOTAL_ROWS} rows total")
    exceeded = exceeded_rows(rows)
    check(MARKED_SET_MISMATCH, marked == EXPECTED_MARKED,
          f"marked set {marked} != expected {EXPECTED_MARKED}",
          f"exactly {len(marked)} marked rows, forms and tracking issues as expected")
    check(EXCEEDED_SET_MISMATCH, exceeded == EXPECTED_EXCEEDED,
          f"exceeded set {exceeded} != expected {EXPECTED_EXCEEDED}",
          f"exactly {len(exceeded)} outgrown rows, forms and tracking issues as expected")
    check(ORIGIN_MISSING, not no_origin,
          f"rows with no origin pointer: {no_origin}",
          "every row carries an origin pointer")
    return results


# --- Output ----------------------------------------------------------------

RULE = "=" * 78


def print_summary(rows: list[ClauseRow], results: list[CheckResult]) -> None:
    print("PTC/GAL conformance-clause inventory\n" + RULE)
    print(f"{'clause':>8}  {'role':<16}  {'marker':<10}  {'issue':<6}  line")
    for row in rows:
        print(f"{row.clause_id:>8}  {row.role[:16]:<16}  {(row.marker_form or '-'):<10}  "
              f"{(row.marker_tracking_issue or '-'):<6}  {row.source_line}")
    print(RULE)
    for spec, expected in EXPECTED_ROW_COUNTS.items():
        print(f"  {spec}: {len([r for r in rows if r.spec == spec])}/{expected} rows")
    print(f"  total: {len(rows)}/{EXPECTED_TOTAL_ROWS} rows")
    print(f"  marked (not yet implemented): {len(marked_rows(rows))} of {len(rows)}")
    print(f"  exceeded (outgrown by the RI): {len(exceeded_rows(rows))} of {len(rows)}")
    print("  absence of EITHER marker CLAIMS implemented as written — #359")
    print(RULE)
    for result in results:
        print(f"  [{'PASS' if result.passed else 'FAIL'}] {result.name}: {result.reason}")


def main() -> None:
    default_spec_dir = Path(__file__).resolve().parents[2] / "spec"
    parser = argparse.ArgumentParser(
        description=(
            "Extract every conformance clause from spec/PTC-SPEC.md §8.2 and "
            "spec/GAL-SPEC.md §7.2-§7.4. Extraction only: implementation status "
            "is reported as the spec marks it, never adjudicated."
        )
    )
    parser.add_argument("--spec-dir", type=Path, default=default_spec_dir,
                        help=f"directory holding the two specs (default: {default_spec_dir})")
    parser.add_argument("--summary", action="store_true",
                        help="print a human-readable table instead of JSON")
    parser.add_argument("--pics", action="store_true",
                        help="emit the blank ISO/IEC 9646-7 proforma an implementer completes")
    parser.add_argument("--pics-ri", action="store_true",
                        help="emit the reference implementation's completed statement")
    args = parser.parse_args()

    if not args.spec_dir.is_dir():
        # The specifications are NOT vendored into the reference implementation; they are
        # maintained as their own licensed artifact. A reader hitting this has done nothing
        # wrong, so say where they live and how to point this command at them.
        print(f"ERROR: {args.spec_dir} is not a directory.", file=sys.stderr)
        print(
            "\nThe PTC and GAL specifications are maintained separately, at\n"
            "  https://github.com/wjatx/ptc-gal-standards\n\n"
            "Clone them and point this command at the checkout:\n"
            "  git clone https://github.com/wjatx/ptc-gal-standards\n"
            "  python3 -m safe_agents.contract.spec_clauses --summary \\\n"
            "      --spec-dir ptc-gal-standards\n",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        rows = extract_all(args.spec_dir)
    except SpecFormatError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    results = verify_extraction(rows)
    if args.pics or args.pics_ri:
        print(pics_proforma(rows, filled=args.pics_ri))
    elif args.summary:
        print_summary(rows, results)
    else:
        print(json.dumps([asdict(r) for r in rows], indent=2, ensure_ascii=False))

    failures = [r for r in results if not r.passed]
    for failure in failures:
        print(f"VIOLATION: {failure.name}: {failure.reason}", file=sys.stderr)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
