"""Nothing failed when the normative specs drifted from the shipped schemas.

`spec/README.md` asserts that "spec text follows the shipped contracts, never
the reverse". That is a claim about a process, and until this file nothing
enforced it: two real drifts shipped and were caught only by a human reading
the tables line by line — PTC-31's tool-definition hash after #223, and a
`Grant.hash` field the #246 integrity work removed from the code while the
spec table kept describing it.

## What it compares, and what it deliberately does not

**Field-NAME SETS, bidirectionally. Nothing else.**

Both directions have drifted for real, so both fail:

- *spec-ahead* (a field in the table, absent from Python) — a failure UNLESS
  **that row** carries the inline implementation-status marker (§3 of
  `spec/GAL-SPEC.md`). That escape hatch is the whole point of the marker
  convention: a clause may be normative ahead of the reference implementation,
  but it must say so where a reader — and this test — can see it.
- *code-ahead* (a field on the model, absent from the table) — **always** a
  failure. There is no marker for this direction and that is deliberate:
  shipped behaviour must be documented.

## The escape hatch is ROW-scoped, and that was found by mutation

The first cut of this file also accepted the section's `>
**Implementation status:**` blockquote as an excuse for any missing field in
that object's table. Mutation testing (insert an unmarked phantom `hash` row
into the `Grant` table; the check must go red) showed that rule GREEN: the
`Grant` section carries a blockquote for `certifiedUntil`, so it blanket-
excused the whole object — including a resurrection of the very field #246
removed, which is one of the two drifts this file exists to catch.

The rule below is both stricter and more faithful to the convention as
written. GAL §3: marked clauses carry the blockquote "wherever a reader can
encounter them", and "where a marked clause owns a field-table row, the row
carries the short inline form `(not yet implemented — #NNN)`". So the row form
is the field-level authority, the blockquote is the section-level one, and a
marked field needs BOTH — which `test_marked_rows_carry_the_section_blockquote`
enforces, so the exemption cannot be taken quietly in one place only.

## Types and required-ness are NOT compared

Types and required-ness are NOT compared, and adding them would produce
nothing but false positives. Spec types are prose (`string (ISO-8601 UTC) |
null`, `enum §3.1`, `number [0,1]`), and the spec's `Required` column asks a
different question than `FieldInfo.is_required()`: `SenderIdentity.evidence`,
`ProvenanceEntry.evidence` and `EventTrigger.chain_signatures` are all
always-present-on-the-wire (`Required: yes`) *and* have a `= []` default
(`is_required() is False`). Conditional requirements — `predicate` on
promotion-typed records, `triggeredBy` on demotion-typed ones — are enforced by
`model_validator`, not by field optionality, so the field table's per-row
"promotion-typed only" has no Pydantic counterpart at all.

## Why introspection on one side and regex on the other

The Python side is read by introspection because it is authoritative and
exact: every model here is Pydantic v2 with `extra="forbid"`, so
`model_fields` IS the complete accepted key set (asserted below, so the check
cannot quietly weaken if a model stops forbidding extras).

The contract markdown (`broker/SCHEMAS.md`, `channels/SCHEMAS.md`) is
deliberately NOT read: it disclaims its own authority in favour of the Python,
and is already stale in at least one place. Comparing the specs against it
would compare two derived documents and let the code drift from both.

## The alias map is mandatory, not a convenience

PTC §5.1 names the object `Envelope`; it ships as `EventTrigger`; and
`Envelope` is separately taken in this codebase by
`safe_agents.broker.schemas.envelope` — the *risk* envelope, a completely
different object. Resolving spec names to classes by name would have compared
the wrong two objects and reported green.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import BaseModel

from safe_agents.broker.schemas.evidence import (
    ConfidenceArtifact,
    CorroborationRecord,
    DemotionSignal,
)
from safe_agents.broker.schemas.grant import Grant
from safe_agents.broker.schemas.promotion_record import PromotionRecord
from safe_agents.channels.schemas.event_trigger import (
    ChainSignature,
    EventTrigger,
    ProvenanceEntry,
    SenderIdentity,
)

# <root>/safe_agents/broker/tests/ -> parents[3] == repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SPEC_DIR = _REPO_ROOT / "spec"

# The specifications are maintained in their own repository (https://github.com/wjatx/ptc-gal-standards) and are NOT
# vendored here, so this whole module is conditional. Skipping is correct rather than failing:
# the drift it guards is between spec TEXT and shipped schemas, and with no spec text present
# there is no drift to detect. Clone the specs beside this tree, or pass --spec-dir, to run it.
pytestmark = pytest.mark.skipif(
    not _SPEC_DIR.is_dir(),
    reason="specifications not present; they live at https://github.com/wjatx/ptc-gal-standards",
)

_PTC = "PTC-SPEC.md"
_GAL = "GAL-SPEC.md"

# Spec object name -> shipped Pydantic class. Explicit on purpose; see module
# docstring. A name collision here is silent and green, which is why nothing
# resolves by name.
_ALIASES: dict[tuple[str, str], type[BaseModel]] = {
    (_PTC, "Envelope"): EventTrigger,
    (_PTC, "SenderIdentity"): SenderIdentity,
    (_PTC, "ProvenanceEntry"): ProvenanceEntry,
    (_PTC, "ChainSignature"): ChainSignature,
    (_GAL, "Grant"): Grant,
    (_GAL, "PromotionRecord"): PromotionRecord,
    (_GAL, "ConfidenceArtifact"): ConfidenceArtifact,
    (_GAL, "DemotionSignal"): DemotionSignal,
    (_GAL, "CorroborationRecord"): CorroborationRecord,
}

# Key off the first column only. The header shape is NOT uniform: PTC and GAL
# §5.1/§5.2 carry a `Required` column, GAL §5.3 does not.
_HEADER_RE = re.compile(r"^\| *Field *\|")
_DELIMITER_RE = re.compile(r"^\|[\s\-:|]+\|\s*$")
_HEADING_RE = re.compile(r"^(#{1,6}) +(?:\d+(?:\.\d+)* +)?(.*?)\s*$")
# The heading is not a sufficient object name: GAL §5.3 holds three objects
# under one heading, each introduced by a bold lead-in line above its table.
_LEAD_IN_RE = re.compile(r"^\*\*([A-Za-z][A-Za-z0-9_]*)\*\*")
_FIELD_CELL_RE = re.compile(r"^\| *`([^`]+)`")

# The two forms of the implementation-status marker, per spec/GAL-SPEC.md §3.
_INLINE_MARKER_RE = re.compile(r"not yet implemented", re.IGNORECASE)
_BLOCK_MARKER_RE = re.compile(r"^\s*>\s*\*\*Implementation status:\*\*")


@dataclass(frozen=True)
class SpecTable:
    """One `| Field |` table, with the object it documents."""

    spec: str
    object_name: str
    heading: str
    line_no: int  # 1-based, of the header row
    fields: tuple[str, ...]
    marked_fields: frozenset[str]  # rows carrying the inline marker
    section_marked: bool  # the object's own prose carries the blockquote marker


def _heading_level(line: str) -> int | None:
    m = _HEADING_RE.match(line)
    return len(m.group(1)) if m else None


def _resolve_object_name(lines: list[str], header_idx: int) -> tuple[str, str]:
    """Return (object_name, heading) for the table whose header is at header_idx.

    Back-scan for a bold lead-in, stopping at the enclosing heading — a lead-in
    from a previous section must never name this table's object. Fall back to
    the first token of the heading text (`### 5.3 ProvenanceEntry (one hop)` ->
    `ProvenanceEntry`).
    """
    heading = ""
    lead_in = ""
    for i in range(header_idx - 1, -1, -1):
        line = lines[i]
        if _heading_level(line) is not None:
            heading = _HEADING_RE.match(line).group(2)
            break
        if not lead_in:
            m = _LEAD_IN_RE.match(line)
            if m:
                lead_in = m.group(1)
    name = lead_in or (heading.split()[0] if heading else "")
    return name, heading


def _section_is_marked(lines: list[str], header_idx: int, table_end: int) -> bool:
    """Does the object's own section carry the blockquote status marker?

    Scoped to the object: from the enclosing heading (or bold lead-in, if one
    is nearer) through to the next heading or next bold lead-in after the
    table. A marker belonging to a sibling object must not excuse this one.
    """
    start = 0
    for i in range(header_idx - 1, -1, -1):
        if _heading_level(lines[i]) is not None or _LEAD_IN_RE.match(lines[i]):
            start = i
            break
    end = len(lines)
    for i in range(table_end, len(lines)):
        if _heading_level(lines[i]) is not None or _LEAD_IN_RE.match(lines[i]):
            end = i
            break
    return any(_BLOCK_MARKER_RE.match(line) for line in lines[start:end])


def _parse_spec(spec_name: str) -> list[SpecTable]:
    path = _SPEC_DIR / spec_name
    assert path.is_file(), f"spec file not found: {path}"
    lines = path.read_text(encoding="utf-8").splitlines()

    tables: list[SpecTable] = []
    for idx, line in enumerate(lines):
        if not _HEADER_RE.match(line):
            continue
        assert _DELIMITER_RE.match(lines[idx + 1]), (
            f"{spec_name}:{idx + 2}: a `| Field |` header row must be followed by a "
            "`|---|` delimiter row; the table parser cannot read this table."
        )
        fields: list[str] = []
        marked: set[str] = set()
        row = idx + 2
        while row < len(lines) and lines[row].startswith("|"):
            m = _FIELD_CELL_RE.match(lines[row])
            assert m, (
                f"{spec_name}:{row + 1}: field-table row does not start with a "
                f"backticked field name: {lines[row]!r}"
            )
            name = m.group(1)
            fields.append(name)
            if _INLINE_MARKER_RE.search(lines[row]):
                marked.add(name)
            row += 1

        object_name, heading = _resolve_object_name(lines, idx)
        tables.append(
            SpecTable(
                spec=spec_name,
                object_name=object_name,
                heading=heading,
                line_no=idx + 1,
                fields=tuple(fields),
                marked_fields=frozenset(marked),
                section_marked=_section_is_marked(lines, idx, row),
            )
        )
    return tables


def _all_tables() -> list[SpecTable]:
    return _parse_spec(_PTC) + _parse_spec(_GAL)


# Built at IMPORT time, which is why the skipif above is not enough on its own: a module-level
# read runs before any mark is consulted, so an absent spec/ becomes a collection ERROR rather
# than a skip. Guard the read itself, and let the mark do the skipping.
_TABLES = _all_tables() if _SPEC_DIR.is_dir() else []
_BY_KEY = {(t.spec, t.object_name): t for t in _TABLES}


def _ids(tables: list[SpecTable]) -> list[str]:
    return [f"{t.spec.split('-')[0]}:{t.object_name}" for t in tables]


def test_every_spec_field_table_is_registered() -> None:
    """A new object in a spec must be added to the alias map, not ignored.

    Without this, adding a §5.7 to PTC would be covered by nothing and the
    suite would stay green — the exact silence this file exists to remove.
    """
    unregistered = [
        f"{t.spec} §{t.heading!r} (line {t.line_no}) -> object {t.object_name!r}"
        for t in _TABLES
        if (t.spec, t.object_name) not in _ALIASES
    ]
    assert not unregistered, (
        "Spec field tables with no entry in _ALIASES:\n  "
        + "\n  ".join(unregistered)
        + "\n\nAdd each to _ALIASES in this file, mapping the SPEC's object name to the "
        "shipped Pydantic class (they differ: PTC `Envelope` ships as `EventTrigger`). "
        "Do not resolve by name."
    )


def test_every_registered_object_has_a_spec_table() -> None:
    """The reverse: an object in the alias map whose table vanished."""
    missing = [f"{spec} {name}" for (spec, name) in _ALIASES if (spec, name) not in _BY_KEY]
    assert not missing, (
        "Registered objects with no `| Field |` table found in the spec:\n  "
        + "\n  ".join(missing)
        + "\n\nEither the spec section was removed/renamed (update _ALIASES) or the table "
        "was reshaped so the parser no longer sees it (header must match '| Field |')."
    )


@pytest.mark.parametrize("table", _TABLES, ids=_ids(_TABLES))
def test_model_forbids_extra_fields(table: SpecTable) -> None:
    """`model_fields` is only the complete key set while extras are forbidden.

    If a model stops forbidding extras, its accepted key set becomes open and
    the comparison below silently stops meaning what it claims.
    """
    model = _ALIASES[(table.spec, table.object_name)]
    extra = model.model_config.get("extra")
    assert extra == "forbid", (
        f"{model.__module__}.{model.__name__} has extra={extra!r}, not 'forbid'. "
        f"The {table.spec} §{table.heading} field table can no longer be checked against "
        "it: an open model accepts keys no table documents. Restore "
        "`model_config = ConfigDict(extra=\"forbid\")`."
    )


@pytest.mark.parametrize("table", _TABLES, ids=_ids(_TABLES))
def test_spec_fields_are_implemented(table: SpecTable) -> None:
    """spec-ahead drift: a documented field the shipped model does not have."""
    model = _ALIASES[(table.spec, table.object_name)]
    shipped = set(model.model_fields)
    unimplemented = sorted(f for f in table.fields if f not in shipped)
    # ROW-scoped, never section-scoped — see module docstring.
    unexcused = [f for f in unimplemented if f not in table.marked_fields]
    assert not unexcused, (
        f"SPEC-AHEAD DRIFT — {table.spec} §{table.heading} documents field(s) that "
        f"{model.__module__}.{model.__name__} does not have:\n"
        f"    {', '.join(unexcused)}\n"
        f"  (table at {table.spec}:{table.line_no}; shipped fields: "
        f"{', '.join(sorted(shipped))})\n\n"
        "Do ONE of these:\n"
        "  - If the field was removed from the code deliberately, delete its row from the "
        "spec table (spec text follows the shipped contracts, never the reverse).\n"
        "  - If the clause is deliberately normative AHEAD of the implementation, mark it: "
        "append `*(not yet implemented — #NNN)*` to the field name cell, and add the "
        "blockquote line `> **Implementation status:** NORMATIVE, NOT YET IMPLEMENTED in "
        "the reference implementation (tracking: #NNN).` to the object's section "
        "(spec/GAL-SPEC.md §3). BOTH are required; the row form is what excuses the "
        "field here.\n"
        "  - If the field should exist, implement it on the model."
    )


@pytest.mark.parametrize("table", _TABLES, ids=_ids(_TABLES))
def test_marked_rows_carry_the_section_blockquote(table: SpecTable) -> None:
    """The exemption may not be taken quietly in the table alone.

    GAL §3 requires a marked clause to be flagged "wherever a reader can
    encounter them". A row-only marker would let a normative-ahead field slip
    past a reader who skims the prose, and past this file's row-scoped check
    with nothing else to notice.
    """
    if not table.marked_fields:
        return
    assert table.section_marked, (
        f"{table.spec} §{table.heading} marks field(s) "
        f"{', '.join(sorted(table.marked_fields))} `(not yet implemented — #NNN)` in the "
        f"table (line {table.line_no}) but the object's section carries no "
        "`> **Implementation status:**` blockquote. Per spec/GAL-SPEC.md §3 a marked "
        "clause is flagged wherever a reader can encounter it — add the blockquote line "
        "to this object's section, naming the same tracking issue."
    )


@pytest.mark.parametrize("table", _TABLES, ids=_ids(_TABLES))
def test_shipped_fields_are_specified(table: SpecTable) -> None:
    """code-ahead drift: a shipped field no spec table documents.

    Always a failure. There is no marker for this direction on purpose —
    shipped behaviour must be documented.
    """
    model = _ALIASES[(table.spec, table.object_name)]
    documented = set(table.fields)
    undocumented = sorted(f for f in model.model_fields if f not in documented)
    assert not undocumented, (
        f"CODE-AHEAD DRIFT — {model.__module__}.{model.__name__} ships field(s) that "
        f"{table.spec} §{table.heading} does not document:\n"
        f"    {', '.join(undocumented)}\n"
        f"  (table at {table.spec}:{table.line_no})\n\n"
        "Add a row per field to that table: `| `name` | <abstract type> | <Required> | "
        "<description> |`, matching the column count of the surrounding table (it is not "
        "uniform across sections). There is deliberately NO implementation-status marker "
        "for this direction — a shipped field is behaviour, and behaviour must be "
        "specified. If the field should not exist, remove it from the model instead."
    )


def test_ptc_taint_is_derived_not_a_field() -> None:
    """PTC §5.4 asserts the ABSENCE of a taint field — pin that absence.

    "There is deliberately no writable taint field on the envelope"; taint is a
    derived property. A field-name-set comparison would catch `tainted`
    appearing as a model field only if someone also added it to the §5.1 table,
    so the invariant gets its own assertion.
    """
    assert "tainted" not in EventTrigger.model_fields, (
        "PTC §5.4 states there is deliberately NO writable taint field on the envelope "
        "(taint derives from the provenance chain). `tainted` is now a model field on "
        "EventTrigger. Either restore it as a derived @property, or — if the design "
        "genuinely changed — rewrite PTC §5.4, which currently specifies the opposite."
    )
    assert isinstance(getattr(EventTrigger, "tainted", None), property), (
        "PTC §5.4 specifies envelope taint as a derived property "
        "(tainted iff any provenance entry is labelled `untrusted`). "
        "`EventTrigger.tainted` is no longer a property — the derivation the spec "
        "describes has no implementation."
    )
