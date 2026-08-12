"""Pure, read-only rendering + classification for `show`/`diff` (#221 Phase 5,
item 3 of 4).

Today re-vetting starts blind: a drifted `def_hash` tells an operator THAT a
tool's admitted definition no longer matches what the server advertises, but
nothing shows WHAT moved. This module is the rendering — the actual
deliverable — kept separate from the CLI glue in `mcp/commands.py` so the
classification and text-formatting logic is unit-testable without a store, a
subprocess, or argparse.

Nothing here reads or writes anything. `compute_tool_def_hash`, the signed
set, and the discovery evaluator (`mcp/registry.py:13-16`, drift is COMPUTED
at read time, never persisted as a quarantine write) are untouched — this
module only formats what a caller already fetched.

Four tool classes, rendered deliberately differently:

  NEW        live but no stored row — unadmitted.
  WITHDRAWN  stored row but the server no longer advertises the tool — dead.
  UNCHANGED  both present, `def_hash` matches — rendered COMPACTLY (the whole
             point is that thirty-nine cosmetic-unchanged rows must not drown
             one dangerous DRIFT row).
  DRIFT      both present, `def_hash` differs. Broken down by the SIGNED-SET
             fields that can move (`server_id`/`tool_name` are fixed by the
             lookup coordinate itself):
               - `input_schema` and `output_schema` are CONTRACT changes —
                 machine-summarized (added/removed/retyped/required deltas),
                 never a raw-JSON dump. On a REMOTE (`streamable-http`)
                 server a newly-required input field is additionally a
                 DISCLOSURE ESCALATION (#232): its own block, rendered above
                 the contract summary, naming the destination — the vendor
                 now receives that field on every call. The identical delta
                 on a stdio server stays an ordinary contract change (the
                 child is spawned from our own image).
               - `description` is a STEERING change — the model-facing
                 injection vector a swapped server would use to steer the
                 agent. Rendered VERBATIM AND IN FULL, both old and new. Never
                 truncated, summarized, or whitespace-collapsed — summarizing
                 the injection vector would defeat the point of showing it.
               - The remaining metadata fields (title/icons/annotations/meta/
                 execution — signed since #223) are small values rendered
                 verbatim old/new when they move; an annotation flip like
                 `readOnlyHint` -> `destructiveHint` is exactly the drift the
                 widening exists to catch, so it is never summarized either.

Since #246 the stored row NESTS the ratified definition (`RegisteredTool.
tool_def`); a row whose server advertised no metadata at admission carries
None there, which renders honestly as absent -> present. The first re-vet
pins the real baseline.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum

from safe_agents.broker.mcp.registry import ToolReadResult
from safe_agents.broker.schemas.mcp_registry import (
    McpSnapshotEntry,
    McpToolDef,
    RegisteredTool,
    SchemaDelta,
    diff_input_schema,
)

# `SchemaDelta`/`diff_input_schema` are imported, not defined here: they are the
# `compute_tool_def_hash` companion primitive (the hash says THAT a definition
# moved; the delta says WHAT moved) and now live beside it in the schema layer
# as pure functions over schema dicts, with no store and no formatting. They
# stay importable from this module because it was their original home. The move
# is what lets a second consumer — a wrapper held to the
# `broker.schemas`-only allowlist — reuse the delta rather than restate it,
# which is how a codebase ends up with two notions of "changed".

# The McpToolDef advertised-metadata fields (schemas/mcp_registry.py) — SIGNED
# since #223, carried on RegisteredTool since the same change. Kept as a tuple
# here (not re-derived from the model) so a schema change to McpToolDef is a
# conscious edit to this list too. `output_schema` is deliberately absent: it
# is a CONTRACT-class field rendered through the schema-delta summarizer, not
# a verbatim-rendered value.
VERBATIM_METADATA_FIELDS = (
    "title",
    "icons",
    "annotations",
    "meta",
    "execution",
)


# ---------------------------------------------------------------------------
# input_schema — the CONTRACT delta
# ---------------------------------------------------------------------------


def render_schema_delta(delta: SchemaDelta) -> str:
    if delta.is_empty:
        return (
            "  input_schema: def_hash covers it but no top-level "
            "properties/required difference was detected (a deeper nested "
            "change may still be present — read the raw schemas if unsure)"
        )
    lines = ["  input_schema (CONTRACT change):"]
    for name in delta.added_fields:
        lines.append(f"    + added field: {name!r}")
    for name in delta.removed_fields:
        lines.append(f"    - removed field: {name!r}")
    for name, old_type, new_type in delta.retyped_fields:
        lines.append(f"    ~ retyped field: {name!r} ({old_type} -> {new_type})")
    for name in delta.newly_required:
        lines.append(f"    ! now required: {name!r}")
    for name in delta.no_longer_required:
        lines.append(f"    ! no longer required: {name!r}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# description — the STEERING delta (rendered verbatim, in full, always)
# ---------------------------------------------------------------------------


def render_description_delta(old: str, new: str) -> str:
    """Render both descriptions VERBATIM AND IN FULL — never truncated,
    summarized, or whitespace-collapsed. `description` is model-facing
    injection surface (a swapped server rewrites it to steer the agent), so
    summarizing it here would defeat the entire point of showing it."""
    return "\n".join(
        [
            "  description (STEERING change — rendered verbatim, in full; "
            "this is the model-facing injection vector):",
            "  --- ADMITTED description (verbatim) ---",
            old,
            "  --- LIVE description (verbatim) ---",
            new,
        ]
    )


# ---------------------------------------------------------------------------
# disclosure escalation — a newly-required input field on a REMOTE server (#232)
# ---------------------------------------------------------------------------


def render_disclosure_escalation(delta: SchemaDelta, destination: str) -> str:
    """Render the #232 tier: fields the vendor now RECEIVES that it did not
    before. On a remote (`url`) server `input_schema` is not merely
    model-facing surface — it is an exfiltration-channel specification,
    enumerating what the vendor gets on every call — so a newly-required
    field is categorically more serious there than on a locally-spawned
    child. Each escalated field states whether it is brand new or was
    already advertised as optional; the caller suppresses it from the
    contract summary below (one field, one mention — a name printed twice
    teaches a reader that the loud tier is duplicated noise, the TL11a
    re-derivation)."""
    added = set(delta.added_fields)
    lines = [
        "  !! DISCLOSURE ESCALATION (remote server) — every call now sends "
        f"these to {destination}:",
    ]
    for name in delta.newly_required:
        origin = (
            "a new field, never advertised before"
            if name in added
            else "previously advertised as optional"
        )
        lines.append(f"     ! now required: {name!r} ({origin})")
    lines.append(
        "     input_schema on a remote server enumerates what this vendor "
        "receives on every call."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# advertised metadata — SIGNED since #223
# ---------------------------------------------------------------------------

ALL_METADATA_FIELDS = ("output_schema",) + VERBATIM_METADATA_FIELDS


def render_advertised_metadata(tool_def: McpToolDef) -> str:
    """Live-side rendering of the advertised metadata fields for a tool with
    no admitted baseline to diff against (a NEW tool, or a first-admission
    preview). Everything shown here is covered by `def_hash` — admitting the
    tool ratifies these values too."""
    present = [name for name in ALL_METADATA_FIELDS if getattr(tool_def, name) is not None]
    if not present:
        return (
            "  advertised metadata (signed): none advertised "
            "(of: " + ", ".join(ALL_METADATA_FIELDS) + ")"
        )
    lines = ["  advertised metadata (signed — covered by def_hash):"]
    for name in present:
        lines.append(f"    {name}: {getattr(tool_def, name)!r}")
    return "\n".join(lines)


def render_metadata_delta(name: str, old: object, new: object) -> str:
    """Verbatim old/new rendering for ONE moved metadata field. These are
    small, signed values (an annotation flip like `readOnlyHint` ->
    `destructiveHint` is exactly the drift #223 widened the set to catch), so
    they are shown in full — absent renders as "not advertised", never as an
    empty container."""

    def _side(value: object) -> str:
        return "(not advertised)" if value is None else repr(value)

    return "\n".join(
        [
            f"  {name} (signed metadata change):",
            f"    admitted: {_side(old)}",
            f"    live:     {_side(new)}",
        ]
    )


def render_output_schema_delta(old: dict | None, new: dict | None) -> str:
    """`output_schema` is CONTRACT-class like `input_schema`: when both sides
    exist the delta is machine-summarized; an absent side renders as
    "not advertised" (a schema appearing or vanishing is itself the change)."""
    if old is not None and new is not None:
        delta = diff_input_schema(old, new)
        summary = render_schema_delta(delta).replace("input_schema", "output_schema", 1)
        return summary
    return "\n".join(
        [
            "  output_schema (CONTRACT change):",
            f"    admitted: {'(not advertised)' if old is None else repr(old)}",
            f"    live:     {'(not advertised)' if new is None else repr(new)}",
        ]
    )


# ---------------------------------------------------------------------------
# show — one stored row
# ---------------------------------------------------------------------------


def render_registered_tool(server_id: str, tool_name: str, result: ToolReadResult) -> str:
    """Render one `store.get_tool` result for `show`. Read-only; formats what
    the caller already fetched."""
    if result.quarantined:
        # #246: a quarantined read carries tool=None — tampered bytes are
        # evidence, never parsed — so there is no row content to show.
        return "\n".join(
            [
                f"=== {server_id}/{tool_name} ===",
                f"  [HMAC-QUARANTINED: {result.quarantine_reason}]",
                "  stored bytes failed verification and were not parsed; "
                "root-cause the tamper before touching this row (M6)",
            ]
        )
    if result.tool is None:
        return f"NOT FOUND: no registry row for {server_id}/{tool_name}"
    row = result.tool
    tool_def = row.tool_def
    lines = [
        f"=== {server_id}/{tool_name} ===",
        f"  status: {row.status.value}",
        f"  def_hash: {row.def_hash}",
        f"  admitted_by: {row.admitted_by}",
        f"  admitted_at: {row.admitted_at}",
        f"  input_schema: {tool_def.input_schema!r}",
    ]
    admitted_metadata = [
        name for name in ALL_METADATA_FIELDS if getattr(tool_def, name) is not None
    ]
    for name in admitted_metadata:
        lines.append(f"  {name}: {getattr(tool_def, name)!r}")
    if not admitted_metadata:
        lines.append(
            "  metadata: none ratified (the server advertised none at admission)"
        )
    lines += [
        "  description (verbatim):",
        tool_def.description,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# diff — one tool's classification + rendering
# ---------------------------------------------------------------------------


class DriftKind(str, Enum):
    NEW = "NEW"
    WITHDRAWN = "WITHDRAWN"
    UNCHANGED = "UNCHANGED"
    DRIFT = "DRIFT"


@dataclass
class ToolDiffResult:
    tool_name: str
    kind: DriftKind
    rendered: str
    #: True only when BOTH sides exist and their `description` text differs —
    #: i.e. the STEERING half of a DRIFT. Never True for NEW/WITHDRAWN (no
    #: admitted baseline to have moved away from) or UNCHANGED. Callers use it
    #: to route a coordinate into the verbatim-rendered, separately-acknowledged
    #: bucket: `description` is the model-facing injection vector, so a bulk
    #: ceremony must never let one blanket confirmation cover a change to it.
    description_changed: bool = False
    #: True only when the tool sits on a REMOTE (`streamable-http`) server AND
    #: the DRIFT includes a newly-required input field — the #232 disclosure
    #: escalation (the vendor now receives that field on every call). A caller
    #: with acknowledgment semantics routes it exactly like
    #: `description_changed`: a blanket bulk confirmation must never cover a
    #: field the agent must now send to a third party. Always False on stdio
    #: (the child is spawned from our own image) and for NEW/WITHDRAWN/
    #: UNCHANGED.
    disclosure_escalation: bool = False


def render_tool_diff(
    tool_name: str,
    stored: RegisteredTool | None,
    live_entry: McpSnapshotEntry | None,
    *,
    transport: str = "stdio",
    source: str | None = None,
) -> ToolDiffResult:
    """Classify + render ONE tool coordinate against its stored row (or lack
    of one). Pure — the caller resolved both `stored` and `live_entry`
    already; this only decides what class it is and how to show it.

    `transport`/`source` are the server's declared transport and destination
    (a `McpServerSnapshot` carries both) and make the CONTRACT rendering
    transport-aware (#232): on `"streamable-http"` a newly-required input
    field renders as a disclosure escalation naming `source` (the URL). The
    stdio default keeps every transport-blind caller byte-identical."""
    header = f"=== {tool_name} ==="

    if live_entry is None:
        assert stored is not None  # caller never asks about a tool absent from both
        rendered = "\n".join(
            [
                header,
                (
                    f"  status: WITHDRAWN — admitted (def_hash={stored.def_hash}) "
                    "but no longer advertised by the live server (dead tool; "
                    "absent from this snapshot)"
                ),
                f"  admitted_by: {stored.admitted_by}",
                f"  admitted_at: {stored.admitted_at}",
            ]
        )
        return ToolDiffResult(tool_name, DriftKind.WITHDRAWN, rendered)

    live_def = live_entry.tool_def
    live_hash = live_entry.def_hash

    if stored is None:
        rendered = "\n".join(
            [
                header,
                "  status: NEW — live but not admitted (no registry row)",
                render_advertised_metadata(live_def),
            ]
        )
        return ToolDiffResult(tool_name, DriftKind.NEW, rendered)

    if stored.def_hash == live_hash:
        # Compact by design (see module docstring): unchanged rows must not
        # drown a real DRIFT row in output volume.
        rendered = "\n".join([header, f"  status: unchanged (def_hash={live_hash})"])
        return ToolDiffResult(tool_name, DriftKind.UNCHANGED, rendered)

    stored_def = stored.tool_def  # the ratified definition, nested since #246
    lines = [
        header,
        f"  status: DRIFT — def_hash changed (admitted={stored.def_hash} live={live_hash})",
    ]
    disclosure_escalation = False
    if stored_def.input_schema != live_def.input_schema:
        delta = diff_input_schema(stored_def.input_schema, live_def.input_schema)
        # #232, the TL11a discipline re-derived for the base: on a remote
        # server a newly-required field renders in its own block, ABOVE the
        # contract summary, naming the destination. Deliberately narrow —
        # only newly required, only remote; promoting every remote schema
        # delta would put retyped optionals in the unmissable tier and train
        # reviewers to bulk-dismiss it (the M5 finding-flood failure).
        if transport == "streamable-http" and delta.newly_required:
            disclosure_escalation = True
            lines.append(
                render_disclosure_escalation(delta, source or "the remote server")
            )
            # One field, one mention: the escalation block already states
            # both the required flip and (when applicable) the addition, so
            # both lists suppress the escalated names here.
            escalated = set(delta.newly_required)
            remainder = SchemaDelta(
                added_fields=[n for n in delta.added_fields if n not in escalated],
                removed_fields=delta.removed_fields,
                retyped_fields=delta.retyped_fields,
                newly_required=[],
                no_longer_required=delta.no_longer_required,
            )
            if not remainder.is_empty:
                lines.append(render_schema_delta(remainder))
        else:
            lines.append(render_schema_delta(delta))
    else:
        lines.append("  input_schema: unchanged")
    description_changed = stored_def.description != live_def.description
    if description_changed:
        lines.append(render_description_delta(stored_def.description, live_def.description))
    else:
        lines.append("  description: unchanged")

    # Signed metadata (#223). A row admitted when the server advertised no
    # metadata carries None, so a live value honestly renders as absent ->
    # present. Unchanged fields stay silent — the M5 flood discipline: quiet
    # fields must not drown the one that moved.
    if stored_def.output_schema != live_def.output_schema:
        lines.append(render_output_schema_delta(stored_def.output_schema, live_def.output_schema))
    moved = [
        name
        for name in VERBATIM_METADATA_FIELDS
        if getattr(stored_def, name) != getattr(live_def, name)
    ]
    for name in moved:
        lines.append(
            render_metadata_delta(name, getattr(stored_def, name), getattr(live_def, name))
        )
    return ToolDiffResult(
        tool_name,
        DriftKind.DRIFT,
        "\n".join(lines),
        description_changed=description_changed,
        disclosure_escalation=disclosure_escalation,
    )


def render_diff_summary(results: list[ToolDiffResult]) -> str:
    """A one-line count so thirty-nine unchanged rows don't bury the summary
    either. `diff` is an inspection tool, not a gate — this never implies a
    pass/fail verdict, only a count per class."""
    counts = Counter(r.kind for r in results)
    per_kind = " ".join(f"{kind.value}={counts.get(kind, 0)}" for kind in DriftKind)
    return f"diff summary: {len(results)} tool(s) — {per_kind}"
