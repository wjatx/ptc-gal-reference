"""mcp.audit_dataset — what the MCP registry audit judges, and how it is loaded.

The parsed form of the three item kinds the registry stores, a pure parser over
whole Dynamo-shaped items, and the sqlite loader. The rules live in
``mcp/audit.py``; this module holds no rule except the one a parser cannot
avoid owning: an item that does not parse is a finding.

**Nothing is dropped.** The grants auditor leaves an unparseable item out of
its dataset and reports it. Here the item is reported AND kept, with whatever
could be read from it, because two later rules need to know it exists. A row
whose bytes were edited into something that no longer parses is still a row at
that key, and the HMAC rule should judge its bytes. A record that no longer
parses still occupies its ledger slot, and the signature rule should say the
bytes do not verify. Leaving either out would turn one tamper into a
misleading orphan finding on its neighbour.

**The parsed model is never the integrity basis.** ``raw_data`` is the item's
``data`` string exactly as stored. Every keyed rule verifies those bytes
verbatim. The parsed ``row`` / ``record`` / ``proposal`` exists for the rules
that compare fields, and is ``None`` when the bytes do not parse.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from pydantic import ValidationError

from safe_agents.broker.grants.audit import AuditViolation, read_items_sqlite
from safe_agents.broker.mcp.proposals import McpAdmissionProposal
from safe_agents.broker.mcp.signing import McpAdmissionRecord
from safe_agents.broker.schemas.mcp_registry import RegisteredTool

UNPARSEABLE_ITEM = "MCP_UNPARSEABLE_ITEM"

# The three key prefixes the registry stores under (registry.py and
# proposals.py own the layout; these are used here only to dispatch).
ROW_PREFIX = "TOOLDEF#"
RECORD_PREFIX = "TOOLREC#"
PROPOSAL_PREFIX = "TOOLPROP#"
_PREFIXES = (ROW_PREFIX, RECORD_PREFIX, PROPOSAL_PREFIX)


def display_coordinate(pk: str, prefix: str) -> str:
    """``<server>/<tool>`` for a finding, from the item's key.

    Display only. Grouping and every comparison use the key itself, because a
    ``#`` inside a server id would make this split ambiguous.
    """
    server_id, _, tool_name = pk.removeprefix(prefix).partition("#")
    return f"{server_id}/{tool_name}"


@dataclass(frozen=True)
class AuditedRow:
    """One ``TOOLDEF#`` item: its key, its stored bytes, its item-level HMAC."""

    pk: str
    sk: str
    raw_data: str | None
    stored_hash: str | None
    row: RegisteredTool | None

    @property
    def coordinate(self) -> str:
        return display_coordinate(self.pk, ROW_PREFIX)


@dataclass(frozen=True)
class AuditedRecord:
    """One ``TOOLREC#`` item: its key, its stored bytes, its DSSE envelope.

    ``signature`` stays as loaded: a dict for a well-formed envelope, ``None``
    for an unsigned record, or the raw value when it did not decode. The
    verifier fails closed on anything that is not a dict, so a mangled
    attribute is a finding there and needs no special case here.
    """

    pk: str
    sk: str
    raw_data: str | None
    signature: dict | str | None
    record: McpAdmissionRecord | None

    @property
    def coordinate(self) -> str:
        return display_coordinate(self.pk, RECORD_PREFIX)


@dataclass(frozen=True)
class AuditedProposal:
    """One ``TOOLPROP#`` item: its key, its stored bytes, HMAC and status."""

    pk: str
    sk: str
    raw_data: str | None
    stored_hash: object
    status: object
    proposal: McpAdmissionProposal | None

    @property
    def coordinate(self) -> str:
        return display_coordinate(self.pk, PROPOSAL_PREFIX)


@dataclass(frozen=True)
class McpAuditDataset:
    """The parsed registry contents ``run_audit`` judges.

    ``parse_violations`` carries every ``MCP_UNPARSEABLE_ITEM`` finding
    collected while parsing, so a corrupt item reaches the report.
    """

    rows: tuple[AuditedRow, ...] = ()
    records: tuple[AuditedRecord, ...] = ()
    proposals: tuple[AuditedProposal, ...] = ()
    parse_violations: tuple[AuditViolation, ...] = ()


def _parse(model, data: object):
    """``(parsed, None)`` or ``(None, why)``. Never raises on stored bytes."""
    if not isinstance(data, str):
        return None, "the item carries no data string"
    try:
        return model.model_validate_json(data), None
    except ValidationError as exc:
        # The first error names the field; the full text can echo stored content.
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first["loc"]) or "<document>"
        return None, f"{first['type']} at {where} ({exc.error_count()} error(s))"


def dataset_from_items(items: Iterable[Mapping]) -> McpAuditDataset:
    """Parse raw table items into the audited dataset, dispatching on pk prefix.

    Takes whole items from whatever enumerated the table, and ignores every
    item kind that is not the registry's (grants, counters and the rest have
    their own auditor or their own integrity mechanism).
    """
    rows: list[AuditedRow] = []
    records: list[AuditedRecord] = []
    proposals: list[AuditedProposal] = []
    parse_violations: list[AuditViolation] = []

    def unparseable(pk: str, sk: object, why: str) -> None:
        parse_violations.append(
            AuditViolation(
                rule=UNPARSEABLE_ITEM,
                coordinate=pk,
                detail=f"item sk={sk!r} could not be parsed: {why}",
            )
        )

    for item in items:
        pk = item.get("pk")
        if not isinstance(pk, str) or not pk.startswith(_PREFIXES):
            continue  # not a registry item
        sk = item.get("sk")
        if not isinstance(sk, str):
            unparseable(pk, sk, "the item has no string sort key")
            sk = ""
        data = item.get("data")
        raw_data = data if isinstance(data, str) else None

        if pk.startswith(ROW_PREFIX):
            row, why = _parse(RegisteredTool, data)
            if why is not None:
                unparseable(pk, sk, why)
            stored_hash = item.get("rowHash")
            rows.append(
                AuditedRow(
                    pk=pk,
                    sk=sk,
                    raw_data=raw_data,
                    stored_hash=stored_hash if isinstance(stored_hash, str) else None,
                    row=row,
                )
            )

        elif pk.startswith(RECORD_PREFIX):
            record, why = _parse(McpAdmissionRecord, data)
            if why is not None:
                unparseable(pk, sk, why)
            signature = item.get("signature")
            if isinstance(signature, str):
                try:
                    signature = json.loads(signature)
                except ValueError:
                    pass  # kept raw: the verifier fails closed on a non-dict
            records.append(
                AuditedRecord(
                    pk=pk, sk=sk, raw_data=raw_data, signature=signature, record=record
                )
            )

        elif pk.startswith(PROPOSAL_PREFIX):
            proposal, why = _parse(McpAdmissionProposal, data)
            if why is not None:
                unparseable(pk, sk, why)
            proposals.append(
                AuditedProposal(
                    pk=pk,
                    sk=sk,
                    raw_data=raw_data,
                    stored_hash=item.get("proposalHash"),
                    status=item.get("status"),
                    proposal=proposal,
                )
            )

    return McpAuditDataset(
        rows=tuple(rows),
        records=tuple(records),
        proposals=tuple(proposals),
        parse_violations=tuple(parse_violations),
    )


def load_dataset_sqlite(db_path: str | Path) -> McpAuditDataset:
    """Read every item from a local ``broker.db`` and parse the registry's.

    The whole table, through the grants auditor's own reader. Auditing a
    filtered subset would silently exempt whatever the filter missed, and an
    orphan row is findable only by enumerating.

    One limit, shared with the grants loader: the substrate stores each item's
    attributes as one JSON column, and a column that is no longer JSON raises
    here. The audit command reports that as "could not run" (exit 2). It is
    loud and it is never read as clean, but it is not a named finding.
    """
    return dataset_from_items(read_items_sqlite(db_path))
