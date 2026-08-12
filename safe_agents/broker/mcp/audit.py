"""MCP registry integrity audit — SEED for #235, not the finished auditor.

## What this is

The MCP registry has **zero auditor coverage**: the 19-row grant-integrity suite
(`grants/audit.py`) knows nothing about `TOOLDEF#` / `TOOLREC#` / `TOOLPROP#`, so
every row and record in the registry is currently unaudited. #235 closes that.

This module is the *seed*: the six rules below were written and **run live against
the development registry on 2026-07-20** (9 records, 5 rows — all green) while
verifying that a proposal deletion had not damaged the ledger. Preserving them here
means #235 starts from working, floor-proven checks rather than from scratch.

It deliberately mirrors `grants/audit.py`: pure rules over a parsed dataset, findings
as `AuditViolation`, and a loud `skipped_rules` so a rule that could not run is never
reported green.

## What it is NOT

- **Not wired into the audit CI job.** `grants/audit.py` fans out per env; this does not.
- **Not complete.** #235 item 4 (the dead-tool / `WITHDRAWN` report) is NOT implemented.
- **Not acknowledgment-aware.** The #196 waiver ceremony (`grants/acknowledgments.py`)
  is not integrated, so there is no GREEN-with-annotations path yet.
- **Not runnable on the floor by any deployed identity.** See the IAM gap below.

## The IAM gap — read this before writing any more rules

`AuditorRole` and `WatcherRole` are scoped to `grantsTableArn` **only**
[verified 2026-07-20: `infra/lib/identity-stack.ts:517` (auditor) and `:615` (watcher);
`mcpRegistryTableArn` appears at `:123` broker, `:422` checker, `:491` maker — and
nowhere else]. **Neither auditor identity holds any grant on the MCP registry table** —
not `Scan`, not `Query`, not even `GetItem`.

So an MCP audit rule written today passes every in-memory test and is `AccessDenied` on
both floors. #235 must land an IAM change first. This is exactly the failure recorded as
lessons-ledger entry 49: *a test double implements the interface, not the authority.*

The live run that produced these rules used ambient admin credentials, which is why it
worked and why it is not evidence that the audit can run.

## Scan vs. manifest enumeration — a real design fork

`ORPHAN_ROW` (a row whose tool no later image declares) is **only** detectable by
enumerating the table itself. `diff` enumerates from the image-baked manifest and is
therefore *structurally incapable* of seeing such a row — that is #235's blind spot 3,
and it was hit live while writing this.

That means the audit needs `dynamodb:Scan` on the registry table, which no ceremony role
has by design and which the auditor role does not have yet. The alternative — enumerate
from the manifest — cannot ever detect the orphan class. **This fork should be decided
in #235 before the rules are finalized.** Granting `Scan` to `AuditorRole` (read-only,
already its posture on the grants table) looks right, but it is an authority change and
belongs to the issue, not to this seed.

## Record+row atomicity — DECIDED and shipped (product-wrapper Phase 1, 2026-07-24)

Per-coordinate record+row atomicity landed as `ToolRegistryStore.admit_tool_with_record`
(an Update-only 2-item `TransactWriteItems` — only `dynamodb:UpdateItem` needed, so no
IAM change; both ceremony call sites use it). NEW `ORPHAN_RECORD` findings can therefore
no longer be produced by the ceremony. The rule STAYS: it still catches historical
orphans (pre-atomicity artifacts) and out-of-band tamper — same reasoning as
`LEDGER_COUNTERPART` on the grants side. #235 should treat an `ORPHAN_RECORD` finding
dated after 2026-07-24 as tamper evidence, not ceremony fallout.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Iterable, Mapping

from safe_agents.broker.grants.audit import AuditViolation
from safe_agents.broker.mcp.registry import _hmac_payload
from safe_agents.broker.schemas.mcp_registry import RegisteredTool

# Rule names, in the grants-auditor idiom (see grants/audit.py rule vocabulary).
RECORD_SIGNATURE_VERIFIES = "MCP_RECORD_SIGNATURE_VERIFIES"
RECORD_PAYLOAD_MATCHES_STORED = "MCP_RECORD_PAYLOAD_MATCHES_STORED"
ROW_HMAC_INTACT = "MCP_ROW_HMAC_INTACT"
ROW_MATCHES_LAST_RECORD = "MCP_ROW_MATCHES_LAST_RECORD"
ORPHAN_ROW = "MCP_ORPHAN_ROW"
ORPHAN_RECORD = "MCP_ORPHAN_RECORD"

ALL_RULES = (
    RECORD_SIGNATURE_VERIFIES,
    RECORD_PAYLOAD_MATCHES_STORED,
    ROW_HMAC_INTACT,
    ROW_MATCHES_LAST_RECORD,
    ORPHAN_ROW,
    ORPHAN_RECORD,
)


@dataclass(frozen=True)
class AuditedRow:
    """One parsed `TOOLDEF#<server>#<tool>` row.

    raw_data / stored_hash are the integrity basis itself (#246 stored-bytes):
    ROW_HMAC_INTACT verifies the bytes verbatim, never a re-serialization —
    mirrors grants/audit.py's AuditedGrant.
    """

    server_id: str
    tool_name: str
    def_hash: str
    status: str
    row: RegisteredTool
    stored_hash: str
    raw_data: str = ""

    @property
    def coordinate(self) -> str:
        return f"{self.server_id}/{self.tool_name}"


@dataclass(frozen=True)
class AuditedRecord:
    """One parsed `TOOLREC#<server>#<tool>` admission record + its DSSE envelope."""

    server_id: str
    tool_name: str
    ts: str
    record: dict
    signature: dict | None

    @property
    def coordinate(self) -> str:
        return f"{self.server_id}/{self.tool_name}"


@dataclass(frozen=True)
class McpAuditDataset:
    rows: tuple[AuditedRow, ...]
    records: tuple[AuditedRecord, ...]


@dataclass(frozen=True)
class McpAuditReport:
    violations: tuple[AuditViolation, ...]
    skipped_rules: tuple[str, ...]
    rows_examined: int
    records_examined: int


# ---------------------------------------------------------------------------
# Parsing — pure, no store handles
# ---------------------------------------------------------------------------


def dataset_from_items(items: Iterable[Mapping]) -> McpAuditDataset:
    """Parse raw registry items into the audited dataset.

    Accepts whatever enumerated the table (Scan today; see the module docstring's
    Scan-vs-manifest fork). Unparseable items are skipped here rather than raising —
    #235 should add an UNPARSEABLE_ITEM rule mirroring the grants auditor, so a
    corrupt item is a finding instead of a silent omission.
    """
    rows: list[AuditedRow] = []
    records: list[AuditedRecord] = []
    for item in items:
        pk = item.get("pk", "")
        parts = pk.split("#")
        if len(parts) < 3:
            continue
        kind, server_id, tool_name = parts[0], parts[1], parts[2]
        if kind == "TOOLDEF":
            data = json.loads(item["data"])
            rows.append(
                AuditedRow(
                    server_id=server_id,
                    tool_name=tool_name,
                    def_hash=data["def_hash"],
                    status=data["status"],
                    row=RegisteredTool.model_validate(data),
                    stored_hash=item.get("rowHash", ""),
                    raw_data=item["data"],
                )
            )
        elif kind == "TOOLREC":
            sig = item.get("signature")
            records.append(
                AuditedRecord(
                    server_id=server_id,
                    tool_name=tool_name,
                    ts=item["sk"],
                    record=json.loads(item["data"]),
                    signature=json.loads(sig) if sig else None,
                )
            )
    return McpAuditDataset(rows=tuple(rows), records=tuple(records))


# ---------------------------------------------------------------------------
# The rules — each pure, each independently testable
# ---------------------------------------------------------------------------


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (mirrors channels/signing.py)."""
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode()
        + b" "
        + payload_type.encode()
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def check_record_signatures(
    dataset: McpAuditDataset, verify_keys: Mapping[str, str] | None
) -> tuple[list[AuditViolation], list[str]]:
    """RECORD_SIGNATURE_VERIFIES + RECORD_PAYLOAD_MATCHES_STORED.

    The second rule is the sharp one and must never be dropped as redundant: a
    signature that verifies over a payload DIFFERENT from the stored record bytes
    is precisely the forgery a naive "is it signed?" check waves through. Verify
    the signature, then verify the signed statement equals what is actually stored.

    Keyless posture (no verify keys) SKIPS both rules loudly rather than passing
    them — same discipline as the grants auditor.
    """
    if verify_keys is None:
        return [], [RECORD_SIGNATURE_VERIFIES, RECORD_PAYLOAD_MATCHES_STORED]

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    violations: list[AuditViolation] = []
    for rec in dataset.records:
        if rec.signature is None:
            violations.append(
                AuditViolation(
                    rule=RECORD_SIGNATURE_VERIFIES,
                    coordinate=rec.coordinate,
                    detail=f"record {rec.ts} is UNSIGNED; an admission mints callability",
                )
            )
            continue
        sig_block = rec.signature["signatures"][0]
        key_id = sig_block["keyid"]
        pem = verify_keys.get(key_id)
        if pem is None:
            violations.append(
                AuditViolation(
                    rule=RECORD_SIGNATURE_VERIFIES,
                    coordinate=rec.coordinate,
                    detail=f"record {rec.ts} signed by unknown key_id {key_id!r}",
                )
            )
            continue
        payload = base64.b64decode(rec.signature["payload"])
        try:
            serialization.load_pem_public_key(pem.encode()).verify(
                base64.b64decode(sig_block["sig"]),
                _dsse_pae(rec.signature["payloadType"], payload),
            )
        except InvalidSignature:
            violations.append(
                AuditViolation(
                    rule=RECORD_SIGNATURE_VERIFIES,
                    coordinate=rec.coordinate,
                    detail=f"record {rec.ts} signature does NOT verify against {key_id}",
                )
            )
            continue
        signed_record = json.loads(payload)["predicate"]["record"]
        if signed_record != rec.record:
            violations.append(
                AuditViolation(
                    rule=RECORD_PAYLOAD_MATCHES_STORED,
                    coordinate=rec.coordinate,
                    detail=(
                        f"record {rec.ts} has a VALID signature over DIFFERENT bytes "
                        "than are stored — the signed statement and the stored record "
                        "disagree"
                    ),
                )
            )
    return violations, []


def check_row_hmac(
    dataset: McpAuditDataset, hmac_key: bytes | None
) -> tuple[list[AuditViolation], list[str]]:
    """ROW_HMAC_INTACT — a row edited out-of-band is HMAC-quarantined.

    The read-side twin of the store's verify-on-read quarantine: HMAC the
    STORED BYTES verbatim against the item-level rowHash (#246 — never a
    re-serialization, so schema evolution can never fire this rule; mirrors
    grants/audit.py's GRANT_TAMPER). Keyless posture SKIPS loudly. Note the
    recovery tension this surfaces and does not solve: a quarantined row is
    never auto-re-admitted (by design), and there is currently no sanctioned
    recovery ceremony — that wedge is #236.
    """
    if hmac_key is None:
        return [], [ROW_HMAC_INTACT]
    violations = []
    for row in dataset.rows:
        if not row.raw_data or _hmac_payload(row.raw_data, hmac_key) != row.stored_hash:
            violations.append(
                AuditViolation(
                    rule=ROW_HMAC_INTACT,
                    coordinate=row.coordinate,
                    detail="row HMAC mismatch — the row was written outside the ceremony",
                )
            )
    return violations, []


def check_row_matches_last_record(dataset: McpAuditDataset) -> list[AuditViolation]:
    """ROW_MATCHES_LAST_RECORD — the ledger must EXPLAIN the row, not merely coexist.

    A row whose `def_hash` is not the newest record's `defHash` means callability was
    granted by something other than the ceremony. This is the rule that turns the
    append-only ledger from a log into evidence.
    """
    by_coord: dict[str, list[AuditedRecord]] = {}
    for rec in dataset.records:
        by_coord.setdefault(rec.coordinate, []).append(rec)
    violations = []
    for row in dataset.rows:
        recs = sorted(by_coord.get(row.coordinate, []), key=lambda r: r.ts)
        if not recs:
            continue  # ORPHAN_ROW's job, not this rule's
        last = recs[-1]
        if last.record.get("defHash") != row.def_hash:
            violations.append(
                AuditViolation(
                    rule=ROW_MATCHES_LAST_RECORD,
                    coordinate=row.coordinate,
                    detail=(
                        f"row def_hash {row.def_hash[:12]} != newest record "
                        f"{str(last.record.get('defHash'))[:12]} at {last.ts}"
                    ),
                )
            )
    return violations


def check_orphans(dataset: McpAuditDataset) -> list[AuditViolation]:
    """ORPHAN_ROW + ORPHAN_RECORD — the two halves of ledger/row correspondence.

    ORPHAN_RECORD: a `TOOLREC#` with no row. Since the atomic
    `admit_tool_with_record` landed (2026-07-24) the ceremony can no longer
    produce one — a conditional-write conflict cancels BOTH legs. The rule is
    NOT dead code: it still catches historical (pre-atomicity) orphans and
    out-of-band tamper (see the module docstring).

    ORPHAN_ROW: a row with no record at all. Detectable ONLY by enumerating the
    table; manifest enumeration structurally cannot see it.
    """
    row_coords = {r.coordinate for r in dataset.rows}
    rec_coords = {r.coordinate for r in dataset.records}
    violations = []
    for coord in sorted(row_coords - rec_coords):
        violations.append(
            AuditViolation(
                rule=ORPHAN_ROW,
                coordinate=coord,
                detail="row has NO admission record — callability with no ceremony behind it",
            )
        )
    for coord in sorted(rec_coords - row_coords):
        violations.append(
            AuditViolation(
                rule=ORPHAN_RECORD,
                coordinate=coord,
                detail="admission record with NO row — ceremony completed, row write did not",
            )
        )
    return violations


def run_audit(
    dataset: McpAuditDataset,
    *,
    hmac_key: bytes | None = None,
    verify_keys: Mapping[str, str] | None = None,
) -> McpAuditReport:
    """Run every rule. Rules that cannot run in this mode are SKIPPED loudly.

    A skipped rule is never reported green — an empty violations tuple over a
    keyless run means "we could not check", not "it passed".
    """
    violations: list[AuditViolation] = []
    skipped: list[str] = []

    sig_v, sig_s = check_record_signatures(dataset, verify_keys)
    violations += sig_v
    skipped += sig_s

    hmac_v, hmac_s = check_row_hmac(dataset, hmac_key)
    violations += hmac_v
    skipped += hmac_s

    violations += check_row_matches_last_record(dataset)
    violations += check_orphans(dataset)

    return McpAuditReport(
        violations=tuple(violations),
        skipped_rules=tuple(skipped),
        rows_examined=len(dataset.rows),
        records_examined=len(dataset.records),
    )
