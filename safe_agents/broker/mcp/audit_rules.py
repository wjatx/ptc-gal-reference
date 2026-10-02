"""mcp.audit_rules — the MCP registry audit's rules, each pure and separately testable.

Every function here takes the parsed dataset (``mcp/audit_dataset.py``) and
returns findings; the keyed ones also return the rules they had to skip.
``mcp/audit.py`` runs them and says what the audit covers and what it does not.
"""

from __future__ import annotations

import base64
import json

from safe_agents.broker.grants.audit import AuditViolation
from safe_agents.broker.mcp.audit_dataset import (
    RECORD_PREFIX,
    ROW_PREFIX,
    UNPARSEABLE_ITEM,
    AuditedProposal,
    AuditedRecord,
    AuditedRow,
    McpAuditDataset,
)
from safe_agents.broker.mcp.proposals import _proposal_pk
from safe_agents.broker.mcp.registry import DynamoToolRegistry, _hmac_payload
from safe_agents.broker.mcp.signing import verify_admission_record
from safe_agents.channels.signing import KeyResolver

# Rule names. Every one carries the MCP_ prefix, so a report that lists these
# beside the grants auditor's rules stays unambiguous.
KEY_MATCHES_CONTENT = "MCP_KEY_MATCHES_CONTENT"
RECORD_SIGNATURE_VERIFIES = "MCP_RECORD_SIGNATURE_VERIFIES"
RECORD_PAYLOAD_MATCHES_STORED = "MCP_RECORD_PAYLOAD_MATCHES_STORED"
ROW_HMAC_INTACT = "MCP_ROW_HMAC_INTACT"
ROW_MATCHES_LAST_RECORD = "MCP_ROW_MATCHES_LAST_RECORD"
ORPHAN_ROW = "MCP_ORPHAN_ROW"
ORPHAN_RECORD = "MCP_ORPHAN_RECORD"
PROPOSAL_TAMPER = "MCP_PROPOSAL_TAMPER"
PROPOSAL_LIFECYCLE = "MCP_PROPOSAL_LIFECYCLE"

# The rules that cannot run without the store-integrity HMAC key, and the ones
# that cannot run without the issuer's verify keys.
HMAC_RULES: tuple[str, ...] = (ROW_HMAC_INTACT, PROPOSAL_TAMPER)
SIGNATURE_RULES: tuple[str, ...] = (RECORD_SIGNATURE_VERIFIES, RECORD_PAYLOAD_MATCHES_STORED)

ALL_RULES: tuple[str, ...] = (
    UNPARSEABLE_ITEM,
    KEY_MATCHES_CONTENT,
    RECORD_SIGNATURE_VERIFIES,
    RECORD_PAYLOAD_MATCHES_STORED,
    ROW_HMAC_INTACT,
    ROW_MATCHES_LAST_RECORD,
    ORPHAN_ROW,
    ORPHAN_RECORD,
    PROPOSAL_TAMPER,
    PROPOSAL_LIFECYCLE,
)

ANNOTATION_SIGNATURES_UNCHECKED = "mcp-record-signatures-unchecked"

# The sort key the store reads a row at (registry.py: DynamoToolRegistry._row_key).
_ROW_SK = DynamoToolRegistry._row_key("", "")["sk"]

# What a proposal's item-level status may be: put_proposal writes "pending",
# and consume_proposal flips it once to one of the other two (proposals.py).
_VALID_PROPOSAL_STATUSES = frozenset({"pending", "ratified", "rejected"})


# ---------------------------------------------------------------------------
# Key binding: the coordinate an item is stored under versus the one it names
# ---------------------------------------------------------------------------


def _expected_key(entry: AuditedRow | AuditedRecord | AuditedProposal) -> tuple[str, str] | None:
    """The key the store would write this item's content under, or None.

    Built with the stores' own key functions, so the auditor and the stores
    cannot disagree about the layout. ``None`` when the bytes did not parse:
    there is then no content to name a coordinate.
    """
    if isinstance(entry, AuditedRow):
        if entry.row is None:
            return None
        key = DynamoToolRegistry._row_key(entry.row.server_id, entry.row.tool_name)
        return key["pk"], key["sk"]
    if isinstance(entry, AuditedRecord):
        if entry.record is None:
            return None
        key = DynamoToolRegistry._record_key(
            entry.record.serverId, entry.record.toolName, entry.record.ts
        )
        return key["pk"], key["sk"]
    if entry.proposal is None:
        return None
    tool_def = entry.proposal.tool_def
    return _proposal_pk(tool_def.server_id, tool_def.tool_name), entry.proposal.proposal_id


def _key_bound(entry: AuditedRow | AuditedRecord | AuditedProposal) -> bool:
    """True when the item parses and is stored under the key its content names."""
    return _expected_key(entry) == (entry.pk, entry.sk)


def check_key_matches_content(dataset: McpAuditDataset) -> list[AuditViolation]:
    """MCP_KEY_MATCHES_CONTENT: an item sits under the key its own bytes name.

    The store looks items up by key, and the integrity mechanisms bind the
    ``data`` bytes, not the key. The row HMAC is over ``data`` alone, and an
    admission signature is over the record. So an intact, correctly signed
    record copied under another tool's key would be returned as that tool's
    ledger, with a signature that verifies. This rule closes that: a record's
    partition key must be the one built from its signed ``serverId`` and
    ``toolName``, and its sort key must be its signed ``ts``; a row and a
    proposal are held to the same standard against their HMAC'd bytes.

    Runs without key material. When the signature or HMAC rules are skipped it
    compares bytes nothing authenticated, which is still a structural finding
    and is no longer a statement about what was signed.
    """
    violations = []
    kinds = (
        ("registry row", dataset.rows),
        ("admission record", dataset.records),
        ("admission proposal", dataset.proposals),
    )
    for kind, entries in kinds:
        for entry in entries:
            expected = _expected_key(entry)
            if expected is None or expected == (entry.pk, entry.sk):
                continue  # unparseable is MCP_UNPARSEABLE_ITEM's finding
            violations.append(
                AuditViolation(
                    rule=KEY_MATCHES_CONTENT,
                    coordinate=entry.coordinate,
                    detail=(
                        f"{kind} stored at pk={entry.pk!r} sk={entry.sk!r} names "
                        f"pk={expected[0]!r} sk={expected[1]!r} in its own bytes; an "
                        "item copied under another coordinate's key explains nothing there"
                    ),
                )
            )
    return violations


# ---------------------------------------------------------------------------
# The admission ledger: signatures
# ---------------------------------------------------------------------------


def _index_mismatches(record: AuditedRecord) -> list[str] | None:
    """Index fields of a VERIFIED statement that disagree with the stored record.

    ``None`` means the comparison could not be made at all (the statement
    carries no index object, or the verified bytes are not a JSON object).
    """
    try:
        statement = json.loads(base64.b64decode(record.signature["payload"]))
        index = statement["predicate"]["record"]
        stored = json.loads(record.raw_data)
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(index, dict) or not isinstance(stored, dict):
        return None
    absent = object()
    return sorted(name for name, value in index.items() if stored.get(name, absent) != value)


def check_record_signatures(
    dataset: McpAuditDataset, key_resolver: KeyResolver | None
) -> tuple[list[AuditViolation], list[str]]:
    """MCP_RECORD_SIGNATURE_VERIFIES + MCP_RECORD_PAYLOAD_MATCHES_STORED.

    Every admission record must carry a DSSE envelope that verifies, under the
    issuer's key, over the item's stored bytes. Fails closed: no signature, no
    stored bytes, an unknown signer and a signature that does not verify are
    each a finding. The verification is ``verify_admission_record``, so what
    "verifies" means here is what it means for the promotion ledger: every
    signature present, the payload type, the statement and predicate types, a
    subject digest recomputed from the stored bytes, and a signature key id
    that matches the signer the statement names.

    The second rule runs only on an envelope that verified. The statement
    carries a few record fields in the clear so that an index can be built
    without parsing the record. The subject digest binds the record itself, so
    those fields are redundant with it, and this rule holds them to it: a field
    the index states must equal the same field of the stored record. Fields the
    record has and the index omits are not a finding. That is how the record
    grows.

    With no verify keys both rules are skipped, loudly.
    """
    if key_resolver is None:
        return [], list(SIGNATURE_RULES)

    violations: list[AuditViolation] = []

    def finding(rule: str, record: AuditedRecord, detail: str) -> None:
        violations.append(AuditViolation(rule=rule, coordinate=record.coordinate, detail=detail))

    for record in dataset.records:
        if record.signature is None:
            finding(
                RECORD_SIGNATURE_VERIFIES,
                record,
                f"admission record sk={record.sk} carries no DSSE signature; an admission "
                "mints callability, so it must be signed by the issuer identity",
            )
            continue
        if record.raw_data is None:
            finding(
                RECORD_SIGNATURE_VERIFIES,
                record,
                f"admission record sk={record.sk} has no stored bytes; a signature cannot "
                "be verified without the exact stored serialization",
            )
            continue
        result = verify_admission_record(record.raw_data, record.signature, key_resolver)
        if not result.ok:
            finding(
                RECORD_SIGNATURE_VERIFIES,
                record,
                f"admission record sk={record.sk} failed signature verification "
                f"({result.reason}) against its stored bytes under the issuer verify keys",
            )
            continue
        mismatched = _index_mismatches(record)
        if mismatched is None:
            finding(
                RECORD_PAYLOAD_MATCHES_STORED,
                record,
                f"admission record sk={record.sk} verifies, but its signed statement "
                "carries no readable record index to compare with the stored record",
            )
        elif mismatched:
            finding(
                RECORD_PAYLOAD_MATCHES_STORED,
                record,
                f"admission record sk={record.sk} verifies, but the index fields "
                f"{mismatched} in its signed statement disagree with the stored record",
            )
    return violations, []


# ---------------------------------------------------------------------------
# Rows: HMAC, and correspondence with the ledger
# ---------------------------------------------------------------------------


def check_row_hmac(
    dataset: McpAuditDataset, hmac_key: bytes | None
) -> tuple[list[AuditViolation], list[str]]:
    """MCP_ROW_HMAC_INTACT: a row edited outside the ceremony reads back quarantined.

    The read-side twin of the store's verify-on-read quarantine: HMAC the
    STORED BYTES verbatim against the item-level rowHash (never a
    re-serialization, so schema evolution can never fire this rule; mirrors
    grants/audit.py's GRANT_TAMPER). A missing ``data`` string or ``rowHash``
    is a finding too, since the item cannot be verified. Keyless posture SKIPS
    loudly. Note the recovery tension this surfaces and does not solve: a
    quarantined row is never auto-re-admitted (by design), and there is
    currently no sanctioned recovery ceremony.
    """
    if hmac_key is None:
        return [], [ROW_HMAC_INTACT]
    violations = []
    for row in dataset.rows:
        if (
            row.raw_data is None
            or row.stored_hash is None
            or _hmac_payload(row.raw_data, hmac_key) != row.stored_hash
        ):
            violations.append(
                AuditViolation(
                    rule=ROW_HMAC_INTACT,
                    coordinate=row.coordinate,
                    detail=(
                        "stored row bytes do not match the recomputed HMAC; the row "
                        "was written outside the ceremony and reads back quarantined"
                    ),
                )
            )
    return violations, []


def _slot_rows(dataset: McpAuditDataset) -> list[AuditedRow]:
    """The rows at the sort key the store actually reads (``get_tool``)."""
    return [row for row in dataset.rows if row.sk == _ROW_SK]


def _ledger_by_coordinate(dataset: McpAuditDataset) -> dict[str, list[AuditedRecord]]:
    """Admission records that can explain a row, per coordinate, oldest first.

    Only a record that parses and sits under the key its own bytes name counts.
    The order is the stored sort key, which for such a record is its ``ts``:
    the same order ``list_records`` returns, so "newest" here is the store's
    newest.
    """
    grouped: dict[str, list[AuditedRecord]] = {}
    for record in dataset.records:
        if _key_bound(record):
            grouped.setdefault(record.pk.removeprefix(RECORD_PREFIX), []).append(record)
    for entries in grouped.values():
        entries.sort(key=lambda entry: entry.sk)
    return grouped


def check_row_matches_last_record(dataset: McpAuditDataset) -> list[AuditViolation]:
    """MCP_ROW_MATCHES_LAST_RECORD: the ledger must EXPLAIN the row, not merely coexist.

    A row whose `def_hash` is not the newest record's `defHash` means callability was
    granted by something other than the ceremony. This is the rule that turns the
    append-only ledger from a log into evidence. A re-vet history is legal: older
    records name superseded hashes, and only the newest has to match.
    """
    ledger = _ledger_by_coordinate(dataset)
    violations = []
    for row in _slot_rows(dataset):
        records = ledger.get(row.pk.removeprefix(ROW_PREFIX))
        if row.row is None or not records:
            continue  # MCP_UNPARSEABLE_ITEM's finding, or MCP_ORPHAN_ROW's
        newest = records[-1]
        if newest.record.defHash != row.row.def_hash:
            violations.append(
                AuditViolation(
                    rule=ROW_MATCHES_LAST_RECORD,
                    coordinate=row.coordinate,
                    detail=(
                        f"row def_hash {row.row.def_hash[:12]} != newest record "
                        f"{newest.record.defHash[:12]} at {newest.sk}"
                    ),
                )
            )
    return violations


def check_orphans(dataset: McpAuditDataset) -> list[AuditViolation]:
    """MCP_ORPHAN_ROW + MCP_ORPHAN_RECORD: the two halves of ledger/row correspondence.

    ORPHAN_ROW: a row no admission record explains. Detectable ONLY by
    enumerating the table; manifest enumeration structurally cannot see it. A
    record counts only if it parses and names this coordinate in its own bytes,
    so a record copied here from another tool does not make the row look
    accounted for.

    ORPHAN_RECORD: a `TOOLREC#` with no row. Since the atomic
    `admit_tool_with_record` landed (2026-07-24) the ceremony can no longer
    produce one: a conditional-write conflict cancels BOTH legs. The rule is
    NOT dead code. It still catches historical (pre-atomicity) orphans and
    out-of-band tamper, and a finding dated after that change is tamper
    evidence rather than ceremony fallout.
    """
    ledger = _ledger_by_coordinate(dataset)
    stored_at = {record.pk.removeprefix(RECORD_PREFIX) for record in dataset.records}
    rows = {row.pk.removeprefix(ROW_PREFIX): row for row in _slot_rows(dataset)}
    violations = []
    for suffix in sorted(rows):
        if suffix in ledger:
            continue
        unusable = (
            " (records are stored under this key, but none parses and names this "
            "coordinate)"
            if suffix in stored_at
            else ""
        )
        violations.append(
            AuditViolation(
                rule=ORPHAN_ROW,
                coordinate=rows[suffix].coordinate,
                detail=(
                    "row has NO admission record that explains it: callability with "
                    f"no ceremony behind it{unusable}"
                ),
            )
        )
    orphaned = {
        record.pk.removeprefix(RECORD_PREFIX): record
        for record in dataset.records
        if record.pk.removeprefix(RECORD_PREFIX) not in rows
    }
    for suffix in sorted(orphaned):
        violations.append(
            AuditViolation(
                rule=ORPHAN_RECORD,
                coordinate=orphaned[suffix].coordinate,
                detail=(
                    "admission record with NO row: the ledger names a tool the "
                    "registry does not hold"
                ),
            )
        )
    return violations


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------


def check_proposals(
    dataset: McpAuditDataset, hmac_key: bytes | None
) -> tuple[list[AuditViolation], list[str]]:
    """MCP_PROPOSAL_LIFECYCLE + MCP_PROPOSAL_TAMPER (mirrors the grants pair).

    LIFECYCLE: the item-level status stays in the closed vocabulary; anything
    else is a hand edit. Read-side limit: no-resurrection (a consumed proposal
    never flips back to pending) is the store condition's job, and a
    point-in-time read cannot see a flip.

    TAMPER (HMAC key): recompute the HMAC over the stored data string, the
    read-side twin of the stores' ProposalIntegrityError. A tampered proposal
    would launder a swapped tool definition into a signed admission at ratify
    time. The mutable status is deliberately outside the HMAC.
    """
    violations = []
    for proposal in dataset.proposals:
        if not isinstance(proposal.status, str) or (
            proposal.status not in _VALID_PROPOSAL_STATUSES
        ):
            violations.append(
                AuditViolation(
                    rule=PROPOSAL_LIFECYCLE,
                    coordinate=proposal.coordinate,
                    detail=(
                        f"proposal {proposal.sk} has status {proposal.status!r}, outside "
                        f"the closed vocabulary {sorted(_VALID_PROPOSAL_STATUSES)}"
                    ),
                )
            )
    if hmac_key is None:
        return violations, [PROPOSAL_TAMPER]
    for proposal in dataset.proposals:
        if (
            proposal.raw_data is None
            or _hmac_payload(proposal.raw_data, hmac_key) != proposal.stored_hash
        ):
            violations.append(
                AuditViolation(
                    rule=PROPOSAL_TAMPER,
                    coordinate=proposal.coordinate,
                    detail=(
                        f"proposal {proposal.sk} failed HMAC verification; a tampered "
                        "proposal launders into a signed admission at ratify time"
                    ),
                )
            )
    return violations, []
