"""mcp.audit — read-only integrity audit of the admitted-tool registry.

Pure rules (``mcp/audit_rules.py``) over an already-loaded dataset
(``mcp/audit_dataset.py``), findings as the grants auditor's ``AuditViolation``,
and a loud ``skipped_rules`` so a rule that could not run is never reported
green. It mirrors ``grants/audit.py`` in shape and never writes.

## Where it runs

On a local (sqlite) store it runs through the one audit door an operator
already has, ``python -m safe_agents.broker.grants.audit_command --sqlite PATH``,
which audits the grants and this registry from one read of the file and prints
how many items of each kind it examined (#143).

On the cloud floor it does not run. No deployed audit identity can read the
registry table, so a rule here would pass every in-memory test and be
``AccessDenied`` on the floor; the first change there is IAM (#96). The audit
command says so in its report when it is given a DynamoDB table.

## Modes

Decided by what the caller can supply, never by a flag:

  hmac_key      present: ``MCP_ROW_HMAC_INTACT`` and ``MCP_PROPOSAL_TAMPER`` run.
                Absent: both are named in ``skipped_rules``.
  key_resolver  the ISSUER's verify keys. Present: the two signature rules run.
                Absent: both are named in ``skipped_rules`` and the report
                carries an annotation saying no signature was checked.

## Rules

  MCP_UNPARSEABLE_ITEM              a registry item that does not parse is a
                                    finding, and it is still judged by every
                                    rule that needs only its bytes or its key
  MCP_KEY_MATCHES_CONTENT           an item's key names the coordinate that its
                                    integrity-bound bytes name
  MCP_RECORD_SIGNATURE_VERIFIES     (verify keys) every admission record's
                                    stored bytes verify under the issuer key,
                                    through ``verify_admission_record``
  MCP_RECORD_PAYLOAD_MATCHES_STORED (verify keys) the audit-index fields a
                                    verified statement carries in the clear
                                    agree with the stored record
  MCP_ROW_HMAC_INTACT               (HMAC key) a row's stored bytes verify
                                    against its item-level ``rowHash``
  MCP_ROW_MATCHES_LAST_RECORD       a row's ``def_hash`` is the one its newest
                                    admission record ratified
  MCP_ORPHAN_ROW                    every row has an admission record
  MCP_ORPHAN_RECORD                 every admission record has a row
  MCP_PROPOSAL_TAMPER               (HMAC key) a proposal's stored bytes verify
                                    against its ``proposalHash``
  MCP_PROPOSAL_LIFECYCLE            a proposal's status is in the closed
                                    vocabulary

## Why the signature rule is the shared verifier over stored bytes

This module began as a seed that rebuilt its own idea of the signed statement
and compared it with the parsed record. That comparison stopped matching the
day ``McpAdmissionRecord`` grew a field, so it reported every honest record as
a mismatch, and it never checked the payload type, the predicate type, the
subject digest, the signer binding or any signature past the first. The rule
now calls ``verify_admission_record``, the same verification the promotion
ledger uses, over the item's ``data`` string exactly as stored. Record growth
cannot move it, and a byte changed in the stored record does.

## What is not here

- The cloud arm (#96), above.
- A dead-tool report. A row whose tool no image declares any more is not
  flagged, because this audit reads the store and has no manifest (#96).
- Rollback. A coordinate removed whole, or a store put back to an earlier
  state that was itself consistent, reads clean. Nothing here records a head
  that a later read could be compared with.
- Waivers. No rule here is in the acknowledgment ceremony's waivable
  vocabulary (``grants/acknowledgments.py``), so every finding stays red until
  the store is fixed.
- Anything the broker does at connect. The broker checks the row HMAC and the
  discovery hash; it does not verify an admission record's signature. This
  audit is where that signature is verified.
"""

from __future__ import annotations

from dataclasses import dataclass

from safe_agents.broker.grants.audit import AuditViolation
from safe_agents.broker.mcp.audit_dataset import (
    UNPARSEABLE_ITEM,
    McpAuditDataset,
    dataset_from_items,
    load_dataset_sqlite,
)
from safe_agents.broker.mcp.audit_rules import (
    ALL_RULES,
    ANNOTATION_SIGNATURES_UNCHECKED,
    HMAC_RULES,
    KEY_MATCHES_CONTENT,
    ORPHAN_RECORD,
    ORPHAN_ROW,
    PROPOSAL_LIFECYCLE,
    PROPOSAL_TAMPER,
    RECORD_PAYLOAD_MATCHES_STORED,
    RECORD_SIGNATURE_VERIFIES,
    ROW_HMAC_INTACT,
    ROW_MATCHES_LAST_RECORD,
    SIGNATURE_RULES,
    check_key_matches_content,
    check_orphans,
    check_proposals,
    check_record_signatures,
    check_row_hmac,
    check_row_matches_last_record,
)
from safe_agents.channels.signing import KeyResolver

__all__ = [
    "ALL_RULES",
    "ANNOTATION_SIGNATURES_UNCHECKED",
    "HMAC_RULES",
    "KEY_MATCHES_CONTENT",
    "ORPHAN_RECORD",
    "ORPHAN_ROW",
    "PROPOSAL_LIFECYCLE",
    "PROPOSAL_TAMPER",
    "RECORD_PAYLOAD_MATCHES_STORED",
    "RECORD_SIGNATURE_VERIFIES",
    "ROW_HMAC_INTACT",
    "ROW_MATCHES_LAST_RECORD",
    "SIGNATURE_RULES",
    "UNPARSEABLE_ITEM",
    "McpAuditDataset",
    "McpAuditReport",
    "dataset_from_items",
    "load_dataset_sqlite",
    "run_audit",
]


@dataclass(frozen=True)
class McpAuditReport:
    """Outcome of one ``run_audit`` pass.

    ``skipped_rules`` names every rule that could not run in this mode. The
    counts say what was examined, so an empty ``violations`` over an empty
    registry is distinguishable from a real pass. ``annotations`` names what a
    reader must know to read the result correctly.
    """

    violations: tuple[AuditViolation, ...]
    skipped_rules: tuple[str, ...]
    rows_examined: int
    records_examined: int
    proposals_examined: int = 0
    annotations: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# The audit
# ---------------------------------------------------------------------------


def run_audit(
    dataset: McpAuditDataset,
    *,
    hmac_key: bytes | None = None,
    key_resolver: KeyResolver | None = None,
) -> McpAuditReport:
    """Run every rule the supplied material allows; skip the rest LOUDLY.

    ``key_resolver`` is the ISSUER's verify-key resolver. The admission ledger
    is issuer-signed, so a record signed by any other key, the evaluator's
    included, is an unknown signer and a finding.

    A skipped rule is never reported green. An empty violations tuple over a
    keyless run means "we could not check", not "it passed".

    Read-side limit, the same one the grants auditor states: this judges the
    store as it stands. It proves the rows, the ledger and the proposals are
    consistent with each other and with their integrity material. It cannot
    replay how the state was reached, and it does not know which tools any
    image declares.
    """
    violations: list[AuditViolation] = list(dataset.parse_violations)
    skipped: list[str] = []
    annotations: list[str] = []

    violations += check_key_matches_content(dataset)

    signature_violations, signature_skipped = check_record_signatures(dataset, key_resolver)
    violations += signature_violations
    skipped += signature_skipped
    if signature_skipped:
        annotations.append(
            f"{ANNOTATION_SIGNATURES_UNCHECKED}: no issuer verify keys are configured, "
            f"so none of the {len(dataset.records)} admission record signature(s) was "
            "checked, and MCP_KEY_MATCHES_CONTENT compared record bytes that nothing "
            "authenticated"
        )

    hmac_violations, hmac_skipped = check_row_hmac(dataset, hmac_key)
    violations += hmac_violations
    skipped += hmac_skipped

    violations += check_row_matches_last_record(dataset)
    violations += check_orphans(dataset)

    proposal_violations, proposal_skipped = check_proposals(dataset, hmac_key)
    violations += proposal_violations
    skipped += proposal_skipped

    return McpAuditReport(
        violations=tuple(violations),
        skipped_rules=tuple(skipped),
        rows_examined=len(dataset.rows),
        records_examined=len(dataset.records),
        proposals_examined=len(dataset.proposals),
        annotations=tuple(annotations),
    )
