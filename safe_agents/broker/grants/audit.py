"""grants.audit — read-only grant-integrity auditor (#62).

Pure functions over an already-loaded grants-table dataset → typed findings.
The auditor NEVER writes: the only AWS-touching function is ``load_dataset``,
and its only API call is a paginated Scan. Everything else operates on the
parsed ``AuditDataset``, so the same rules run identically against production
items and in-memory fixtures (the #62 CI policy table).

Two loaders, one parser (#252): ``load_dataset`` (DynamoDB Scan) and
``load_dataset_sqlite`` (a local ``broker.db``) both hand whole items to
``dataset_from_items``, so a local floor is audited by the same rules under the
same names as a cloud floor — a differential test asserts identical findings
from identical items through both loaders. ``run_grants_audit`` is the
invocation path over either.

Two modes, decided by what the caller can supply:

  keyed   — ``hmac_key`` present: every rule runs, including the HMAC twins of
            the stores' verify-on-read quarantine (GRANT_TAMPER,
            PROPOSAL_TAMPER, QUARANTINED_NO_RAISE).
  keyless — no ``hmac_key``: the CI mode. The namespace-split doctrine keeps
            BROKER_HMAC_KEY away from CI identities, so HMAC-dependent rules
            land in ``AuditReport.skipped_rules`` — LOUDLY, never silently
            green. Signature verification is gated the same way on
            ``record_key_resolver``.

Rules (each documented at its check site in run_audit):

  LEDGER_COUNTERPART        every grant has a bootstrap/promotion record
  LEVEL_LEDGER_CONSISTENT   grant.level never exceeds the ledger-derived level
  RECORD_SIGNATURE_VERIFIES promotion records carry a verifying DSSE envelope
  PROPOSAL_LIFECYCLE        proposal status stays in the closed vocabulary
  PROPOSAL_TAMPER           (keyed) proposalHash HMAC verifies
  GRANT_TAMPER              (keyed) grant hash HMAC verifies
  QUARANTINED_NO_RAISE      (keyed) a quarantined grant never sits above its
                            ledger-derived level
  GRANT_ENVELOPE_IN_FORCE   grant.envelopeHash matches the stored in-force
                            envelope for its principal (#201)
  UNPARSEABLE_ITEM          a lifecycle item that cannot be parsed is itself
                            a finding, never a crash

Acknowledgments (#196): a TRUE finding can be dispositioned by a signed ACK#
ceremony record (grants/acknowledgments.py) — the matched finding moves to
``AuditReport.acknowledged`` (with the waiver ref) instead of ``violations``,
GREEN-with-annotations, never silently green. Only WAIVABLE_RULES can be
waived; an acknowledgment applies only when its issuer signature VERIFIES, so
keyless/no-resolver runs skip acknowledgment verification loudly and apply no
waivers. Two rules police the waivers themselves:

  ACKNOWLEDGMENT_SIGNATURE_VERIFIES  a stored acknowledgment must verify
  ACKNOWLEDGMENT_NOT_WAIVABLE        an acknowledgment naming an un-waivable
                                     rule is itself a finding
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, get_args

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.grants.acknowledgments import (
    WAIVABLE_RULES,
    AcknowledgmentRecord,
    verify_acknowledgment,
    violation_detail_digest,
)
from safe_agents.broker.grants.demotion import (
    _rank,  # the SAME rank ordering the lifecycle moves on — never duplicated
)
from safe_agents.broker.grants.proposals import ProposalStatus, compute_proposal_hash
from safe_agents.broker.grants.record_signing import verify_record
from safe_agents.broker.grants.store import _hmac_payload, _principal_key
from safe_agents.broker.schemas import Envelope, Grant, PromotionRecord
from safe_agents.broker.schemas.envelope import compute_envelope_hash
from safe_agents.channels.signing import KeyResolver

# ---------------------------------------------------------------------------
# Rule names — stable identifiers; a violation names exactly which lifecycle
# guarantee broke, mirroring the invariant IDs in test_grants_integrity.py
# ---------------------------------------------------------------------------

LEDGER_COUNTERPART = "LEDGER_COUNTERPART"
LEVEL_LEDGER_CONSISTENT = "LEVEL_LEDGER_CONSISTENT"
RECORD_SIGNATURE_VERIFIES = "RECORD_SIGNATURE_VERIFIES"
PROPOSAL_LIFECYCLE = "PROPOSAL_LIFECYCLE"
PROPOSAL_TAMPER = "PROPOSAL_TAMPER"
GRANT_TAMPER = "GRANT_TAMPER"
QUARANTINED_NO_RAISE = "QUARANTINED_NO_RAISE"
GRANT_ENVELOPE_IN_FORCE = "GRANT_ENVELOPE_IN_FORCE"
UNPARSEABLE_ITEM = "UNPARSEABLE_ITEM"
ACKNOWLEDGMENT_SIGNATURE_VERIFIES = "ACKNOWLEDGMENT_SIGNATURE_VERIFIES"
ACKNOWLEDGMENT_NOT_WAIVABLE = "ACKNOWLEDGMENT_NOT_WAIVABLE"

# The rules that cannot run without the grant-table HMAC key (keyless = CI mode).
HMAC_RULES: tuple[str, ...] = (GRANT_TAMPER, PROPOSAL_TAMPER, QUARANTINED_NO_RAISE)

# The closed proposal-status vocabulary, derived from the store's own Literal so
# the auditor and proposals.py can never disagree about what a valid status is.
_VALID_PROPOSAL_STATUSES: frozenset[str] = frozenset(get_args(ProposalStatus))

_EARNING_RECORD_TYPES = ("bootstrap", "promotion")


# ---------------------------------------------------------------------------
# Typed findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditViolation:
    """One rule breach at one table coordinate.

    coordinate is the grant coordinate ("<principal-key>#<actionClass>") for
    lifecycle rules, or the raw item pk for parse failures. detail is
    audit-safe: ids + levels + reasons, never payload content.
    """

    rule: str
    coordinate: str
    detail: str


@dataclass(frozen=True)
class AcknowledgedFinding:
    """A true finding dispositioned by a verified acknowledgment (#196).

    Reported BESIDE the violations, never dropped: the dispatch is
    GREEN-with-annotations, never silently green. waiver_ref names the
    acknowledgment (who, when, why) so the disposition is auditable itself.
    """

    violation: AuditViolation
    waiver_ref: str


@dataclass(frozen=True)
class AuditReport:
    """Outcome of one run_audit pass.

    skipped_rules names every rule that could NOT run in this mode (no HMAC
    key, no key resolver) — a skipped rule is surfaced loudly, never reported
    green. The counts say what was examined, so an empty violations tuple over
    an empty table is distinguishable from a real pass.
    """

    violations: tuple[AuditViolation, ...]
    skipped_rules: tuple[str, ...]
    grants_examined: int
    records_examined: int
    proposals_examined: int
    envelopes_examined: int = 0
    acknowledged: tuple[AcknowledgedFinding, ...] = ()


# ---------------------------------------------------------------------------
# The parsed dataset — pure data, no store handles
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditedGrant:
    """One parsed GRANT# item, with the stored bytes and item-level HMAC.

    raw_data / stored_hash are the integrity basis itself (#246 stored-bytes):
    GRANT_TAMPER verifies the bytes verbatim, never a re-serialization.
    """

    grant: Grant
    raw_data: str | None = None
    stored_hash: str | None = None


@dataclass(frozen=True)
class AuditedRecord:
    """One parsed RECORD# item with the DSSE envelope stored beside it.

    raw_data is the exact stored serialization — the verify basis since #246
    (the signature's subject digest is the sha256 over these bytes verbatim,
    never a re-serialization of the parsed record). signature stays as loaded:
    a dict for a well-formed envelope, None for an unsigned append, or the
    undecodable raw value — verify_record fails closed on anything that is not
    a dict, so a mangled attribute is a violation, not a special case here.
    """

    record: PromotionRecord
    signature: dict | str | None = None
    raw_data: str | None = None


@dataclass(frozen=True)
class AuditedProposal:
    """One PROPOSAL# item, kept raw: the tamper rule recomputes over the exact
    stored data string, and the status rule judges the item-level attribute."""

    coordinate: str
    proposal_id: str
    data_json: str
    stored_hash: object
    status: object


@dataclass(frozen=True)
class AuditedAcknowledgment:
    """One parsed ACK# item with its DSSE envelope stored beside it (#196).

    raw_data is the exact stored serialization — the verify basis since #246
    instance 7 (subject digest over the stored bytes verbatim). signature
    stays as loaded (dict / None / raw undecodable value) —
    verify_acknowledgment fails closed on anything that is not a dict.
    """

    ack: AcknowledgmentRecord
    signature: dict | str | None = None
    raw_data: str | None = None


@dataclass(frozen=True)
class AuditedEnvelope:
    """One parsed ENVELOPE# item, reduced to what the audit judges: which
    principal it is in force for, and its recomputed content hash (#201).

    The hash is recomputed here from the stored bytes via the SAME
    model-load + compute_envelope_hash path the broker runtime uses at boot,
    so audit-side and enforcement-side can never disagree about what the
    in-force hash is. Plain content hash — no key, so the keyless/read-only
    audit posture holds.
    """

    principal_key: str
    envelope_hash: str


@dataclass(frozen=True)
class AuditDataset:
    """The parsed grants-table contents run_audit judges.

    parse_violations carries every UNPARSEABLE_ITEM finding collected while
    parsing — an item that cannot be parsed is a finding in the report, never
    a crash and never silently dropped.
    """

    grants: tuple[AuditedGrant, ...] = ()
    records: tuple[AuditedRecord, ...] = ()
    proposals: tuple[AuditedProposal, ...] = ()
    envelopes: tuple[AuditedEnvelope, ...] = ()
    acknowledgments: tuple[AuditedAcknowledgment, ...] = ()
    parse_violations: tuple[AuditViolation, ...] = ()


# ---------------------------------------------------------------------------
# Loading — one loader per backend, both feeding the same parser
# ---------------------------------------------------------------------------
#
# The rules never learn which backend they audited: each loader's only job is
# to produce whole Dynamo-shaped items for ``dataset_from_items``, which has
# been backend-agnostic since it was written. ``load_dataset`` remains the ONLY
# AWS-touching function in this module, and its only API call is a Scan.
#
# The sqlite arm exists because a local floor that cannot be audited by its own
# tooling has no honest posture story (#252): after the grants-sqlite slice
# (#247) every grants store family had a local arm EXCEPT the thing that audits
# them — the #267 second-arm shape, correct at site #1 and silently absent at
# site #2.


def load_dataset(table) -> AuditDataset:
    """Scan the grants table (paginated) and parse it into an AuditDataset.

    ``table`` is an already-constructed boto3 Table resource — this function
    never builds credentials or sessions itself, so the caller decides which
    (read-only) identity the Scan runs under. Pagination mirrors the
    LastEvaluatedKey loop in store.py list_records.
    """
    items: list[dict] = []
    kwargs: dict = {}
    while True:
        response = table.scan(**kwargs)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return dataset_from_items(items)
        kwargs["ExclusiveStartKey"] = last_key


def load_dataset_sqlite(db_path: str | Path) -> AuditDataset:
    """Read every item from a local ``broker.db`` and parse it into an AuditDataset.

    The sqlite mirror of :func:`load_dataset`: reads the whole ``items`` table
    (the Scan analogue — auditing a subset would silently exempt whatever the
    filter missed) and re-merges ``pk``/``sk`` back into the attribute map,
    which the substrate keeps in columns. That re-merge is not cosmetic: the
    parser dispatches on the ``pk`` prefix and reads ``sk`` as a proposal's id,
    so attribute maps alone would parse as nothing and report a clean audit of
    an empty dataset — the worst possible failure for an integrity check.

    Read-only, like every path in this module: the connection is opened, read,
    and closed. Opening does bootstrap the schema on a fresh file (the
    substrate's idempotent ``_ensure_schema``), which is why the path is a
    parameter — an operator naming the wrong path gets an empty audit against a
    new file, and the report's examined-counts are what shows it.
    """
    conn = substrate.open_connection(db_path)
    try:
        rows = conn.execute("SELECT pk, sk, item FROM items ORDER BY pk, sk").fetchall()
    finally:
        conn.close()
    return dataset_from_items({"pk": pk, "sk": sk, **json.loads(item)} for pk, sk, item in rows)


def dataset_from_items(items: Iterable[dict]) -> AuditDataset:
    """Parse raw table items into an AuditDataset, dispatching on pk prefix.

    Item kinds that share the grants table but are not lifecycle items
    (COUNTER#, IDEM#, INTENT#, ...) are ignored — they have their own
    integrity mechanisms. ENVELOPE# rows ARE parsed since #201: the
    GRANT_ENVELOPE_IN_FORCE rule judges grants against them, so an envelope
    row that fails to parse is an UNPARSEABLE_ITEM finding like any
    lifecycle item.
    """
    grants: list[AuditedGrant] = []
    records: list[AuditedRecord] = []
    proposals: list[AuditedProposal] = []
    envelopes: list[AuditedEnvelope] = []
    acknowledgments: list[AuditedAcknowledgment] = []
    parse_violations: list[AuditViolation] = []

    def _unparseable(pk: str, item: dict, why: str) -> None:
        parse_violations.append(
            AuditViolation(
                rule=UNPARSEABLE_ITEM,
                coordinate=pk,
                detail=f"item sk={item.get('sk')!r} could not be parsed: {why}",
            )
        )

    for item in items:
        pk = item.get("pk")
        if not isinstance(pk, str):
            _unparseable(str(pk), item, "item has no string pk")
            continue

        if pk.startswith("GRANT#"):
            try:
                grant = Grant.model_validate_json(item["data"])
            except (KeyError, TypeError, ValueError) as exc:
                _unparseable(pk, item, str(exc))
                continue
            stored_hash = item.get("grantHash")
            grants.append(
                AuditedGrant(
                    grant=grant,
                    raw_data=item["data"],
                    stored_hash=stored_hash if isinstance(stored_hash, str) else None,
                )
            )

        elif pk.startswith("RECORD#"):
            try:
                record = PromotionRecord.model_validate_json(item["data"])
            except (KeyError, TypeError, ValueError) as exc:
                _unparseable(pk, item, str(exc))
                continue
            signature = item.get("signature")
            if isinstance(signature, str):
                try:
                    signature = json.loads(signature)
                except ValueError:
                    pass  # kept raw: verify_record fails closed on a non-dict
            records.append(
                AuditedRecord(record=record, signature=signature, raw_data=item["data"])
            )

        elif pk.startswith("ACK#"):
            try:
                ack = AcknowledgmentRecord.model_validate_json(item["data"])
            except (KeyError, TypeError, ValueError) as exc:
                _unparseable(pk, item, str(exc))
                continue
            signature = item.get("signature")
            if isinstance(signature, str):
                try:
                    signature = json.loads(signature)
                except ValueError:
                    pass  # kept raw: verify_acknowledgment fails closed on a non-dict
            acknowledgments.append(
                AuditedAcknowledgment(ack=ack, signature=signature, raw_data=item["data"])
            )

        elif pk.startswith("ENVELOPE#"):
            try:
                envelope = Envelope.model_validate_json(item["data"])
            except (KeyError, TypeError, ValueError) as exc:
                _unparseable(pk, item, str(exc))
                continue
            envelopes.append(
                AuditedEnvelope(
                    principal_key=pk.removeprefix("ENVELOPE#"),
                    envelope_hash=compute_envelope_hash(envelope),
                )
            )

        elif pk.startswith("PROPOSAL#"):
            data = item.get("data")
            if not isinstance(data, str):
                _unparseable(pk, item, "proposal item carries no data string")
                continue
            proposals.append(
                AuditedProposal(
                    coordinate=pk.removeprefix("PROPOSAL#"),
                    proposal_id=str(item.get("sk", "<unknown>")),
                    data_json=data,
                    stored_hash=item.get("proposalHash"),
                    status=item.get("status"),
                )
            )

    return AuditDataset(
        grants=tuple(grants),
        records=tuple(records),
        proposals=tuple(proposals),
        envelopes=tuple(envelopes),
        acknowledgments=tuple(acknowledgments),
        parse_violations=tuple(parse_violations),
    )


# ---------------------------------------------------------------------------
# The audit — pure over the dataset; mode decided by what the caller supplies
# ---------------------------------------------------------------------------


def _grant_coordinate(grant: Grant) -> str:
    return f"{_principal_key(grant.principal)}#{grant.actionClass}"


def _record_coordinate(record: PromotionRecord) -> str:
    return f"{_principal_key(record.principal)}#{record.actionClass}"


def _records_by_coordinate(
    dataset: AuditDataset,
) -> dict[str, list[AuditedRecord]]:
    """Group ledger entries per grant coordinate, chronological.

    Ordering key is the stored sk ("<ts>#<recordType>") — lexical order IS
    chronological because record ts is canonical (validate_record_ts)."""
    grouped: dict[str, list[AuditedRecord]] = {}
    for entry in dataset.records:
        grouped.setdefault(_record_coordinate(entry.record), []).append(entry)
    for entries in grouped.values():
        entries.sort(key=lambda e: f"{e.record.ts}#{e.record.recordType}")
    return grouped


def run_audit(
    dataset: AuditDataset,
    *,
    hmac_key: bytes | None = None,
    record_key_resolver: KeyResolver | None = None,
) -> AuditReport:
    """Run every rule the supplied material allows; skip the rest LOUDLY.

    Read-side limits, stated once here and per rule below: this auditor judges
    the table as it stands. It proves consistency between what is stored and
    what the ceremony ledger accounts for; it cannot replay how the state was
    reached — the write-side guards (conditional writes, quarantine refusals,
    single-shot proposal consumption) own that, and the #62 policy table
    proves THOSE stay live.
    """
    violations: list[AuditViolation] = list(dataset.parse_violations)
    skipped: list[str] = []
    ledger = _records_by_coordinate(dataset)
    in_force = {e.principal_key: e.envelope_hash for e in dataset.envelopes}

    for entry in dataset.grants:
        grant = entry.grant
        coordinate = _grant_coordinate(grant)
        coordinate_records = ledger.get(coordinate, [])

        # LEDGER_COUNTERPART — every level was earned through the ceremony
        # ledger: seeds emit bootstrap records (#123), promotions append
        # promotion records, so a grant with neither is a bypass write.
        # Since #244 the record and the grant commit as ONE atomic unit
        # (write_record_and_grant at every ceremony write-pair site), so NEW
        # findings here can no longer be ceremony fallout. The rule STAYS: it
        # still catches historical artifacts (pre-atomicity interruptions)
        # and out-of-band tamper — a finding dated after the #244 cutover is
        # tamper evidence, same framing as MCP_ORPHAN_RECORD (mcp/audit.py).
        if not any(
            e.record.recordType in _EARNING_RECORD_TYPES for e in coordinate_records
        ):
            violations.append(
                AuditViolation(
                    rule=LEDGER_COUNTERPART,
                    coordinate=coordinate,
                    detail=(
                        f"grant at level {grant.level.value!r} has no bootstrap- or "
                        "promotion-typed ledger record; every level must be earned "
                        "through the ceremony ledger"
                    ),
                )
            )

        # LEVEL_LEDGER_CONSISTENT — grant.level must not EXCEED the level the
        # ledger accounts for (the chronologically-last record's toLevel). A
        # grant BELOW its ledger is allowed by design: a crash between the
        # grant write and the record append fails toward less authority.
        derived = coordinate_records[-1].record.toLevel if coordinate_records else None
        if derived is not None and _rank(grant.level) > _rank(derived):
            violations.append(
                AuditViolation(
                    rule=LEVEL_LEDGER_CONSISTENT,
                    coordinate=coordinate,
                    detail=(
                        f"grant level {grant.level.value!r} exceeds the ledger-derived "
                        f"level {derived.value!r}; the ledger accounts for every raise"
                    ),
                )
            )

        # GRANT_ENVELOPE_IN_FORCE (#201) — grant.envelopeHash must match the
        # stored in-force envelope for its principal. A mismatched grant is
        # quarantined by the broker on EVERY call (sa#122) — operationally
        # dead — yet is HMAC-clean, so no other rule sees it (#199's incident
        # grant passed a green audit). Fires expectedly after any far-jump
        # redeploy: the remedy is `re-seed`, which re-attests HMAC-clean
        # grants at the same level. Read-side limit: judged only where an
        # ENVELOPE# row exists for the principal — a manifest-mode floor
        # stores no envelope rows, and this rule cannot see the manifest.
        in_force_hash = in_force.get(_principal_key(grant.principal))
        if in_force_hash is not None and grant.envelopeHash != in_force_hash:
            violations.append(
                AuditViolation(
                    rule=GRANT_ENVELOPE_IN_FORCE,
                    coordinate=coordinate,
                    detail=(
                        f"grant envelopeHash {grant.envelopeHash!r} does not match "
                        f"the in-force envelope {in_force_hash!r} for its principal; "
                        "the broker quarantines this grant on every call — re-seed "
                        "re-attests HMAC-clean grants at the same level"
                    ),
                )
            )

        if hmac_key is not None:
            # GRANT_TAMPER — the read-side twin of the store's verify-on-read
            # quarantine: HMAC the STORED BYTES verbatim against the item-level
            # grantHash (#246 — never a re-serialization, so schema evolution
            # can never fire this rule). A missing grantHash attribute is a
            # finding too: the item cannot be verified. Every finding here is
            # a grant that reads back quarantined and needs operator attention.
            quarantined = (
                entry.raw_data is None
                or entry.stored_hash is None
                or entry.stored_hash != _hmac_payload(entry.raw_data, hmac_key)
            )
            if quarantined:
                violations.append(
                    AuditViolation(
                        rule=GRANT_TAMPER,
                        coordinate=coordinate,
                        detail=(
                            "stored grant hash does not match the recomputed HMAC; "
                            "the grant reads back quarantined and must not authorize "
                            "anything until the tamper is resolved"
                        ),
                    )
                )
            # QUARANTINED_NO_RAISE — a quarantined grant must not sit above its
            # ledger-derived level. Read-side limit, stated honestly: the
            # ledger does not timestamp WHEN quarantine began, so "no raise
            # after quarantine" is enforced write-side (ceremony and demotion
            # both refuse quarantined reads) and approximated here by the
            # level-vs-ledger bound — a quarantined grant above its ledger is
            # the strongest read-side evidence of an unaccounted raise.
            if quarantined and derived is not None and _rank(grant.level) > _rank(derived):
                violations.append(
                    AuditViolation(
                        rule=QUARANTINED_NO_RAISE,
                        coordinate=coordinate,
                        detail=(
                            f"quarantined grant sits at {grant.level.value!r}, above "
                            f"the ledger-derived level {derived.value!r}; a "
                            "quarantined grant must never hold unaccounted authority"
                        ),
                    )
                )

    # RECORD_SIGNATURE_VERIFIES — every promotion-typed record must carry a
    # DSSE envelope that verify_record confirms (fails closed). Only ratify
    # installs the signing store, so bootstrap/demotion/tightening records are
    # exempt. Read-side limit: predicate fields inside the record (covered,
    # provenance maturity) are proposer ASSERTIONS at N=1 owner — #364 tracks
    # deriving provenance maturity rather than asserting it (#193/#174 were
    # named here and both closed without landing that measurement) — so this
    # rule verifies AUTHENTICITY (who signed what), never the truth of the
    # asserted evidence.
    if record_key_resolver is None:
        skipped.append(RECORD_SIGNATURE_VERIFIES)
    else:
        for entry in dataset.records:
            if entry.record.recordType != "promotion":
                continue
            coordinate = _record_coordinate(entry.record)
            if entry.signature is None:
                violations.append(
                    AuditViolation(
                        rule=RECORD_SIGNATURE_VERIFIES,
                        coordinate=coordinate,
                        detail=(
                            f"promotion record ts={entry.record.ts} carries no DSSE "
                            "signature; every ratified promotion is issuer-signed"
                        ),
                    )
                )
                continue
            # Verify from the STORED bytes (#246): the subject digest is the
            # sha256 over the item's data string verbatim — NEVER a
            # re-serialization of the parsed record (that would re-derive the
            # basis from today's model and read every pre-schema-growth record
            # as a signature failure). A dataset entry without the stored
            # bytes cannot be verified at all: fail closed with a violation,
            # not a synthesized basis.
            if entry.raw_data is None:
                violations.append(
                    AuditViolation(
                        rule=RECORD_SIGNATURE_VERIFIES,
                        coordinate=coordinate,
                        detail=(
                            f"promotion record ts={entry.record.ts} has no stored "
                            "bytes on the dataset entry; a signature cannot be "
                            "verified without the exact stored serialization"
                        ),
                    )
                )
                continue
            result = verify_record(entry.raw_data, entry.signature, record_key_resolver)
            if not result.ok:
                violations.append(
                    AuditViolation(
                        rule=RECORD_SIGNATURE_VERIFIES,
                        coordinate=coordinate,
                        detail=(
                            f"promotion record ts={entry.record.ts} failed signature "
                            f"verification ({result.reason})"
                        ),
                    )
                )

    # PROPOSAL_LIFECYCLE — the item-level status must stay in the closed
    # pending/ratified/rejected vocabulary; anything else is a hand edit (the
    # single-shot consume flip only ever writes the two terminal values).
    # Read-side limit: no-resurrection (a consumed proposal never flips back)
    # is the store condition's job — a point-in-time scan cannot see a flip.
    for proposal in dataset.proposals:
        if proposal.status not in _VALID_PROPOSAL_STATUSES:
            violations.append(
                AuditViolation(
                    rule=PROPOSAL_LIFECYCLE,
                    coordinate=proposal.coordinate,
                    detail=(
                        f"proposal {proposal.proposal_id} has status "
                        f"{proposal.status!r}, outside the closed vocabulary "
                        f"{sorted(_VALID_PROPOSAL_STATUSES)}"
                    ),
                )
            )

    if hmac_key is None:
        skipped.extend(HMAC_RULES)
    else:
        # PROPOSAL_TAMPER — the keyed half of the proposal rule: recompute the
        # HMAC over the stored data string (the read-side twin of the stores'
        # ProposalIntegrityError). The mutable status attribute is deliberately
        # outside the hash, same as compute_proposal_hash documents.
        for proposal in dataset.proposals:
            expected = compute_proposal_hash(proposal.data_json, hmac_key)
            if proposal.stored_hash != expected:
                violations.append(
                    AuditViolation(
                        rule=PROPOSAL_TAMPER,
                        coordinate=proposal.coordinate,
                        detail=(
                            f"proposal {proposal.proposal_id} failed HMAC "
                            "verification; a tampered proposal launders into a "
                            "signed grant at ratify time"
                        ),
                    )
                )

    # Acknowledgments (#196) — sanctioned disposition of TRUE findings. Judged
    # BEFORE they can waive anything: a waiver mints "green", so it is itself
    # authority. Rules: only WAIVABLE_RULES can be acknowledged (closed
    # vocabulary — HMAC tamper etc. stay un-waivable); the acknowledgment must
    # be issuer-signed and VERIFY (no resolver ⇒ verification skipped LOUDLY
    # and NO waiver applies — fail toward RED, never toward green); the match
    # is exact on (rule, coordinate, detail-digest), so a NEW finding at the
    # same coordinate is never auto-waived by an old acknowledgment.
    waivers: dict[tuple[str, str, str], str] = {}
    if record_key_resolver is None:
        skipped.append(ACKNOWLEDGMENT_SIGNATURE_VERIFIES)
    else:
        for entry in dataset.acknowledgments:
            ack = entry.ack
            if ack.rule not in WAIVABLE_RULES:
                violations.append(
                    AuditViolation(
                        rule=ACKNOWLEDGMENT_NOT_WAIVABLE,
                        coordinate=ack.coordinate,
                        detail=(
                            f"acknowledgment ts={ack.ts} names rule {ack.rule!r}, which "
                            f"is not in the closed waivable vocabulary "
                            f"{sorted(WAIVABLE_RULES)}; it waives nothing"
                        ),
                    )
                )
                continue
            # Verify from the STORED bytes (#246 instance 7); an entry without
            # them cannot be verified — fail closed, the waiver applies nothing.
            if entry.raw_data is None:
                violations.append(
                    AuditViolation(
                        rule=ACKNOWLEDGMENT_SIGNATURE_VERIFIES,
                        coordinate=ack.coordinate,
                        detail=(
                            f"acknowledgment ts={ack.ts} has no stored bytes on the "
                            "dataset entry; its signature cannot be verified and it "
                            "waives nothing"
                        ),
                    )
                )
                continue
            result = verify_acknowledgment(entry.raw_data, entry.signature, record_key_resolver)
            if not result.ok:
                violations.append(
                    AuditViolation(
                        rule=ACKNOWLEDGMENT_SIGNATURE_VERIFIES,
                        coordinate=ack.coordinate,
                        detail=(
                            f"acknowledgment ts={ack.ts} for rule {ack.rule} failed "
                            f"signature verification ({result.reason}); it waives nothing"
                        ),
                    )
                )
                continue
            waivers[(ack.rule, ack.coordinate, ack.detailDigest)] = (
                f"acknowledged by {ack.acknowledgedBy} at {ack.ts}: {ack.rationale}"
            )

    remaining: list[AuditViolation] = []
    acknowledged: list[AcknowledgedFinding] = []
    for violation in violations:
        waiver_ref = (
            waivers.get(
                (violation.rule, violation.coordinate, violation_detail_digest(violation.detail))
            )
            if violation.rule in WAIVABLE_RULES
            else None
        )
        if waiver_ref is None:
            remaining.append(violation)
        else:
            acknowledged.append(AcknowledgedFinding(violation=violation, waiver_ref=waiver_ref))
    violations = remaining

    return AuditReport(
        violations=tuple(violations),
        skipped_rules=tuple(skipped),
        grants_examined=len(dataset.grants),
        records_examined=len(dataset.records),
        proposals_examined=len(dataset.proposals),
        envelopes_examined=len(dataset.envelopes),
        acknowledged=tuple(acknowledged),
    )
