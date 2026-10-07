"""grants.audit — read-only grant-integrity auditor.

Pure functions over an already-loaded grants-table dataset → typed findings.
The auditor NEVER writes: the only AWS-touching function is ``load_dataset``,
and its only API call is a paginated Scan. Everything else operates on the
parsed ``AuditDataset``, so the same rules run identically against production
items and in-memory fixtures (the CI policy table).

Two loaders, one parser: ``load_dataset`` (DynamoDB Scan) and
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
  LEVEL_DROP_RECORDED       grant.level never sits BELOW the ledger-derived
                            level: every drop (demotion, tightening, lapse)
                            has its record
  GRANT_TERM_RATIFIED       grant.certifiedUntil equals the term on the
                            promotion record that last set it
  GRANT_TS_RECORDED         grant.ts equals the ts of the latest ledger record
                            at its coordinate, in both directions: a later
                            grant ts is a write the ledger does not explain,
                            an earlier one is a record whose grant write did
                            not land
  RECORD_SIGNATURE_VERIFIES every record in scope carries a DSSE envelope that
                            verifies under ITS RECORD TYPE'S signing role
                            (issuer: promotion/bootstrap/tightening/
                            reattestation; evaluator: demotion/lapse). Scope
                            is set by
                            RECORD_SIGNING_EPOCH — see below
  EVALUATOR_RECORD_CONTINUOUS a demotion or lapse record starts from the level
                            the ledger held immediately before it: the
                            evaluator's key signs these, so one that starts
                            anywhere else can leave the ledger higher than
                            the issuer ever put it
  RECORD_SIGNING_EPOCH_VALID the configured epoch is in force at the supplied
                            evaluation instant. An epoch after it is a
                            finding, and the records are checked in full
                            all the same
  PROPOSAL_LIFECYCLE        proposal status stays in the closed vocabulary
  PROPOSAL_TAMPER           (keyed) proposalHash HMAC verifies
  GRANT_TAMPER              (keyed) grant hash HMAC verifies
  QUARANTINED_NO_RAISE      (keyed) a quarantined grant never sits above its
                            ledger-derived level
  GRANT_ENVELOPE_IN_FORCE   grant.envelopeHash matches the stored in-force
                            envelope for its principal
  UNPARSEABLE_ITEM          a lifecycle item that cannot be parsed is itself
                            a finding, never a crash

A ``reattestation`` record changes no level (GAL §4.3), so every rule that
derives a coordinate's level from its ledger, or looks for the record that
earned it, passes over the type: the level and the earning record are the ones
the ledger held immediately before it (``_level_bearing``). Its signature is
checked like any other issuer-signed record's. GRANT_TS_RECORDED is the one
grant-against-ledger rule that does NOT pass over it: that rule reads a
timestamp and no level, and a re-attestation is a write to the grant like any
other, so its record is the latest one when it is the last thing written.

Acknowledgments: a TRUE finding can be dispositioned by a signed ACK#
ceremony record (grants/acknowledgments.py) — the matched finding moves to
``AuditReport.acknowledged`` (with the waiver ref) instead of ``violations``,
GREEN-with-annotations, never silently green. Only WAIVABLE_RULES can be
waived; an acknowledgment applies only when its issuer signature VERIFIES, so
keyless/no-resolver runs skip acknowledgment verification loudly and apply no
waivers. Two rules police the waivers themselves:

  ACKNOWLEDGMENT_SIGNATURE_VERIFIES  a stored acknowledgment must verify
  ACKNOWLEDGMENT_NOT_WAIVABLE        an acknowledgment naming an un-waivable
                                     rule is itself a finding

The record-signing EPOCH. GAL-SPEC §6.10 requires EVERY ledger record to be
signed, but ledgers written before the second signing role existed hold
unsigned demotion/tightening/bootstrap rows that cannot be re-minted.

  * ``signing_epoch`` set: every record MUST carry a verifying signature of
    its role, whatever its type and whatever its ``ts``. No record is excused
    by its own timestamp. On an unsigned record that field was written by
    whoever wrote the row, so an exemption keyed on it could be claimed by a
    planted row. Honest unsigned history is excused one record at a time by
    the acknowledgment ceremony above, which is signed.
  * ``signing_epoch`` unset — scope stays what it was (promotion and
    reattestation required, lapse-if-present), and the report carries a NAMED annotation saying the
    all-types requirement is not being enforced. Never a silent skip.

A RECORD_SIGNATURE_VERIFIES finding names the sha256 of the record's STORED
bytes. An acknowledgment binds the digest of the exact detail string, so it
excuses those bytes and no others: a different record written at the same
coordinate, type and ``ts`` produces a different detail, and the earlier
acknowledgment does not apply to it. An entry with no stored bytes has nothing
to bind, so its finding is never waived.

A GRANT_TS_RECORDED finding names the sha256 of the GRANT's stored bytes and
both timestamps, on the same terms: an acknowledgment excuses the grant as it
stood when it was signed, and a grant rewritten afterwards is a new finding.
One variant has no second timestamp to name: where a record's ts is not an
instant, the latest record is not established. That finding names the sha256
of the stored bytes of EVERY record at the coordinate in its place, so an
acknowledgment of it covers that ledger and no later state of it.
Nothing but a verified acknowledgment excuses one. There is no adoption date
for this rule and no field on a grant or a record that takes a coordinate out
of its scope, because whoever wrote the row wrote that field too.

``now`` is the explicit evaluation instant the EPOCH itself is judged at,
required whenever an epoch is supplied and never derived from a record's ts —
the same discipline as the grant term (``grants.term``). That judgement is the
only use of the epoch instant: an epoch after ``now`` is
RECORD_SIGNING_EPOCH_VALID, and every record is still checked. No record's
``ts`` is compared against the epoch, and the auditor takes no clock of its
own.
"""

from __future__ import annotations

import datetime
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
from safe_agents.broker.grants.ledger_clock import (
    _recorded_instant,  # the SAME reading of a stored ts the ledger clock takes
)
from safe_agents.broker.grants.proposals import ProposalStatus, compute_proposal_hash
from safe_agents.broker.grants.record_signing import (
    EVALUATOR_ROLE,
    RoleKeyResolvers,
    signing_role_for_record_type,
    stored_record_digest_hex,
    verify_record_by_type,
)
from safe_agents.broker.grants.store import _hmac_payload, _principal_key
from safe_agents.broker.schemas import Envelope, Grant, PromotionRecord
from safe_agents.broker.schemas.envelope import compute_envelope_hash
from safe_agents.broker.schemas.promotion_record import REATTESTATION_RECORD_TYPE
from safe_agents.channels.signing import KeyResolver

# ---------------------------------------------------------------------------
# Rule names — stable identifiers; a violation names exactly which lifecycle
# guarantee broke, mirroring the invariant IDs in test_grants_integrity.py
# ---------------------------------------------------------------------------

LEDGER_COUNTERPART = "LEDGER_COUNTERPART"
LEVEL_LEDGER_CONSISTENT = "LEVEL_LEDGER_CONSISTENT"
LEVEL_DROP_RECORDED = "LEVEL_DROP_RECORDED"
GRANT_TERM_RATIFIED = "GRANT_TERM_RATIFIED"
GRANT_TS_RECORDED = "GRANT_TS_RECORDED"
RECORD_SIGNATURE_VERIFIES = "RECORD_SIGNATURE_VERIFIES"
EVALUATOR_RECORD_CONTINUOUS = "EVALUATOR_RECORD_CONTINUOUS"
RECORD_SIGNING_EPOCH_VALID = "RECORD_SIGNING_EPOCH_VALID"
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

# The record types that can account for a grant existing at a level. Listed,
# not derived by exclusion: a reattestation record (and any type added later)
# earns nothing unless it is named here.
_EARNING_RECORD_TYPES = ("bootstrap", "promotion")

# With no signing epoch declared, the types that must carry a signature
# anyway. A promotion mints authority. A reattestation returns a quarantined
# grant to acting authority, and its one sanctioned writer refuses to run
# without the issuer's key, so an unsigned one is a row no ceremony wrote.
_ALWAYS_SIGNED_TYPES = ("promotion", REATTESTATION_RECORD_TYPE)

# With no signing epoch declared, the types whose signature is verified when
# one is present and not demanded when it is absent: honest unsigned history
# of these exists from before signing was adopted.
_SIGNED_IF_PRESENT_TYPES = ("lapse",)

# Annotation names — stable identifiers for the green-with-annotations half of
# the report. An annotation is never a pass and never a violation: it names a
# thing the reader must know to read the result correctly.
ANNOTATION_SIGNING_EPOCH_UNSET = "record-signing-epoch-unset"
ANNOTATION_SIGNING_EPOCH_UNENFORCEABLE = "record-signing-epoch-unenforceable"


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
    """A true finding dispositioned by a verified acknowledgment.

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

    annotations names every NARROWING the reader needs to interpret the result:
    today, whether the all-types signing requirement ran at all.
    Green-with-annotations, never silently green — the same polarity as
    ``acknowledged``.
    """

    violations: tuple[AuditViolation, ...]
    skipped_rules: tuple[str, ...]
    grants_examined: int
    records_examined: int
    proposals_examined: int
    envelopes_examined: int = 0
    acknowledged: tuple[AcknowledgedFinding, ...] = ()
    annotations: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# The parsed dataset — pure data, no store handles
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditedGrant:
    """One parsed GRANT# item, with the stored bytes and item-level HMAC.

    raw_data / stored_hash are the integrity basis itself (stored-bytes integrity):
    GRANT_TAMPER verifies the bytes verbatim, never a re-serialization.
    """

    grant: Grant
    raw_data: str | None = None
    stored_hash: str | None = None


@dataclass(frozen=True)
class AuditedRecord:
    """One parsed RECORD# item with the DSSE envelope stored beside it.

    raw_data is the exact stored serialization — the verify basis since stored-bytes integrity
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
    """One parsed ACK# item with its DSSE envelope stored beside it.

    raw_data is the exact stored serialization — the verify basis since stored-bytes integrity
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
    principal it is in force for, and its recomputed content hash.

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
# tooling has no honest posture story: after the grants-sqlite slice
# every grants store family had a local arm EXCEPT the thing that audits
# them — the second-arm shape (#140), correct at site #1 and silently absent at
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
    return dataset_from_items(read_items_sqlite(db_path))


def read_items_sqlite(db_path: str | Path) -> list[dict]:
    """Every item in a local ``broker.db``, Dynamo-shaped, in one read.

    The read half of :func:`load_dataset_sqlite`, separate so that a second
    auditor over the same file (the MCP registry's, ``mcp/audit.py``) parses the
    SAME snapshot through the SAME reader instead of growing its own SELECT.
    """
    conn = substrate.open_connection(db_path)
    try:
        rows = conn.execute("SELECT pk, sk, item FROM items ORDER BY pk, sk").fetchall()
    finally:
        conn.close()
    return [{"pk": pk, "sk": sk, **json.loads(item)} for pk, sk, item in rows]


def dataset_from_items(items: Iterable[dict]) -> AuditDataset:
    """Parse raw table items into an AuditDataset, dispatching on pk prefix.

    Item kinds that share the grants table but are not lifecycle items
    (COUNTER#, IDEM#, INTENT#, ...) are ignored — they have their own
    integrity mechanisms. ENVELOPE# rows ARE parsed now: the
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


def _epoch_instant_and_label(value: str) -> tuple[datetime.datetime, str]:
    """The epoch as (instant, display label).

    The instant is what RECORD_SIGNING_EPOCH_VALID compares against the
    evaluation instant. Both are aware datetimes, so every legal spelling of
    one instant (``+00:00``, ``Z``, a non-UTC offset) gets one verdict.

    The label is the operator's value, followed by the canonical UTC form it
    normalized to when the two differ. An epoch silently reinterpreted is a
    different instant from the one the operator meant to configure.

    No record ``ts`` is compared against the epoch. An earlier version
    exempted records dated before it, and an unsigned record could claim that
    exemption with a timestamp its own writer chose.
    """
    parsed = _parse_instant(value)
    canonical = parsed.astimezone(datetime.UTC).isoformat()
    return parsed, canonical if canonical == value else f"{value} ({canonical})"


def _parse_instant(value: str) -> datetime.datetime:
    """Parse an explicit UTC instant, refusing a naive one.

    A naive epoch would compare against an aware ``now`` by raising, or worse,
    be silently localized — so it is refused here with a message an operator
    can act on.
    """
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"record-signing epoch {value!r} is not an ISO-8601 instant"
        ) from exc
    if parsed.tzinfo is None:
        raise ValueError(
            f"record-signing epoch {value!r} has no UTC offset; the epoch must "
            "name an unambiguous instant"
        )
    return parsed


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


def _level_bearing(entries: list[AuditedRecord]) -> list[AuditedRecord]:
    """The coordinate's records a level may be read from, order kept.

    Drops ``reattestation`` records (GAL §4.3). An honest one restates the
    level the ledger already held, so dropping it changes nothing. A planted
    one could restate any level it liked, and a reader that took the ledger's
    level from the last record would then take it from that.
    """
    return [entry for entry in entries if entry.record.bears_level]


def _ts_instant(ts: object) -> datetime.datetime | None:
    """A stored ts as an instant, or None where it does not name one.

    The reading is the ledger clock's (``_recorded_instant``), so the audit
    and the writer agree on which record is latest, a naive value read as UTC
    included. Neither ``Grant.ts`` nor a record's ``ts`` is checked as a
    timestamp at parse, so a planted row can carry any string here: one that
    does not parse, or one whose offset carries it outside the representable
    range. Each is a finding at the call site, never a crash. The schema does
    hold both to ``str``, so no loader hands over anything else. TypeError is
    caught for a dataset entry built in memory without validation.
    """
    try:
        return _recorded_instant(ts)
    except (TypeError, ValueError, OverflowError):
        return None


def _coordinate_ledger_digest(coordinate_records: list[AuditedRecord]) -> str | None:
    """One sha256 over the stored bytes of every record at a coordinate.

    None when an entry carries no stored bytes: there is then nothing to bind.
    The digest is over the sorted per-record digests, so it does not depend on
    the order the records were listed in, and it moves when a record is
    appended, removed or replaced.
    """
    if any(entry.raw_data is None for entry in coordinate_records):
        return None
    digests = sorted(stored_record_digest_hex(entry.raw_data) for entry in coordinate_records)
    return stored_record_digest_hex("\n".join(digests))


def _grant_ts_mismatch(
    grant_ts: str, coordinate_records: list[AuditedRecord]
) -> tuple[str, bool] | None:
    """How ``grant_ts`` fails to be the ts of the coordinate's latest record.

    None when it is that record's ts. Otherwise the clause a
    GRANT_TS_RECORDED detail states, and whether that clause binds the ledger
    state it was judged against. The clause names the latest record's ts, and
    that binds it: a record appended later moves the latest ts and so the
    detail. Where the latest record is not established there is no such ts, so
    the clause carries a digest of every record at the coordinate instead, and
    is unbound when one of them has no stored bytes.

    "Latest" is the maximum INSTANT over every record at the coordinate,
    whatever its type, a ``reattestation`` included. It is never the last
    element of the list and never the greatest string: those agree with the
    instant for canonical values, and a planted row need not be canonical.

    Equality is on the stored string. A sanctioned write puts one value on
    the record and on the grant, so a grant ts that names the latest record's
    instant in a different spelling was still written by something else.
    Where two records share the latest instant in two spellings, either
    spelling is a latest record's ts.
    """
    instants = [_ts_instant(entry.record.ts) for entry in coordinate_records]
    if None in instants:
        # No ceremony writes such a record (validate_record_ts refuses it), and
        # with one present the latest record is not established. Skipping it
        # would let a row decide for itself whether it is counted.
        unreadable = sorted(
            repr(entry.record.ts)
            for entry, instant in zip(coordinate_records, instants)
            if instant is None
        )
        # Without the ledger digest this detail would read the same whatever
        # was appended or removed beside the unreadable record, and one
        # acknowledgment of it would excuse the coordinate from then on.
        ledger_digest = _coordinate_ledger_digest(coordinate_records)
        ledger_state = (
            f"the {len(coordinate_records)} records there, stored bytes "
            f"sha256:{ledger_digest}"
            if ledger_digest is not None
            else "a record there has no stored bytes on the dataset entry, so "
            "nothing an acknowledgment can bind"
        )
        return (
            f"cannot be held to the ledger: the record ts {', '.join(unreadable)} "
            "at its coordinate is not an instant, so the latest record is not "
            f"established ({ledger_state})",
            ledger_digest is not None,
        )
    latest = max(instants)
    latest_ts = sorted(
        {
            entry.record.ts
            for entry, instant in zip(coordinate_records, instants)
            if instant == latest
        }
    )
    if grant_ts in latest_ts:
        return None
    against = (
        "the latest ledger record at its coordinate "
        f"(ts={', '.join(repr(ts) for ts in latest_ts)})"
    )
    grant_instant = _ts_instant(grant_ts)
    if grant_instant is None:
        clause = f"is not an instant and so is not the ts of {against}"
    elif grant_instant > latest:
        clause = f"is later than {against}: a write to the grant that the ledger does not explain"
    elif grant_instant < latest:
        clause = f"is earlier than {against}: a record whose grant write did not land"
    else:
        clause = (
            f"names the instant of {against} in a different form: a sanctioned write "
            "puts one value on both"
        )
    return clause, True


def _as_role_resolvers(
    record_key_resolver: KeyResolver | RoleKeyResolvers | None,
) -> RoleKeyResolvers | None:
    """Normalize the resolver argument to role-keyed form.

    A bare callable is the pre-role calling convention and means the ISSUER's
    map — the only role that existed then. It is NOT spread across both roles:
    that would make every caller who passes one resolver accept an
    issuer-signed demotion, which is exactly the binding this rule adds. A
    caller with an evaluator map passes ``RoleKeyResolvers``.
    """
    if record_key_resolver is None:
        return None
    if isinstance(record_key_resolver, RoleKeyResolvers):
        return record_key_resolver
    return RoleKeyResolvers(issuer=record_key_resolver)


def run_audit(
    dataset: AuditDataset,
    *,
    hmac_key: bytes | None = None,
    record_key_resolver: KeyResolver | RoleKeyResolvers | None = None,
    signing_epoch: str | None = None,
    now: datetime.datetime | None = None,
) -> AuditReport:
    """Run every rule the supplied material allows; skip the rest LOUDLY.

    Read-side limits, stated once here and per rule below: this auditor judges
    the table as it stands. It proves consistency between what is stored and
    what the ceremony ledger accounts for; it cannot replay how the state was
    reached — the write-side guards (conditional writes, quarantine refusals,
    single-shot proposal consumption) own that, and the CI policy table
    proves THOSE stay live.

    ``signing_epoch`` is the ISO-8601 UTC instant record signing was adopted
    at. Setting it requires a verifying signature on EVERY record, of every
    type and every ``ts`` (see the module docstring); ``now`` is the explicit
    evaluation instant the epoch's own validity is judged at, and is REQUIRED
    when an epoch is supplied. Neither is ever derived from the data.
    """
    if signing_epoch is not None and now is None:
        raise ValueError(
            "signing_epoch requires an explicit evaluation instant (now=...); "
            "deriving one from the records under audit would let the ledger "
            "decide whether its own epoch is in force"
        )
    violations: list[AuditViolation] = list(dataset.parse_violations)
    skipped: list[str] = []
    annotations: list[str] = []
    resolvers = _as_role_resolvers(record_key_resolver)
    ledger = _records_by_coordinate(dataset)
    in_force = {e.principal_key: e.envelope_hash for e in dataset.envelopes}
    # Findings with nothing to bind an acknowledgment to. They are never
    # waived, whatever the rule's place in WAIVABLE_RULES.
    unbound_findings: set[AuditViolation] = set()

    for entry in dataset.grants:
        grant = entry.grant
        coordinate = _grant_coordinate(grant)
        coordinate_records = ledger.get(coordinate, [])

        # LEDGER_COUNTERPART — every level was earned through the ceremony
        # ledger: seeds emit bootstrap records, promotions append
        # promotion records, so a grant with neither is a bypass write.
        # Since the atomic-write change the record and the grant commit as ONE atomic unit
        # (write_record_and_grant at every ceremony write-pair site), so NEW
        # findings here can no longer be ceremony fallout. The rule STAYS: it
        # still catches historical artifacts (pre-atomicity interruptions)
        # and out-of-band tamper — a finding dated after the atomic-write cutover is
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
        # grant BELOW its ledger is the separate, waivable LEVEL_DROP_RECORDED
        # below: it fails toward less authority, but it is still a drop the
        # ledger cannot explain.
        # A reattestation record is passed over: the derived level is the one
        # the ledger held immediately before it.
        level_records = _level_bearing(coordinate_records)
        derived = level_records[-1].record.toLevel if level_records else None
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

        # LEVEL_DROP_RECORDED (GAL §6.11) — every level drop is recorded:
        # demotion, tightening and lapse each append their record in the SAME
        # atomic unit as the lowered grant, so a grant below its
        # ledger-derived level is a drop no record explains — an out-of-band
        # write, or pre-atomic-write history where demotion wrote the grant first.
        # Waivable (acknowledgments.WAIVABLE_RULES) because that history
        # failed toward less authority. Read-side limit: it judges the stored
        # level only. A grant whose certification term has passed but whose
        # lapse is not yet written sits AT its ledger level and is not a
        # finding here — enforcement already acts at lastSafeLevel
        # (grants.term.effective_level), and this auditor takes no clock.
        if derived is not None and _rank(grant.level) < _rank(derived):
            violations.append(
                AuditViolation(
                    rule=LEVEL_DROP_RECORDED,
                    coordinate=coordinate,
                    detail=(
                        f"grant level {grant.level.value!r} is below the ledger-derived "
                        f"level {derived.value!r}; every level drop (demotion, "
                        "tightening, lapse) appends its own record"
                    ),
                )
            )

        # GRANT_TERM_RATIFIED (GAL §6.7.6) — the term enforced is the
        # term the checker ratified. Only a promotion sets a term: the ceremony
        # writes the same value onto the grant and onto the signed promotion
        # record, and every later write (demotion, tightening, lapse,
        # re-attestation) carries it forward unchanged — the stores refuse any
        # non-promotion lengthening (store.refuse_term_extension). So the
        # grant's term must equal the one on the chronologically-latest
        # promotion record, however the level moved since: a later lapse or
        # demotion explains the LEVEL, never a different term. A lapse record
        # may carry certifiedUntil too (the term that expired, GAL §5.2), and
        # this rule does not read it: what a lapse record says about a term
        # is the evaluator's account, never what the checker ratified. With no
        # promotion on the ledger (bootstrap only) there is no ratified term,
        # so the grant must carry none. Un-waivable: a mismatch is a term the
        # checker never ratified — authority, in either direction.
        promotions = [e.record for e in coordinate_records if e.record.recordType == "promotion"]
        ratified_term = promotions[-1].certifiedUntil if promotions else None
        if coordinate_records and grant.certifiedUntil != ratified_term:
            source = (
                f"the latest promotion record (ts={promotions[-1].ts})"
                if promotions
                else "the ledger, which holds no promotion record"
            )
            violations.append(
                AuditViolation(
                    rule=GRANT_TERM_RATIFIED,
                    coordinate=coordinate,
                    detail=(
                        f"grant certifiedUntil {grant.certifiedUntil!r} differs from the "
                        f"term {ratified_term!r} ratified on {source}; the term enforced "
                        "must be the term the checker ratified"
                    ),
                )
            )

        # GRANT_TS_RECORDED (GAL §6.11, GAL-40): the grant's ts is the
        # ledger's. Every sanctioned write stamps the grant and the record it
        # appends with one ts (write_record_and_grant, ts from next_ledger_ts),
        # so a grant's ts must be the ts of the latest record at its
        # coordinate. Later than every record: something wrote the grant and
        # appended nothing. Earlier than the latest: a record was appended and
        # its grant write did not land. The level, term and envelope rules
        # above each catch a write that moved the field they read; this one
        # catches a write that moved none of them.
        # Every record type counts, reattestation included (no _level_bearing
        # here): the rule reads a timestamp, and re-seed stamps its record and
        # the grant like any other writer.
        # A grant with NO record at all is LEDGER_COUNTERPART's finding and
        # not also this one: there is no latest record to hold it to, and one
        # orphan would otherwise need two acknowledgments for one fact.
        # The boundary is "no record", which is narrower than that rule's "no
        # bootstrap or promotion record". A coordinate holding only records
        # that earn nothing (a lone demotion, a lone reattestation) still has
        # a latest record, so a grant ts that is not that record's is this
        # finding as well as that one: two facts, a grant nothing earned and
        # a grant write nothing recorded.
        # Waivable (acknowledgments.WAIVABLE_RULES), for a ledger whose grants
        # were re-attested before re-attestation appended a record. The detail
        # carries the sha256 of the grant's STORED bytes and both timestamps,
        # so an acknowledgment excuses the grant as it stood and a later
        # rewrite is a new finding. (Where a record's ts is not an instant
        # there is no latest ts to name, and the detail carries a digest of
        # every record at the coordinate in its place.) It is the digest of the bytes and not the
        # item's grantHash, which is an attribute beside them that a keyless
        # run cannot check and a rewrite can leave in place. Nothing else takes a grant out of scope:
        # no date, no epoch, no field on the grant or on a record. Read-side
        # limits: it compares timestamps and cannot say what the unexplained
        # write changed. And it holds the grant to the ledger as it stands, so
        # a record planted at the grant's ts satisfies it. Whether a ceremony
        # wrote that record is RECORD_SIGNATURE_VERIFIES's question, which is
        # asked of every record type only once RECORD_SIGNING_EPOCH is set.
        mismatch = (
            _grant_ts_mismatch(grant.ts, coordinate_records) if coordinate_records else None
        )
        if mismatch is not None:
            clause, ledger_bound = mismatch
            stored = (
                f"stored bytes sha256:{stored_record_digest_hex(entry.raw_data)}"
                if entry.raw_data is not None
                else "no stored bytes on the dataset entry, so nothing an acknowledgment can bind"
            )
            finding = AuditViolation(
                rule=GRANT_TS_RECORDED,
                coordinate=coordinate,
                detail=(
                    f"grant at level {grant.level.value!r} ({stored}) carries "
                    f"ts={grant.ts!r}, which {clause}; every sanctioned write "
                    "stamps the grant and its record with one ts"
                ),
            )
            violations.append(finding)
            if entry.raw_data is None or not ledger_bound:
                unbound_findings.add(finding)

        # GRANT_ENVELOPE_IN_FORCE — grant.envelopeHash must match the
        # stored in-force envelope for its principal. A mismatched grant is
        # quarantined by the broker on EVERY call — operationally
        # dead — yet is HMAC-clean, so no other rule sees it (the dead-grant incident
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
            # grantHash (never a re-serialization, so schema evolution
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

    # EVALUATOR_RECORD_CONTINUOUS — a record the evaluator's key signs
    # (demotion, lapse) must start from the level the ledger held immediately
    # before it. The schema already refuses one that raises on its own terms
    # (fromLevel -> toLevel). That is not enough: a "demotion" from out-of-loop
    # to on-loop lowers on paper, and planted on a ledger that stood at in-loop
    # it leaves the derived level at on-loop, raised, under the evaluator's
    # key. The issuer's key is the only one that may raise (GAL §6.10), so an
    # evaluator record is honest only as a step down from where the ledger
    # actually was. Judged over every coordinate with records, grant or no
    # grant. Un-waivable: a finding is a raise the issuer never signed.
    # "The level the ledger held" passes over reattestation records, which
    # hold none: a demotion that follows one starts from the level before it.
    for coordinate, coordinate_records in ledger.items():
        level_before = None
        for entry in _level_bearing(coordinate_records):
            record = entry.record
            if (
                signing_role_for_record_type(record.recordType) == EVALUATOR_ROLE
                and record.fromLevel != level_before
            ):
                held = level_before.value if level_before is not None else "no level"
                violations.append(
                    AuditViolation(
                        rule=EVALUATOR_RECORD_CONTINUOUS,
                        coordinate=coordinate,
                        detail=(
                            f"{record.recordType} record at {record.ts} starts from "
                            f"{record.fromLevel.value!r}, but the ledger held {held!r} "
                            "immediately before it; a record the evaluator signs may "
                            "only lower the level the ledger accounts for"
                        ),
                    )
                )
            level_before = record.toLevel

    # RECORD_SIGNATURE_VERIFIES — a record in scope must carry a DSSE envelope
    # that verifies under ITS RECORD TYPE'S signing role (fails closed):
    # issuer for promotion/bootstrap/tightening/reattestation, evaluator for
    # demotion/lapse (record_signing.RECORD_TYPE_SIGNING_ROLE). Binding the type to the role
    # is what makes the second identity mean anything — an evaluator-signed
    # promotion is an attempt to mint authority from the no-model side, and an
    # auditor that accepted any known key would wave it through.
    #
    # SCOPE is the epoch's job, never a per-type exemption list and never a
    # per-record one:
    #   epoch set:   every record of every type must be signed, whatever its
    #                ts. A record's own timestamp excuses nothing, because on
    #                an unsigned record that field is the writer's own claim.
    #                Honest unsigned history is excused by acknowledgment.
    #   epoch unset: the narrower scope (promotion required, lapse- and
    #                reattestation-if-signed)
    #                plus a LOUD annotation that the rest is unenforced.
    # Read-side limit: predicate fields inside the record (covered, provenance
    # maturity) are proposer ASSERTIONS at N=1 owner — #21 tracks deriving
    # provenance maturity rather than asserting it (two earlier issues were named here
    # and both closed without landing that measurement) — so this rule verifies
    # AUTHENTICITY (who signed what), never the truth of the asserted evidence.

    if resolvers is None:
        skipped.append(RECORD_SIGNATURE_VERIFIES)
        annotations.append(
            f"{ANNOTATION_SIGNING_EPOCH_UNENFORCEABLE}: no verify keys are configured "
            f"for any signing role, so no record signature was checked"
            + (f" (RECORD_SIGNING_EPOCH={signing_epoch})" if signing_epoch else "")
        )
    else:
        if signing_epoch is None:
            annotations.append(
                f"{ANNOTATION_SIGNING_EPOCH_UNSET}: no RECORD_SIGNING_EPOCH is "
                "configured, so the all-types signing requirement (bootstrap, "
                "demotion, tightening, reattestation) is NOT enforced; only promotion "
                "records are required to be signed, and lapse and reattestation "
                "records only if they carry a signature. Set RECORD_SIGNING_EPOCH to the ISO-8601 UTC "
                "instant record signing was adopted at to enforce GAL-SPEC §6.10 "
                "on every record"
            )
        else:
            epoch_instant, epoch_label = _epoch_instant_and_label(signing_epoch)
            # RECORD_SIGNING_EPOCH_VALID — the epoch is judged at the SUPPLIED
            # evaluation instant, and that is the only thing the instant is
            # used for. An epoch after it names an adoption that has not
            # happened: a misconfiguration, un-waivable and loud. It narrows
            # nothing. The loop below runs with the all-types requirement on,
            # so a future epoch can only add this finding to the report.
            if epoch_instant > now:
                violations.append(
                    AuditViolation(
                        rule=RECORD_SIGNING_EPOCH_VALID,
                        coordinate="RECORD_SIGNING_EPOCH",
                        detail=(
                            f"the configured record-signing epoch {epoch_label} is "
                            f"after the evaluation instant {now.isoformat()}; it is "
                            "not yet in force. The all-types signing requirement "
                            "was applied to every record regardless"
                        ),
                    )
                )
        # An epoch that is set turns the all-types requirement on for every
        # record. Nothing about a record, its ts included, turns it back off.
        all_types_required = signing_epoch is not None
        for entry in dataset.records:
            record_type = entry.record.recordType
            if not all_types_required:
                # No-epoch scope: a promotion or a reattestation must be
                # signed; a lapse that carries a signature must verify; the
                # other types are out of scope until an epoch is declared.
                if record_type in _SIGNED_IF_PRESENT_TYPES and entry.signature is None:
                    continue
                if (
                    record_type not in _ALWAYS_SIGNED_TYPES
                    and record_type not in _SIGNED_IF_PRESENT_TYPES
                ):
                    continue
            coordinate = _record_coordinate(entry.record)
            role = signing_role_for_record_type(record_type)
            # The STORED bytes are the basis for everything below. A signature
            # is verified against the sha256 over the item's data string
            # verbatim, NEVER a re-serialization of the parsed record (that
            # would re-derive the basis from today's model and read every
            # pre-schema-growth record as a signature failure). A finding names
            # the same digest, so an acknowledgment of it covers these bytes
            # only. An entry without the stored bytes can be neither verified
            # nor bound: fail closed with a violation that no acknowledgment
            # applies to, signed or not.
            if entry.raw_data is None:
                unbound = AuditViolation(
                    rule=RECORD_SIGNATURE_VERIFIES,
                    coordinate=coordinate,
                    detail=(
                        f"{record_type} record ts={entry.record.ts} has no stored "
                        "bytes on the dataset entry; without the exact stored "
                        "serialization a signature cannot be verified and a "
                        "finding cannot be bound to the record"
                    ),
                )
                violations.append(unbound)
                unbound_findings.add(unbound)
                continue
            stored = f"stored bytes sha256:{stored_record_digest_hex(entry.raw_data)}"
            # The level change rides in the finding too. Whoever acknowledges
            # an unsigned or unverifiable record must see what authority it
            # sets without opening the row: a digest alone reads the same for
            # a tightening and for a bootstrap straight to out-of-loop.
            from_level = entry.record.fromLevel.value if entry.record.fromLevel else "no grant"
            change = f"{from_level} -> {entry.record.toLevel.value}"
            if entry.signature is None:
                violations.append(
                    AuditViolation(
                        rule=RECORD_SIGNATURE_VERIFIES,
                        coordinate=coordinate,
                        detail=(
                            f"{record_type} record ts={entry.record.ts} {change} "
                            f"({stored}) carries no DSSE signature; it must be signed by the "
                            f"{role} identity"
                        ),
                    )
                )
                continue
            result = verify_record_by_type(
                entry.raw_data,
                entry.signature,
                record_type=record_type,
                resolvers=resolvers,
            )
            if not result.ok:
                violations.append(
                    AuditViolation(
                        rule=RECORD_SIGNATURE_VERIFIES,
                        coordinate=coordinate,
                        detail=(
                            f"{record_type} record ts={entry.record.ts} {change} "
                            f"({stored}) failed signature verification ({result.reason}); this "
                            f"type is signed by the {role} identity"
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

    # Acknowledgments — sanctioned disposition of TRUE findings. Judged
    # BEFORE they can waive anything: a waiver mints "green", so it is itself
    # authority. Rules: only WAIVABLE_RULES can be acknowledged (closed
    # vocabulary — HMAC tamper etc. stay un-waivable); the acknowledgment must
    # be issuer-signed and VERIFY (no resolver ⇒ verification skipped LOUDLY
    # and NO waiver applies — fail toward RED, never toward green); the match
    # is exact on (rule, coordinate, detail-digest), so a NEW finding at the
    # same coordinate is never auto-waived by an old acknowledgment. A
    # RECORD_SIGNATURE_VERIFIES detail carries the sha256 of the record's
    # stored bytes, so that holds for a record REPLACED in place too.
    # Acknowledgments stay ISSUER-signed: a waiver mints "green", which is
    # authority, so it belongs to the ceremony side and never to the automatic
    # evaluator (which only ever lowers). Hence resolvers.issuer, not a
    # role selected by anything in the record.
    waivers: dict[tuple[str, str, str], str] = {}
    if resolvers is None or resolvers.issuer is None:
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
            # Verify from the STORED bytes (stored-bytes instance 7); an entry without
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
            result = verify_acknowledgment(
                entry.raw_data, entry.signature, resolvers.issuer
            )
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
            if violation.rule in WAIVABLE_RULES and violation not in unbound_findings
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
        annotations=tuple(annotations),
    )
