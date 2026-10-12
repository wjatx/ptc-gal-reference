"""grants.grant_standing: does the issuer key behind a grant's level still have standing?

GAL §6.10 (GAL-41, #179): a verifier establishes, at the evaluation instant and
from a source it pins, that the key which signed the record a grant's level
rests on has not been withdrawn. Where standing is withdrawn, or cannot be
established within the declared maximum age, the grant acts at the lower of its
level and lastSafeLevel. This module is the enforcer's half and the part the
withdrawal runner and the audit share.

Which record a level rests on
-----------------------------
The last record that licensed the grant: the latest ``bootstrap`` or
``promotion`` at its coordinate, or a ``reattestation`` after one. Only records
at or before the grant's own ``ts`` count. Every sanctioned write stamps the
grant and its record with one ``ts``, so on an honest ledger that is every
record, and a record appended later with no grant write beside it does not
describe the grant as stored. Demotion, lapse, tightening and withdrawal
records lower a level or keep it and license nothing, so none of them moves the
key a level rests on. That is also why an evaluator key's withdrawal changes no
enforced level: no evaluator-signed record licenses a grant.

The key id is taken from that record's signature, and only after the signature
verifies over the stored bytes (``record_signing.verify_record_by_type``). An
envelope's ``keyid`` is a claim until then.

Unsigned history, and the record-signing epoch
----------------------------------------------
Standing applies from the record-signing epoch (``RECORD_SIGNING_EPOCH``). A
licensing record with no signature whose ``ts`` is before the epoch is history
signed by no key, so there is no key whose standing could be asked about; it is
``before_epoch``, and the grant keeps its level. With no epoch declared every
unsigned licensing record is treated that way, with one exception below. The
audit reports such records (RECORD_SIGNATURE_VERIFIES) and says when no standing
source is configured. The record's ``ts`` is judged up to the skew bound LATER
(an authority-raising record, GAL-42), so the bound can only narrow the
exemption. A licensing record that is unsigned at or after the epoch, carries a
signature that does not verify, or names a key the standing document does not
list, leaves standing not established, and the grant falls.

The exception: an unsigned licensing record that comes after a signed record at
its coordinate, in ledger order, is never history, whatever its ``ts`` and
whether or not an epoch is declared. Signing had begun at that coordinate before
it was written, so its ``ts`` is only its own claim about when it was made, and
GAL §6.10 excuses no unsigned record by anything it says about itself. Without
this, a writer that may append records but holds no issuer key could plant an
unsigned ``reattestation`` at the grant's own ``ts`` (its sk sorts after the
signed ``promotion`` beside it) and restore a level a withdrawal took away.

What the cache keys on
----------------------
The resolved key for a coordinate is cached against the grant's ``ts``, as the
design ruling on #179 sets out. The next sanctioned write changes the ``ts``, so the first
call after each ledger write pays one partition Query and one signature check,
and every other call pays a dictionary lookup. A verified key id and a
``before_epoch`` result depend on nothing else and stay cached until the grant
is written again. A result that did not verify is cached against the standing
document's version too, because a later document can add the key that signed
it. A ledger that could not be read is never cached.

What this buys, and its limits
------------------------------
A grant whose licensing record was signed by a withdrawn key acts at the lower
of its level and lastSafeLevel from the first call after this process accepts
the withdrawal, with no write. It does not cover the window between a
withdrawal's publication and the next fetch (up to the maximum age), anything
the key's holder did before the withdrawal was published, or a compromise of the
standing-authority key. The reading is the last licensing record: a ladder
whose lower rung was signed by a withdrawn key and whose upper rung was not
keeps the upper rung's level.
"""

from __future__ import annotations

import datetime
import logging
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from safe_agents.broker.grants.ledger_clock import _recorded_instant
from safe_agents.broker.grants.record_signing import (
    ISSUER_ROLE,
    RoleKeyResolvers,
    verify_record_by_type,
)
from safe_agents.broker.grants.standing_source import (
    IN_STANDING,
    NOT_ESTABLISHED,
    WITHDRAWN,
    StandingSource,
)
from safe_agents.broker.runtime.input_age import InputAsOf
from safe_agents.broker.schemas import Grant
from safe_agents.broker.schemas.clock_skew import ZERO_SKEW, end_judged_at
from safe_agents.broker.schemas.common import AUTONOMY_RANK, Principal
from safe_agents.broker.schemas.promotion_record import REATTESTATION_RECORD_TYPE

logger = logging.getLogger(__name__)

#: The env name of the record-signing epoch: the instant record signing was
#: adopted at. The audit reads it (grants/audit_command.py); the enforcer reads
#: it where an issuer standing source is configured.
RECORD_SIGNING_EPOCH_ENV = "RECORD_SIGNING_EPOCH"

#: The record types that earn a level. A reattestation after one re-licenses it.
EARNING_RECORD_TYPES: tuple[str, ...] = ("bootstrap", "promotion")

# What resolving the key behind a grant's level can find.
LICENSED_BY_KEY = "key"
LICENSED_BEFORE_EPOCH = "before_epoch"
LICENSING_UNVERIFIED = "unverified"

#: The prefixes of a fall's reason, so a reader can tell a withdrawal (act on
#: the key) from an outage (act on the source) without parsing the rest.
FALL_KEY_WITHDRAWN = "issuer key withdrawn"
FALL_NOT_ESTABLISHED = "issuer standing not established"


class StoredRecordReader(Protocol):
    """A record store that returns a coordinate's records as stored, in sk order."""

    def list_stored_records(self, principal: Principal, action_class: str, session=None): ...


@dataclass(frozen=True)
class LicensingKey:
    """What a grant's level rests on: a verified key, unsigned history, or neither."""

    kind: str
    key_id: str | None = None
    record_type: str | None = None
    record_ts: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class StandingAssessment:
    """One grant's standing at one instant.

    ``held`` False means the grant acts at the lower of its level and
    lastSafeLevel. ``reason`` says why, beginning with ``FALL_KEY_WITHDRAWN`` or
    ``FALL_NOT_ESTABLISHED``. ``as_of`` is the standing document's as-of where
    the answer depended on it, for the decision's input record (#176).
    """

    held: bool
    reason: str | None = None
    as_of: InputAsOf | None = None


def _instant(value: object) -> datetime.datetime | None:
    try:
        return _recorded_instant(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None


def licensing_record(stored: Sequence, grant_instant: datetime.datetime):
    """The last record at or before ``grant_instant`` that licensed the grant, or None.

    ``stored`` is a coordinate's records in ledger (sk) order, each with a
    ``.record``. The latest ``bootstrap`` or ``promotion``, or a
    ``reattestation`` after one. A record whose ``ts`` is not an instant cannot
    be placed and is passed over.
    """
    found = None
    earned = False
    for entry in stored:
        instant = _instant(entry.record.ts)
        if instant is None or instant > grant_instant:
            continue
        record_type = entry.record.recordType
        if record_type in EARNING_RECORD_TYPES:
            earned = True
            found = entry
        elif record_type == REATTESTATION_RECORD_TYPE and earned:
            found = entry
    return found


def _before_epoch(
    instant: datetime.datetime,
    epoch: datetime.datetime | None,
    skew: datetime.timedelta,
) -> bool:
    """True iff unsigned history at ``instant`` predates the record-signing epoch.

    The instant is a record's own claim, judged up to the bound LATER (GAL-42),
    so a skew bound only narrows what counts as history. No epoch declared:
    every unsigned record is history.
    """
    if epoch is None:
        return True
    return end_judged_at(instant, skew) < epoch


def _follows_a_signed_record(stored: Sequence, entry) -> bool:
    """True iff a record before ``entry`` in ledger (sk) order carries a signature.

    A carried signature, verified or not, shows that signing had begun at the
    coordinate. Counting one that does not verify can only make more grants
    fall, never fewer.
    """
    for earlier in stored:
        if earlier is entry:
            return False
        if earlier.signature is not None:
            return True
    return False


def resolve_licensing_key(
    stored: Sequence,
    grant: Grant,
    *,
    resolvers: RoleKeyResolvers,
    signing_epoch: datetime.datetime | None = None,
    skew: datetime.timedelta = ZERO_SKEW,
) -> LicensingKey:
    """The verified key behind ``grant``'s level (see the module docstring)."""
    grant_instant = _instant(grant.ts)
    if grant_instant is None:
        return LicensingKey(
            LICENSING_UNVERIFIED, detail=f"the grant's ts {grant.ts!r} is not an instant"
        )
    entry = licensing_record(stored, grant_instant)
    if entry is None:
        if _before_epoch(grant_instant, signing_epoch, skew):
            return LicensingKey(
                LICENSED_BEFORE_EPOCH,
                detail="no record licenses the grant, and its ts is before the record-signing epoch",
            )
        return LicensingKey(
            LICENSING_UNVERIFIED,
            detail="no bootstrap, promotion or reattestation record licenses the grant",
        )
    record = entry.record
    where = {"record_type": record.recordType, "record_ts": record.ts}
    if entry.signature is None:
        if _follows_a_signed_record(stored, entry):
            return LicensingKey(
                LICENSING_UNVERIFIED,
                detail=(
                    f"the {record.recordType} record at ts={record.ts} that licensed the grant "
                    "is unsigned and comes after a signed record at its coordinate, so it is "
                    "not history"
                ),
                **where,
            )
        record_instant = _instant(record.ts)
        if record_instant is not None and _before_epoch(record_instant, signing_epoch, skew):
            return LicensingKey(
                LICENSED_BEFORE_EPOCH,
                detail=f"the licensing {record.recordType} record is unsigned history",
                **where,
            )
        return LicensingKey(
            LICENSING_UNVERIFIED,
            detail=(
                f"the {record.recordType} record at ts={record.ts} that licensed the grant "
                "is unsigned and not before the record-signing epoch"
            ),
            **where,
        )
    if not isinstance(entry.signature, dict):
        result_reason = "record_signature_malformed"
        key_id = None
    else:
        result = verify_record_by_type(
            entry.data, entry.signature, record_type=record.recordType, resolvers=resolvers
        )
        result_reason, key_id = result.reason, result.key_id
    if key_id is not None:
        return LicensingKey(LICENSED_BY_KEY, key_id=key_id, **where)
    return LicensingKey(
        LICENSING_UNVERIFIED,
        detail=(
            f"the {record.recordType} record at ts={record.ts} that licensed the grant "
            f"failed signature verification ({result_reason})"
        ),
        **where,
    )


def _coordinate(grant: Grant) -> tuple:
    p = grant.principal
    return (p.agentId, p.skill, p.user, p.tier, grant.actionClass)


class GrantStandingCheck:
    """The enforcer's issuer-standing input: one per broker process.

    Holds the issuer's ``StandingSource`` and refreshes it lazily, at most once
    per ``refresh_every`` (a quarter of the maximum age unless given), on the
    call that finds it due. ``assess`` never raises: an error inside it is a
    fall, never a pass. Thread-safe.
    """

    def __init__(
        self,
        *,
        source: StandingSource,
        records: StoredRecordReader,
        signing_epoch: datetime.datetime | None = None,
        skew: datetime.timedelta = ZERO_SKEW,
        refresh_every: datetime.timedelta | None = None,
    ) -> None:
        if source.role != ISSUER_ROLE:
            raise ValueError(
                "the enforcer checks the issuer's standing only: an evaluator key's "
                "withdrawal changes no enforced level"
            )
        self.source = source
        self._records = records
        self._resolvers = RoleKeyResolvers(
            issuer=source.key_resolver(), standing={ISSUER_ROLE: source}
        )
        self._epoch = signing_epoch
        self._skew = skew
        self._refresh_every = refresh_every or source.max_age / 4
        self._next_refresh: datetime.datetime | None = None
        self._refresh_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._cache: dict[tuple, tuple[str, int | None, LicensingKey]] = {}

    # -- the source ----------------------------------------------------------

    def refresh(self, now: datetime.datetime):
        """Fetch the document now, and schedule the next lazy fetch from ``now``."""
        with self._refresh_lock:
            return self._refresh_locked(now)

    def _refresh_locked(self, now: datetime.datetime):
        load = self.source.refresh()
        self._next_refresh = now + self._refresh_every
        if not load.accepted:
            logger.warning(
                "issuer standing document not accepted from %s: %s (%s); the version in "
                "force stays until its age runs out",
                self.source.source_label,
                load.verdict,
                load.detail,
            )
        return load

    def _maybe_refresh(self, now: datetime.datetime) -> None:
        due = self._next_refresh
        if due is not None and now < due:
            return
        # One caller fetches; the others decide on the document already in force.
        if self._refresh_lock.acquire(blocking=False):
            try:
                if self._next_refresh is None or now >= self._next_refresh:
                    self._refresh_locked(now)
            finally:
                self._refresh_lock.release()

    # -- the key behind a level ---------------------------------------------

    def _document_version(self) -> int:
        document = self.source.document
        return document.version if document is not None else 0

    def licensing_key(self, grant: Grant) -> LicensingKey:
        """The key behind ``grant``'s level, from the cache or one ledger read."""
        coordinate = _coordinate(grant)
        version = self._document_version()
        with self._cache_lock:
            held = self._cache.get(coordinate)
        if held is not None:
            grant_ts, held_version, key = held
            if grant_ts == grant.ts and held_version in (None, version):
                return key
        try:
            stored = self._records.list_stored_records(grant.principal, grant.actionClass)
        except Exception as exc:  # noqa: BLE001 - an unread ledger is a fall, never a pass
            return LicensingKey(
                LICENSING_UNVERIFIED,
                detail=f"the ledger could not be read ({type(exc).__name__})",
            )
        key = resolve_licensing_key(
            stored, grant, resolvers=self._resolvers, signing_epoch=self._epoch, skew=self._skew
        )
        stable = key.kind in (LICENSED_BY_KEY, LICENSED_BEFORE_EPOCH)
        with self._cache_lock:
            self._cache[coordinate] = (grant.ts, None if stable else version, key)
        return key

    # -- the per-call question ------------------------------------------------

    def assess(self, grant: Grant, now: datetime.datetime) -> StandingAssessment:
        """Is the issuer key behind ``grant``'s level in standing at ``now``?"""
        try:
            return self._assess(grant, now)
        except Exception as exc:  # noqa: BLE001 - fail toward less authority
            return StandingAssessment(
                held=False,
                reason=f"{FALL_NOT_ESTABLISHED}: the standing check failed ({type(exc).__name__})",
            )

    def _assess(self, grant: Grant, now: datetime.datetime) -> StandingAssessment:
        self._maybe_refresh(now)
        key = self.licensing_key(grant)
        if key.kind == LICENSED_BEFORE_EPOCH:
            return StandingAssessment(held=True)
        as_of = self.source.as_of()
        if key.kind == LICENSING_UNVERIFIED:
            return StandingAssessment(
                held=False, reason=f"{FALL_NOT_ESTABLISHED}: {key.detail}", as_of=as_of
            )
        standing = self.source.standing_of(key.key_id, now, skew=self._skew)
        if standing.verdict == IN_STANDING:
            return StandingAssessment(held=True, as_of=as_of)
        signed = f"the {key.record_type} record at ts={key.record_ts} that licensed this grant"
        if standing.verdict == WITHDRAWN:
            entry = standing.entry
            return StandingAssessment(
                held=False,
                reason=(
                    f"{FALL_KEY_WITHDRAWN}: key {key.key_id!r} ({entry.withdrawnReason}, "
                    f"withdrawn at {entry.withdrawnAt}) signed {signed}"
                ),
                as_of=as_of,
            )
        if standing.verdict == NOT_ESTABLISHED:
            if standing.version is None:
                why = "no issuer standing document has been accepted"
            else:
                why = (
                    f"the issuer standing document (version {standing.version}) is past its "
                    f"maximum age at {now.isoformat()}"
                )
            return StandingAssessment(
                held=False, reason=f"{FALL_NOT_ESTABLISHED}: {why}", as_of=as_of
            )
        return StandingAssessment(
            held=False,
            reason=(
                f"{FALL_NOT_ESTABLISHED}: key {key.key_id!r}, which signed {signed}, "
                "is not in the issuer standing document"
            ),
            as_of=as_of,
        )


def ceremony_standing_refusal(
    check: GrantStandingCheck | None, grant: Grant, now: datetime.datetime
) -> str | None:
    """Why an issuer-side ceremony must not build on ``grant`` at ``now``, or None.

    The standing analog of ``term.lapse_pending``. A grant above its
    lastSafeLevel whose issuer standing is not held already acts at the lower
    of the two. A ceremony that built on its stored level would make that level
    act again with no promotion: a re-attestation would become the licensing
    record under a key in standing, and a promotion would raise the grant from
    a level it no longer holds. So both refuse. Recovery from a withdrawal is
    the withdrawal runner's record and then the full promotion ceremony from the
    lowered level; "not established" recovers when the source answers.

    None when no issuer standing source is configured (``check`` None), or when
    the grant is at or below lastSafeLevel and has nowhere to fall.
    """
    if check is None or AUTONOMY_RANK[grant.level] <= AUTONOMY_RANK[grant.lastSafeLevel]:
        return None
    assessment = check.assess(grant, now)
    return None if assessment.held else assessment.reason


def parse_signing_epoch(value: str | None) -> datetime.datetime | None:
    """``RECORD_SIGNING_EPOCH`` as an instant, or None when unset.

    An epoch with no UTC offset is refused: it must name one instant.
    """
    if not value:
        return None
    parsed = datetime.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(
            f"{RECORD_SIGNING_EPOCH_ENV}={value!r} has no UTC offset; it must name an instant"
        )
    return parsed.astimezone(datetime.UTC)
