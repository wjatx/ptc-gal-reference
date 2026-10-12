"""grants.audit_key_standing: the audit's half of signing-key standing.

GAL §6.10 (GAL-41, #179). The enforcer lowers a grant whose issuer key was
withdrawn, and the withdrawal runner records it. This module reports what
neither of them can see, run by ``grants.audit.run_audit``. Every rule here is
un-waivable: none is in ``acknowledgments.WAIVABLE_RULES``, because each one
reports authority resting on a key the deployment has said it no longer trusts,
or a record claiming a fall the ledger does not support.

  RECORD_SIGNER_IN_STANDING     a record whose signature verifies under a key
                                its role's standing document lists as
                                withdrawn, whatever the record's ts and for
                                either role. An evaluator key's withdrawal is
                                reported here and changes no enforced level.
                                Every signed record is judged, inside the
                                signing epoch's scope or not.
  GRANT_STANDING_WITHDRAWN      a grant whose level rests on a withdrawn issuer
                                key and that still sits above its
                                lastSafeLevel: the withdrawal runner has not
                                lowered it. The enforcer already acts lower;
                                the stored grant and the ledger do not say so.
  KEY_SIGNED_AFTER_RETIREMENT   a record signed by a retired key with a ts at or
                                after the key's retiredAt. The ts is judged up
                                to the clock-skew bound LATER (GAL-42), toward
                                reporting. A retired key's records keep their
                                standing; one it signed after retirement is a
                                key still in use that the document says is not.
  WITHDRAWAL_RECORD_MATCHES_LEDGER  a withdrawal record whose coordinate has no
                                licensing record before it that verifies under
                                a key the issuer's standing document lists as
                                withdrawn. The key is derived from the ledger,
                                never read from the record.

Which record a level rests on is ``grants.grant_standing.licensing_record``,
the enforcer's own reading, so the two cannot disagree about which key to ask
after. The audit applies the same reading and not the stricter one (every
issuer-signed raise in the chain); a ladder whose lower rung was signed by a
withdrawn key and whose upper rung was not is not reported.

Standing applies from the record-signing epoch: an unsigned licensing record
is history signed by no key, and is RECORD_SIGNATURE_VERIFIES's to report,
never GRANT_STANDING_WITHDRAWN's. That rule reports only a key that verified
and is withdrawn, so the epoch changes none of its findings and is not read
here, which keeps the audit's rule that no record's ts is compared with it.

With no standing document configured for a role, the rules that need it cannot
run for that role, and a named annotation says so, as an unset signing epoch
is annotated. For the issuer, that annotation is the report that the
deployment does not conform to GAL-41, which is a different fact from passing
it. With no verify keys configured at all, WITHDRAWAL_RECORD_MATCHES_LEDGER is
named in ``skipped_rules`` beside RECORD_SIGNATURE_VERIFIES. The auditor takes
no clock: retirement is judged against each record's own ts.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from safe_agents.broker.grants.demotion import _rank
from safe_agents.broker.grants.grant_standing import (
    LICENSED_BY_KEY,
    licensing_record,
    resolve_licensing_key,
)
from safe_agents.broker.grants.key_standing import KEY_WITHDRAWN, parse_standing_instant
from safe_agents.broker.grants.ledger_clock import _recorded_instant
from safe_agents.broker.grants.record_signing import (
    ISSUER_ROLE,
    RECORD_SIGNER_WITHDRAWN,
    RoleKeyResolvers,
    signing_role_for_record_type,
    stored_record_digest_hex,
    verify_record_by_type,
)
from safe_agents.broker.grants.standing_source import StandingSource
from safe_agents.broker.schemas.clock_skew import ZERO_SKEW, end_judged_at
from safe_agents.broker.schemas.promotion_record import WITHDRAWAL_RECORD_TYPE

RECORD_SIGNER_IN_STANDING = "RECORD_SIGNER_IN_STANDING"
GRANT_STANDING_WITHDRAWN = "GRANT_STANDING_WITHDRAWN"
KEY_SIGNED_AFTER_RETIREMENT = "KEY_SIGNED_AFTER_RETIREMENT"
WITHDRAWAL_RECORD_MATCHES_LEDGER = "WITHDRAWAL_RECORD_MATCHES_LEDGER"

KEY_STANDING_RULES: tuple[str, ...] = (
    RECORD_SIGNER_IN_STANDING,
    GRANT_STANDING_WITHDRAWN,
    KEY_SIGNED_AFTER_RETIREMENT,
    WITHDRAWAL_RECORD_MATCHES_LEDGER,
)

#: The issuer has no standing document: GAL-41 is not conformed to.
ANNOTATION_ISSUER_STANDING_UNCONFIGURED = "gal-41-issuer-standing-unconfigured"
#: The evaluator has no standing document: its records are not checked for withdrawal.
ANNOTATION_EVALUATOR_STANDING_UNCONFIGURED = "evaluator-standing-unconfigured"


@dataclass
class KeyStandingFindings:
    """What the rules found: (rule, coordinate, detail) triples, skips and notes."""

    violations: list[tuple[str, str, str]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Stored:
    """A ledger entry in the shape grant_standing reads: record, stored bytes, envelope."""

    record: object
    data: str | None
    signature: object


def _instant(value: object) -> datetime.datetime | None:
    try:
        return _recorded_instant(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None


def _stored(entries: Iterable) -> list[_Stored]:
    return [_Stored(e.record, e.raw_data, e.signature) for e in entries]


def _verified_signer(entry: _Stored, resolvers: RoleKeyResolvers) -> tuple[str | None, str | None]:
    """(verified key id, verify reason) for a signed entry; (None, None) when unsigned."""
    if entry.signature is None or entry.data is None or not isinstance(entry.signature, dict):
        return None, None
    result = verify_record_by_type(
        entry.data, entry.signature, record_type=entry.record.recordType, resolvers=resolvers
    )
    return result.key_id, result.reason


def key_standing_findings(
    *,
    ledger: Mapping[str, Sequence],
    grants: Iterable,
    resolvers: RoleKeyResolvers | None,
    coordinate_of,
    skew: datetime.timedelta = ZERO_SKEW,
) -> KeyStandingFindings:
    """Run the four rules (module docstring).

    ``ledger`` maps a coordinate to its audited records in ledger order;
    ``grants`` are the audited grants; ``coordinate_of`` maps a Grant to its
    coordinate. Pure: no store, no clock.
    """
    out = KeyStandingFindings()
    standing: Mapping[str, object] = resolvers.standing if resolvers is not None else {}
    issuer = standing.get(ISSUER_ROLE)
    if issuer is None:
        out.annotations.append(
            f"{ANNOTATION_ISSUER_STANDING_UNCONFIGURED}: no issuer standing document is "
            "configured, so this deployment does not conform to GAL-41 (GAL §6.10): no "
            f"grant was checked for a withdrawn issuer key ({GRANT_STANDING_WITHDRAWN}), "
            f"and no issuer-signed record for a withdrawn or retired signer "
            f"({RECORD_SIGNER_IN_STANDING}, {KEY_SIGNED_AFTER_RETIREMENT})"
        )
    if "evaluator" not in standing:
        out.annotations.append(
            f"{ANNOTATION_EVALUATOR_STANDING_UNCONFIGURED}: no evaluator standing document is "
            "configured, so no demotion, lapse or withdrawal record was checked for a "
            f"withdrawn or retired signer ({RECORD_SIGNER_IN_STANDING}, "
            f"{KEY_SIGNED_AFTER_RETIREMENT})"
        )
    if resolvers is None:
        # No verify keys at all: RECORD_SIGNATURE_VERIFIES is skipped and says
        # so, and no signer can be known, so these rules have nothing to judge.
        out.skipped.append(WITHDRAWAL_RECORD_MATCHES_LEDGER)
        return out

    for coordinate, entries in ledger.items():
        stored = _stored(entries)
        for entry in stored:
            role = signing_role_for_record_type(entry.record.recordType)
            source = standing.get(role)
            if source is None:
                continue
            key_id, reason = _verified_signer(entry, resolvers)
            if key_id is None:
                continue
            where = (
                f"{entry.record.recordType} record ts={entry.record.ts} (stored bytes "
                f"sha256:{stored_record_digest_hex(entry.data)})"
            )
            if reason == RECORD_SIGNER_WITHDRAWN:
                out.violations.append((
                    RECORD_SIGNER_IN_STANDING,
                    coordinate,
                    f"{where} is signed by {role} key {key_id!r}, which the {role} standing "
                    "document lists as withdrawn; no record it signed has standing, "
                    "whatever its ts",
                ))
            retired = _retired_at(source, key_id)
            if retired is not None:
                instant = _instant(entry.record.ts)
                if instant is None or end_judged_at(instant, skew) >= retired:
                    out.violations.append((
                        KEY_SIGNED_AFTER_RETIREMENT,
                        coordinate,
                        f"{where} is signed by {role} key {key_id!r}, retired at "
                        f"{retired.isoformat()}; a retired key signs nothing new"
                        + (f" (judged with a clock-skew bound of {skew})" if skew else ""),
                    ))
        for entry in stored:
            if entry.record.recordType == WITHDRAWAL_RECORD_TYPE:
                detail = _withdrawal_disagreement(entry, stored, issuer, resolvers)
                if detail is not None:
                    out.violations.append((WITHDRAWAL_RECORD_MATCHES_LEDGER, coordinate, detail))

    if issuer is not None:
        for audited in grants:
            grant = audited.grant
            if _rank(grant.level) <= _rank(grant.lastSafeLevel):
                continue
            coordinate = coordinate_of(grant)
            key = resolve_licensing_key(
                _stored(ledger.get(coordinate, ())),
                grant,
                resolvers=resolvers,
                skew=skew,
            )
            if key.kind == LICENSED_BY_KEY and issuer.key_state(key.key_id) == KEY_WITHDRAWN:
                out.violations.append((
                    GRANT_STANDING_WITHDRAWN,
                    coordinate,
                    f"grant at level {grant.level.value!r} rests on the {key.record_type} "
                    f"record at ts={key.record_ts}, signed by issuer key {key.key_id!r}, "
                    "which the issuer standing document lists as withdrawn; the enforcer "
                    f"acts at {grant.lastSafeLevel.value!r} and no withdrawal record has "
                    "lowered the stored grant",
                ))
    return out


def _retired_at(source: object, key_id: str) -> datetime.datetime | None:
    """The key's retiredAt in the role's accepted document, or None."""
    document = source.document if isinstance(source, StandingSource) else None
    entry = document.keys.get(key_id) if document is not None else None
    if entry is None or entry.retiredAt is None:
        return None
    return parse_standing_instant(entry.retiredAt, "retiredAt")


def _withdrawal_disagreement(entry, stored, issuer, resolvers) -> str | None:
    """Why a withdrawal record is not supported by the ledger, or None when it is."""
    where = f"withdrawal record ts={entry.record.ts}"
    instant = _instant(entry.record.ts)
    if instant is None:
        return f"{where} has a ts that is not an instant, so its place on the ledger is unknown"
    # The licensing record before the withdrawal: the ledger clock stamps each
    # record strictly after the last, so the withdrawal itself is never one.
    licensing = licensing_record(stored, instant - datetime.timedelta(microseconds=1))
    if licensing is None:
        return (
            f"{where} has no bootstrap, promotion or reattestation record before it at its "
            "coordinate; there is no level a withdrawn key could have licensed"
        )
    key_id, reason = _verified_signer(licensing, resolvers)
    if key_id is None:
        return (
            f"{where} follows a {licensing.record.recordType} record at "
            f"ts={licensing.record.ts} whose signer cannot be verified "
            f"({reason or 'unsigned'}); nothing shows that its key was withdrawn"
        )
    if issuer is None:
        return (
            f"{where} names a fall for issuer key {key_id!r}, and no issuer standing "
            "document is configured to show that key withdrawn"
        )
    if issuer.key_state(key_id) != KEY_WITHDRAWN:
        return (
            f"{where} follows a {licensing.record.recordType} record signed by issuer key "
            f"{key_id!r}, which the issuer standing document does not list as withdrawn"
        )
    return None
