"""channels.dispatch — the in-memory, transport-free reference airlock dispatcher.

**Reference-tier** per docs/contract-vs-reference.md (channels/ADAPTERS.md
§"Status"): this module exists so the gate-ordering clauses in
channels/ADAPTERS.md §"Gate ordering" are executable, and it passes the same
conformance suite (`test_adapters.py`) a third-party dispatcher would. No
transport binding lives here or is named here — see channels/ADAPTERS.md
§"Reference bindings" for where webhook/queue/peer-transit bindings land.

`dispatch_outcome` also says what the sender is told (channels/ADAPTERS.md
§"What the sender is told"): nothing, unless the adapter's gate-1 credential is
per sender (`credential_per_sender`), the sender passed gate 1, and its gate-2
identity is in the trust map, in which case a refusal before the screen is
classed `permanent` or `transient`. `dispatch` is
the same run returning only the envelope, the form the conformance suite calls.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Literal

from safe_agents.channels.adapters import InboundAdapter
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.screening import SCREEN_ERROR, ScreenVerdict, make_screen_record
from safe_agents.channels.signing import CUSTODY_EVIDENCE_PREFIX, ChainVerifyResult
from safe_agents.channels.trust_map import (
    ChannelTrustMap,
    DropReason,
    make_drop_record,
    stamp_inbound,
)

RefusalClass = Literal["permanent", "transient"]
PERMANENT: RefusalClass = "permanent"
TRANSIENT: RefusalClass = "transient"

# The `detail` of a `not_evaluated` drop: which fetched input was unavailable.
NOT_EVALUATED_KEY_SOURCE = "key_source"
NOT_EVALUATED_DEDUPE_STORE = "dedupe_store"


class KeySourceUnavailable(Exception):
    """Raised by a `verify_chain` seam whose verification keys are configured but
    could not be obtained.

    The dispatcher records the envelope `not_evaluated` (`detail` `key_source`)
    and classes the refusal `transient`. A seam raises this only when it cannot
    evaluate at all; a chain it evaluated and refused is a `ChainVerifyResult`.
    Any other exception from the seam is not caught here.
    """


@dataclass(frozen=True)
class DispatchOutcome:
    """One airlock run: the stamped envelope, or the refusal class the sender is told.

    `envelope` is the stamped, worker-ready envelope on acceptance, else None.
    `refusal` is None on acceptance, on a screen refusal (`screen_error`
    included), on a deduplicated replay, and on every refusal toward a sender
    that is not both authenticated (gate 1, by a credential bound to that one
    sender) and mapped (its gate-2 identity resolves in the trust map). Toward
    an authenticated and mapped sender, a
    refusal before the screen is `permanent` when the airlock evaluated the
    envelope and `transient` when a fetched input it needed was unavailable.
    """

    envelope: EventTrigger | None
    refusal: RefusalClass | None = None


def dispatch(
    request: Any,
    *,
    adapter: InboundAdapter,
    trust_map: ChannelTrustMap,
    screen: Callable[[EventTrigger], ScreenVerdict | bool] | None,
    verify_chain: Callable[[EventTrigger], ChainVerifyResult] | None = None,
    verdicts: Any = None,
    dedupe_store: Any,
    drops: Any,
    now: datetime,
    zone: str,
) -> EventTrigger | None:
    """Run the fixed airlock gate order and return the stamped envelope, or None.

    The same run as `dispatch_outcome`, which documents the seams; this form
    drops the refusal class and is what the conformance suite
    (`test_adapters.py`) calls.
    """
    return dispatch_outcome(
        request,
        adapter=adapter,
        trust_map=trust_map,
        screen=screen,
        verify_chain=verify_chain,
        verdicts=verdicts,
        dedupe_store=dedupe_store,
        drops=drops,
        now=now,
        zone=zone,
    ).envelope


def dispatch_outcome(
    request: Any,
    *,
    adapter: InboundAdapter,
    trust_map: ChannelTrustMap,
    screen: Callable[[EventTrigger], ScreenVerdict | bool] | None,
    verify_chain: Callable[[EventTrigger], ChainVerifyResult] | None = None,
    verdicts: Any = None,
    dedupe_store: Any,
    drops: Any,
    now: datetime,
    zone: str,
) -> DispatchOutcome:
    """Run the fixed airlock gate order (channels/ADAPTERS.md §"Gate ordering").

    `dedupe_store` is any object supporting `__contains__`/`add` (a plain
    `set` of dedupe keys works); `drops` is any object supporting `append`,
    receiving `DropRecord` instances. `verdicts` is an optional object
    supporting `append`; it ships OFF (None) by default, and when provided,
    every screen invocation appends exactly one `ScreenRecord` — pass and
    refuse alike, while a null screen appends nothing. `now` must be tz-aware
    and drives the expiry check and every recorded timestamp — this function
    never reads the wall clock.

    Short-circuits on the first gate failure, appending exactly one
    `DropRecord` per failure — the one exception is a dedupe hit, a silent
    no-op, since replays are expected transport behavior. Returns a
    `DispatchOutcome`: the stamped, worker-ready `EventTrigger` on success,
    and the refusal class the sender is told (see `DispatchOutcome`).

    `verify_chain` may raise `KeySourceUnavailable` when its keys are
    configured but cannot be obtained; `dedupe_store` may raise anything when
    the store cannot be read or written. Either is recorded `not_evaluated`
    and classed `transient`. Neither leaves the dedupe key claimed (one edge
    is noted at gate 6), so a retry is evaluated afresh.
    """
    # Gate 1 — transport authenticity, before the body is parsed. The
    # sender's identity is unknown at this point, so the drop digests the
    # empty string rather than anything derived from unauthenticated bytes.
    if not adapter.verify_token(request):
        drops.append(
            make_drop_record(adapter.channel_type, "", "authenticity_failed", now.isoformat())
        )
        return DispatchOutcome(None)

    # Gate 2 — identity extraction; keys every later gate.
    try:
        identity = adapter.extract_identity(request)
    except Exception:
        drops.append(make_drop_record(adapter.channel_type, "", "malformed", now.isoformat()))
        return DispatchOutcome(None)

    # Who the sender is told anything about. A lookup only: no gate moves, no
    # record is written, and gate 5 still decides admission. The sender passed
    # gate 1 and its gate-2 identity is in the trust map, so a refusal before
    # the screen is classed for it; every other sender is told nothing, so a
    # stranger probing the ingress learns nothing about the trust map.
    #
    # That holds only when gate 1 authenticated the sender AS that identity
    # (`credential_per_sender`). Behind a credential every sender shares, the
    # identity is whatever the holder claims, and an answer that differed by
    # identity would tell the holder which identities the trust map holds. So
    # such an adapter's senders are told nothing on every path, and the lookup
    # is not made: `is True`, like `originates_envelope` below, so only an
    # adapter that says so is answered.
    mapped = (
        getattr(adapter, "credential_per_sender", False) is True
        and trust_map.resolve(adapter.channel_type, identity) is not None
    )

    def refuse(
        reason: DropReason,
        refusal: RefusalClass,
        *,
        detail: str | None = None,
        chain_verified: bool = False,
        signer_key_id: str | None = None,
    ) -> DispatchOutcome:
        drops.append(
            make_drop_record(
                adapter.channel_type,
                identity,
                reason,
                now.isoformat(),
                detail=detail,
                chain_verified=chain_verified,
                signer_key_id=signer_key_id,
            )
        )
        return DispatchOutcome(None, refusal if mapped else None)

    # Gate 3 — schema check.
    try:
        envelope = adapter.normalize(request)
    except Exception:
        return refuse("malformed", PERMANENT)

    # Gate 3 (receiver-owned field) — `sender_class` is the receiver's to set and
    # is absent on the wire (channels/SCHEMAS.md C4). Whatever arrived is discarded
    # here, so no later gate can read a class the sender asserted: the screen runs
    # before gate 8 writes the real one, and the signature does not cover this
    # field.
    if envelope.sender_class is not None:
        envelope = envelope.model_copy(update={"sender_class": None})

    # Gate 3 (forwardable) — an accepted envelope is handed onward to the worker
    # in wire form. One that cannot make that trip is malformed, and it has to be
    # refused HERE: past gate 6 its dedupe key is already claimed, so the failure
    # would lose the message, shadow every later copy of it, and leave no drop
    # record. `to_wire` is the same call the transport binding forwards with, and
    # it proves the result is within the size ceiling and parses back unchanged.
    try:
        envelope.to_wire()
    except Exception:
        return refuse("malformed", PERMANENT, detail="not_forwardable")

    # Gate 3 (sender-transport binding) — an adapter's `normalize` MUST produce
    # `sender.channel_identity` equal to the SAME request's gate-2
    # `extract_identity` result (channels/ADAPTERS.md §"InboundAdapter"). This
    # is the backstop for `EventTrigger.dedupe_key()`'s sender half — dedupe
    # (and any downstream attribution built on it) keys on `envelope.sender
    # .channel_identity`. When chain verification is ON, gate 3.5 additionally
    # binds this same field into the signed statement (`channels/SIGNING.md`),
    # so a divergence there is caught as a forged/invalid chain instead; THIS
    # check is what closes the gap when verification is OFF, not yet run for
    # this envelope, or the adapter itself diverges independently of anything
    # cryptographic. A divergence here is untrusted input, so the drop carries
    # no verification evidence — placed BEFORE gate 3.5 for exactly that reason.
    if envelope.sender.channel_identity != identity:
        return refuse("malformed", PERMANENT, detail="sender_identity_mismatch")

    # Gate 3 (audience) — an envelope names the one receiver it is addressed to
    # (channels/SIGNING.md S9). Zone ids are compared exactly, the way a
    # signature's zone is. Without this, an envelope a broker signed for another
    # receiver verifies here whenever this airlock enrols that broker's key and
    # serves a principal of the same name. Placed BEFORE gate 3.5 on purpose:
    # the signer addressed this envelope elsewhere and whoever delivered it here
    # is the party at fault, so the drop carries no verification evidence and
    # can never be counted against the signer. It is also before dedupe, so it
    # claims no key.
    if envelope.audience != zone:
        return refuse("audience_mismatch", PERMANENT)

    # Gate 3.5 — chain-signature verification (channels/SIGNING.md). Injected
    # like the screen and ships OFF (None): with no required-signers configured
    # the airlock skips it and unsigned peers pass, today's trust-by-transport
    # behavior (docs/friction-doctrine.md). When ON, a forged/unsigned/unknown-
    # signer chain drops and is quarantined here — before gate 5, dedupe, or any
    # screen budget, so a forged chain is the cheapest thing to reject
    # (the same reasoning that puts expiry ahead of the budget gates). The drop
    # reason is the verification reason verbatim, a closed DropReason vocabulary.
    # Evidence-of-check (for the campaign watchdog): a *successful* gate 3.5 verification
    # is what any later drop/verdict record in this call may cite as
    # `chain_verified`/`signer_key_id` — a failed or skipped verification
    # keeps every later record at its default (unverified), never asserting a
    # check that didn't happen.
    #
    # An adapter that builds the envelope itself (`originates_envelope`) has no
    # sending broker and so no chain to verify: its envelope is one seed hop the
    # receiver wrote. The gate is skipped for it and no `sig:pass` is recorded.
    # Which adapter an airlock runs is fixed in its image-baked manifest, so
    # nothing on the wire can select this path.
    #
    # Custody (channels/SIGNING.md S10): when the gate ran and passed, and every
    # signature was made by a key the receiver has recorded in agent-separated
    # custody, the evidence class of those records is carried to gate 8. It is
    # a record consulted in the receiver's own configuration, never a check on
    # the peer, and it stays None when the gate is off, skipped or failed.
    #
    # Keys configured but unavailable (the seam raises `KeySourceUnavailable`):
    # the airlock could not evaluate this envelope, so it is recorded
    # `not_evaluated` with `detail` `key_source` and classed transient. This is
    # ahead of gate 5, so an unmapped sender gets the same record and, being
    # unmapped, is told nothing. It is also ahead of dedupe, so nothing is
    # claimed and a retry once the keys are back is evaluated afresh.
    chain_verified = False
    signer_key_id: str | None = None
    custody_evidence: str | None = None
    if verify_chain is not None and getattr(adapter, "originates_envelope", False) is not True:
        try:
            result = verify_chain(envelope)
        except KeySourceUnavailable:
            return refuse("not_evaluated", TRANSIENT, detail=NOT_EVALUATED_KEY_SOURCE)
        if not result.ok:
            return refuse(result.reason, PERMANENT, detail=result.detail)
        chain_verified = True
        signer_key_id = result.signer_key_id
        if result.agent_separated_custody:
            custody_evidence = result.custody_evidence

    # Gate 4 — expiry, ahead of any budget-spending gate.
    if envelope.is_expired(now):
        return refuse(
            "expired", PERMANENT, chain_verified=chain_verified, signer_key_id=signer_key_id
        )

    # Gate 5 — trust-map resolution and principal match. An unmapped identity
    # is told nothing (`mapped` is False), whatever class is named here.
    resolution = trust_map.resolve(adapter.channel_type, identity)
    if resolution is None:
        return refuse(
            "unmapped", PERMANENT, chain_verified=chain_verified, signer_key_id=signer_key_id
        )
    if resolution.principal != envelope.principal:
        return refuse(
            "principal_mismatch",
            PERMANENT,
            chain_verified=chain_verified,
            signer_key_id=signer_key_id,
        )

    # Gate 6 — dedupe, after trust-map (so only mapped senders can write the
    # dedupe store) and before the screen (so replays cannot re-spend
    # screening budget). Marking seen before the screen means a refused
    # message's replays never re-spend screening budget either.
    #
    # A store that cannot be read or written leaves the message unevaluated:
    # recorded `not_evaluated` with `detail` `dedupe_store`, classed transient.
    # A failed read claims nothing. A failed write normally claims nothing
    # either; the one edge is a write that succeeded whose response was lost,
    # which leaves a claimed key behind a transient answer, so the retry
    # dedupes silently. The record exists so an operator can see that case;
    # this build does not try to undo the claim.
    key = envelope.dedupe_key()
    try:
        if key in dedupe_store:
            return DispatchOutcome(None)
        dedupe_store.add(key)
    except Exception:
        return refuse(
            "not_evaluated",
            TRANSIENT,
            detail=NOT_EVALUATED_DEDUPE_STORE,
            chain_verified=chain_verified,
            signer_key_id=signer_key_id,
        )

    # Gate 7 — the injection screen: injected, not owned. A null screen
    # (None) is pass-through; the gate's position is contract, its
    # strictness is consumer policy (docs/friction-doctrine.md). A screen may
    # return a bool or a ScreenVerdict; either way, an escaped exception must
    # not fail open (SCREENING.md's fail-closed backstop).
    if screen is not None:
        try:
            raw = screen(envelope)
        except Exception:
            raw = ScreenVerdict.refusing(SCREEN_ERROR)
        passed = bool(raw)
        reason = raw.reason if isinstance(raw, ScreenVerdict) else None
        if verdicts is not None:
            verdicts.append(
                make_screen_record(
                    adapter.channel_type,
                    identity,
                    envelope.event_id,
                    passed,
                    reason,
                    now.isoformat(),
                    chain_verified=chain_verified,
                    signer_key_id=signer_key_id,
                )
            )
        if not passed:
            # Told nothing, whoever the sender is: a screen refusal reads as an
            # acceptance (channels/SCREENING.md), so a compromised peer gets no
            # feedback on content.
            drops.append(
                make_drop_record(
                    adapter.channel_type,
                    identity,
                    "screen_refused",
                    now.isoformat(),
                    detail=reason,
                    chain_verified=chain_verified,
                    signer_key_id=signer_key_id,
                )
            )
            return DispatchOutcome(None)

    # Gate 8 — taint stamp; cannot fail. Appends the receiver's own
    # provenance entry and sets sender_class, overwriting any wire value.
    # `sig:pass` is recorded only when the signature gate actually ran and
    # passed — evidence of a check performed, never asserted for an unverified
    # chain (the same discipline as `sender.evidence`). The custody entry
    # (e.g. `custody:declared`) follows it under the same rule, and only when
    # every signing key is recorded in agent-separated custody: a chain signed
    # by a key recorded at posture 1 is verified and gets `sig:pass` alone.
    evidence = ["token:pass"]
    if chain_verified:
        evidence.append("sig:pass")
        if custody_evidence is not None:
            evidence.append(f"{CUSTODY_EVIDENCE_PREFIX}{custody_evidence}")
    return DispatchOutcome(
        stamp_inbound(
            envelope,
            resolution,
            zone=zone,
            source=f"channel:{adapter.channel_type}",
            evidence=evidence,
            ts=now.isoformat(),
        )
    )
