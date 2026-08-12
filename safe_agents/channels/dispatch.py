"""channels.dispatch — the in-memory, transport-free reference airlock dispatcher (sa#80).

**Reference-tier** per docs/contract-vs-reference.md (channels/ADAPTERS.md
§"Status"): this module exists so the gate-ordering clauses in
channels/ADAPTERS.md §"Gate ordering" are executable, and it passes the same
conformance suite (`test_adapters.py`) a third-party dispatcher would. No
transport binding lives here or is named here — see channels/ADAPTERS.md
§"Reference bindings" for where webhook/queue/peer-transit bindings land.
"""

from datetime import datetime
from typing import Any, Callable

from safe_agents.channels.adapters import InboundAdapter
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.screening import SCREEN_ERROR, ScreenVerdict, make_screen_record
from safe_agents.channels.signing import ChainVerifyResult
from safe_agents.channels.trust_map import ChannelTrustMap, make_drop_record, stamp_inbound


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
    no-op, since replays are expected transport behavior. Returns the
    stamped, worker-ready `EventTrigger` on success, else `None`.
    """
    # Gate 1 — transport authenticity, before the body is parsed. The
    # sender's identity is unknown at this point, so the drop digests the
    # empty string rather than anything derived from unauthenticated bytes.
    if not adapter.verify_token(request):
        drops.append(
            make_drop_record(adapter.channel_type, "", "authenticity_failed", now.isoformat())
        )
        return None

    # Gate 2 — identity extraction; keys every later gate.
    try:
        identity = adapter.extract_identity(request)
    except Exception:
        drops.append(make_drop_record(adapter.channel_type, "", "malformed", now.isoformat()))
        return None

    # Gate 3 — schema check.
    try:
        envelope = adapter.normalize(request)
    except Exception:
        drops.append(
            make_drop_record(adapter.channel_type, identity, "malformed", now.isoformat())
        )
        return None

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
        drops.append(
            make_drop_record(
                adapter.channel_type,
                identity,
                "malformed",
                now.isoformat(),
                detail="sender_identity_mismatch",
            )
        )
        return None

    # Gate 3.5 — chain-signature verification (channels/SIGNING.md). Injected
    # like the screen and ships OFF (None): with no required-signers configured
    # the airlock skips it and unsigned peers pass, today's trust-by-transport
    # behavior (docs/friction-doctrine.md). When ON, a forged/unsigned/unknown-
    # signer chain drops and is quarantined here — before spending any trust-map,
    # dedupe, or screen budget, so a forged chain is the cheapest thing to reject
    # (the same reasoning that puts expiry ahead of the budget gates). The drop
    # reason is the verification reason verbatim, a closed DropReason vocabulary.
    # Evidence-of-check (sa#161 Phase A1): a *successful* gate 3.5 verification
    # is what any later drop/verdict record in this call may cite as
    # `chain_verified`/`signer_key_id` — a failed or skipped verification
    # keeps every later record at its default (unverified), never asserting a
    # check that didn't happen.
    chain_verified = False
    signer_key_id: str | None = None
    if verify_chain is not None:
        result = verify_chain(envelope)
        if not result.ok:
            drops.append(
                make_drop_record(adapter.channel_type, identity, result.reason, now.isoformat())
            )
            return None
        chain_verified = True
        signer_key_id = result.signer_key_id

    # Gate 4 — expiry, ahead of any budget-spending gate.
    if envelope.is_expired(now):
        drops.append(
            make_drop_record(
                adapter.channel_type,
                identity,
                "expired",
                now.isoformat(),
                chain_verified=chain_verified,
                signer_key_id=signer_key_id,
            )
        )
        return None

    # Gate 5 — trust-map resolution and principal match.
    resolution = trust_map.resolve(adapter.channel_type, identity)
    if resolution is None:
        drops.append(
            make_drop_record(
                adapter.channel_type,
                identity,
                "unmapped",
                now.isoformat(),
                chain_verified=chain_verified,
                signer_key_id=signer_key_id,
            )
        )
        return None
    if resolution.principal != envelope.principal:
        drops.append(
            make_drop_record(
                adapter.channel_type,
                identity,
                "principal_mismatch",
                now.isoformat(),
                chain_verified=chain_verified,
                signer_key_id=signer_key_id,
            )
        )
        return None

    # Gate 6 — dedupe, after trust-map (so only mapped senders can write the
    # dedupe store) and before the screen (so replays cannot re-spend
    # screening budget). Marking seen before the screen means a refused
    # message's replays never re-spend screening budget either.
    key = envelope.dedupe_key()
    if key in dedupe_store:
        return None
    dedupe_store.add(key)

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
            return None

    # Gate 8 — taint stamp; cannot fail. Appends the receiver's own
    # provenance entry and sets sender_class, overwriting any wire value.
    # `sig:pass` is recorded only when the signature gate actually ran and
    # passed — evidence of a check performed, never asserted for an unverified
    # chain (the same discipline as `sender.evidence`).
    evidence = ["token:pass"]
    if verify_chain is not None:
        evidence.append("sig:pass")
    return stamp_inbound(
        envelope,
        resolution,
        zone=zone,
        source=f"channel:{adapter.channel_type}",
        evidence=evidence,
        ts=now.isoformat(),
    )
