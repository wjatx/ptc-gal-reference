"""Campaign correlation engine — sa#161 input-poisoning campaign watchdog.

An off-path watchdog correlates poisoning attempts (airlock drop/screen
records + broker `approval_queue_flood` signals) into attributed campaigns.
It NEVER gates — it produces human-facing reports only; nothing in this
module sheds, denies, or drops load (see `docs/friction-doctrine.md`
§"Availability / forced-abstention"). Contract: `channels/WATCHDOG.md`.

The security-critical rule is reflected-DoS avoidance: attribution happens
only at the authentication strength the airlock actually RECORDED, never
from spoofable content. A "chain forgery" event — evidence AGAINST a claimed
signer — is attributed to the raw transport identity, never to the signer it
falsely claimed to be. Attributing it to the claimed signer would let an
attacker forge chains bearing a victim's key_id and get the watchdog to
recommend throttling the victim: exactly the reflected-DoS this module
exists to avoid.

Pure by construction: `analyze()` takes `now` as an argument and never reads
a clock, a store, or the network. Imports are stdlib + pydantic only (no
boto3/botocore) — see `test_purity_no_aws_no_clock` in the test module,
which also enforces this by inspecting this file's own source text.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

AttributionBasis = Literal["signed-chain", "transport-token", "unattributable", "principal"]

# ---------------------------------------------------------------------------
# Attribution table (implement EXACTLY — this is the reflected-DoS table)
# ---------------------------------------------------------------------------

# These reasons mean the event passed gate 1 (constant-time token match), so
# the transport identity IS authenticated. See `_classify_observed_event`.
VECTOR_AUTH_REASONS = frozenset({
    "screen_refused",
    "expired",
    "unmapped",
    "principal_mismatch",
})

# Signer (signed-chain) attribution is only sound for reasons that are BOTH
# signature-bound AND dedupe-capped — replay amplification otherwise turns a
# single captured envelope into an arbitrarily large attributed count against
# an innocent signer.
#
# Gate ordering (`safe_agents/channels/dispatch.py`): gate 3.5 verifies the
# chain signature, gate 4 checks expiry, gate 5 resolves the trust map
# (`unmapped`/`principal_mismatch`), gate 6 dedupes, and gate 7 is the screen
# (`screen_refused`). Only `screen_refused` fires AFTER dedupe — `expired`,
# `unmapped`, and `principal_mismatch` all fire BEFORE it. That means an
# attacker who captures ONE genuine victim-signed envelope can replay the
# exact bytes N times: each replay re-verifies (genuine signature →
# `chain_verified=True`, `signer_key_id=<victim>`) and then drops at gate 4
# or 5, every time — dedupe never runs, so nothing caps the replay. N
# DropRecords accrue, all honestly `chain_verified`, all attributing to a
# signer who sent exactly one message. `screen_refused` has no such hole: an
# exact byte-for-byte replay dedupes silently at gate 6 (no DropRecord at
# all), and any change to the bytes needed to dodge dedupe — including a
# fresh `event_id`, which rides the signed statement (`channels/SIGNING.md`)
# — breaks the signature, landing the replay in `FORGERY_REASONS` instead,
# attributed to transport only.
#
# `expired`/`unmapped`/`principal_mismatch` still resolve to `transport-token`
# even with a genuinely verified chain (below) — that attribution stays sound:
# replaying requires possessing the captured transport token, and
# `rotate_channel_token` is the correct remedy for a captured token, whether
# or not the replayed payload also carries a real signature.
DEDUPE_CAPPED_REASONS = frozenset({"screen_refused"})

# Evidence AGAINST a claimed signer. Always attributed to the raw transport
# identity, NEVER to any signer identity — see the module docstring.
FORGERY_REASONS = frozenset({
    "chain_signature_missing",
    "chain_signature_invalid",
    "chain_signer_unknown",
})

# The identity claim itself was never authenticated. Any reason string this
# table doesn't otherwise recognize also lands here — a conservative default.
UNATTRIBUTABLE_REASONS = frozenset({
    "authenticity_failed",
    "malformed",
})

# Bases eligible for a throttle recommendation. "unattributable" (no
# authenticated identity to throttle) and "principal" (the flood signal
# names no sender) are deliberately excluded.
_THROTTLE_ELIGIBLE_BASES = frozenset({"signed-chain", "transport-token"})

# Deliberately contains NO shed/deny/drop verb (the never-shed invariant):
# the watchdog recommends, a human acts, and nothing here sheds pending load.
REMEDIATION_VOCABULARY = frozenset({
    "remove_trust_map_entry",
    "rotate_channel_token",
    "unenroll_verify_key",
    "review_screen_config",
    "review_pending_approvals",
})

_REMEDIATION_BY_BASIS: dict[AttributionBasis, list[str]] = {
    "signed-chain": ["remove_trust_map_entry", "unenroll_verify_key"],
    "transport-token": ["remove_trust_map_entry", "rotate_channel_token"],
    "unattributable": ["review_screen_config"],
    "principal": ["review_pending_approvals"],
}

# The single counts_by_reason key used for principal-flood campaigns: a
# FloodEvent carries no `reason` of its own (it IS the approval_queue_flood
# signal), so this names the signal itself.
_FLOOD_REASON = "approval_queue_flood"


def _require_tz_aware(v: datetime, field_name: str) -> datetime:
    """Reject a naive datetime; the AST no-naive-datetime guard covers
    construction sites, this covers values arriving from callers."""
    if v.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware: {v!r}")
    return v


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class ObservedEvent(BaseModel):
    """One airlock drop/screen-refusal record, mapped by the runner.

    `identity_digest` is a `sha256:<64-hex>` digest of the transport
    identity, never the raw value — the same discipline as
    `channels.trust_map.DropRecord.identity_digest`. `chain_verified` /
    `signer_key_id` are evidence-of-check: they let `analyze` attribute at
    the authentication strength the airlock actually verified, never higher.
    """

    model_config = ConfigDict(extra="forbid")

    channel_type: str
    identity_digest: str
    reason: str
    detail: str | None = None
    ts: datetime
    chain_verified: bool = False
    signer_key_id: str | None = None
    source_ref: str | None = None

    @field_validator("ts")
    @classmethod
    def _ts_tz_aware(cls, v: datetime) -> datetime:
        return _require_tz_aware(v, "ObservedEvent.ts")

    @model_validator(mode="after")
    def _signer_requires_verified_chain(self) -> "ObservedEvent":
        if self.signer_key_id is not None and not self.chain_verified:
            raise ValueError("signer_key_id may only be set when chain_verified is True")
        return self


class FloodEvent(BaseModel):
    """One `approval_queue_flood` broker signal."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str
    op: str
    cap: int
    ts: datetime
    source_ref: str | None = None

    @field_validator("ts")
    @classmethod
    def _ts_tz_aware(cls, v: datetime) -> datetime:
        return _require_tz_aware(v, "FloodEvent.ts")


class CampaignThresholds(BaseModel):
    """Correlation thresholds. REQUIRED fields, no defaults: the base ships
    no campaign policy — every bound is consumer-set (friction doctrine)."""

    model_config = ConfigDict(extra="forbid")

    min_attempts: int = Field(gt=0)
    window_seconds: int = Field(gt=0)


class CampaignReport(BaseModel):
    """One attributed campaign — a human-facing report, never a gate."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    kind: Literal["vector", "principal-flood"]
    basis: AttributionBasis
    attribution_key: str
    throttle_eligible: bool
    window_start: datetime
    window_end: datetime
    first_ts: datetime
    last_ts: datetime
    total: int
    counts_by_reason: dict[str, int]
    corpus_refs: list[str]
    suggested_remediation: list[str]

    @field_validator("suggested_remediation")
    @classmethod
    def _remediation_in_vocabulary(cls, v: list[str]) -> list[str]:
        unknown = [entry for entry in v if entry not in REMEDIATION_VOCABULARY]
        if unknown:
            raise ValueError(
                f"suggested_remediation contains entries outside REMEDIATION_VOCABULARY: {unknown!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


def _classify_observed_event(event: ObservedEvent) -> tuple[AttributionBasis, str]:
    """Return (basis, attribution_key) for one ObservedEvent per the
    reflected-DoS attribution table (module docstring)."""
    if event.reason in FORGERY_REASONS:
        # Evidence AGAINST a claimed signer — attribute to raw transport
        # ALWAYS, regardless of chain_verified. A correct airlock never sets
        # chain_verified=True alongside a forgery reason (the model
        # validator only forbids the inverse), but this branch stays
        # conservative even if one somehow did: throttling the claimed
        # signer is exactly the reflected-DoS an attacker wants.
        return "transport-token", f"{event.channel_type}#{event.identity_digest}"

    if event.reason in VECTOR_AUTH_REASONS:
        if (
            event.reason in DEDUPE_CAPPED_REASONS
            and event.chain_verified
            and event.signer_key_id is not None
        ):
            return "signed-chain", event.signer_key_id
        # Either unverified, or a verified chain on a reason that is NOT
        # dedupe-capped (`expired`/`unmapped`/`principal_mismatch`) — replay
        # amplification makes signer attribution unsound for those even with
        # a genuine signature (see DEDUPE_CAPPED_REASONS above). Transport
        # attribution stays sound either way.
        return "transport-token", f"{event.channel_type}#{event.identity_digest}"

    # UNATTRIBUTABLE_REASONS, or any reason string this table doesn't
    # recognize: the identity claim itself was never authenticated.
    # Conservative default.
    return "unattributable", f"{event.channel_type}#{event.identity_digest}"


def _compute_campaign_id(basis: AttributionBasis, attribution_key: str, window_start: datetime) -> str:
    digest = hashlib.sha256(
        f"{basis}|{attribution_key}|{window_start.isoformat()}".encode()
    ).hexdigest()
    return f"campaign-{digest[:16]}"


class _Group:
    """Mutable accumulator for one (kind, basis, attribution_key) group."""

    __slots__ = ("timestamps", "counts_by_reason", "corpus_refs")

    def __init__(self) -> None:
        self.timestamps: list[datetime] = []
        self.counts_by_reason: dict[str, int] = {}
        self.corpus_refs: list[str] = []

    def add(self, ts: datetime, reason: str, source_ref: str | None) -> None:
        self.timestamps.append(ts)
        self.counts_by_reason[reason] = self.counts_by_reason.get(reason, 0) + 1
        if source_ref is not None:
            self.corpus_refs.append(source_ref)


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


def analyze(
    events: Sequence[ObservedEvent],
    floods: Sequence[FloodEvent],
    thresholds: CampaignThresholds,
    now: datetime,
) -> list[CampaignReport]:
    """Correlate drop/screen/flood signals into attributed campaigns.

    Pure: reads no clock, store, or network — `now` is supplied by the
    caller and must be timezone-aware (a naive value is refused, matching
    the AST no-naive-datetime guard's floor for the rest of the base).

    Window: an item is included iff `window_start < ts <= now`, where
    `window_start = now - thresholds.window_seconds`. A group becomes a
    `CampaignReport` iff its in-window count is `>= thresholds.min_attempts`.

    Grouping key is `(kind, basis, attribution_key)` per the reflected-DoS
    attribution table (module docstring / `_classify_observed_event`) for
    ObservedEvents, and `("principal-flood", "principal", f"{agent_id}#{op}")`
    for FloodEvents. Output is sorted by `(kind, basis, attribution_key)` for
    determinism.
    """
    if now.tzinfo is None:
        raise ValueError(f"analyze() now must be timezone-aware: {now!r}")

    window_start = now - timedelta(seconds=thresholds.window_seconds)
    window_end = now

    def in_window(ts: datetime) -> bool:
        return window_start < ts <= now

    groups: dict[tuple[str, AttributionBasis, str], _Group] = {}

    for event in events:
        if not in_window(event.ts):
            continue
        basis, key = _classify_observed_event(event)
        group = groups.setdefault(("vector", basis, key), _Group())
        group.add(event.ts, event.reason, event.source_ref)

    for flood in floods:
        if not in_window(flood.ts):
            continue
        key = f"{flood.agent_id}#{flood.op}"
        group = groups.setdefault(("principal-flood", "principal", key), _Group())
        group.add(flood.ts, _FLOOD_REASON, flood.source_ref)

    reports: list[CampaignReport] = []
    for (kind, basis, attribution_key), group in groups.items():
        total = len(group.timestamps)
        if total < thresholds.min_attempts:
            continue
        reports.append(
            CampaignReport(
                campaign_id=_compute_campaign_id(basis, attribution_key, window_start),
                kind=kind,  # type: ignore[arg-type]
                basis=basis,
                attribution_key=attribution_key,
                throttle_eligible=basis in _THROTTLE_ELIGIBLE_BASES,
                window_start=window_start,
                window_end=window_end,
                first_ts=min(group.timestamps),
                last_ts=max(group.timestamps),
                total=total,
                counts_by_reason=group.counts_by_reason,
                corpus_refs=group.corpus_refs,
                suggested_remediation=_REMEDIATION_BY_BASIS[basis],
            )
        )

    reports.sort(key=lambda r: (r.kind, r.basis, r.attribution_key))
    return reports
