"""
Tests for the campaign correlation engine (sa#161).

Covers:
  1. DEDUPE_CAPPED_REASONS (screen_refused) with a verified chain group under
     signed-chain by signer_key_id, across channel_types
  2. VECTOR_AUTH_REASONS without a verified chain group under transport-token
     (data-driven over the reason table)
  3. screen_refused with chain_verified=True but no signer_key_id falls back
     to transport-token (conservative)
  3b. Replay-amplification negative proof: expired/unmapped/principal_mismatch
      (VECTOR_AUTH_REASONS minus DEDUPE_CAPPED_REASONS) NEVER attribute to a
      signer even with a genuinely verified chain (data-driven) — these gates
      fire before dedupe, so a captured signed envelope is replayable
  3c. A mixed group (same signer: expired + screen_refused) splits into two
      separate campaigns — one capped at transport, one at signed-chain
  4. FORGERY_REASONS always attribute to transport, never a signer — incl.
     the chain_verified+forgery-reason conservative fallback (data-driven)
  5. UNATTRIBUTABLE_REASONS group under unattributable, throttle_eligible=False
     (data-driven)
  6. Unknown reason strings default to unattributable
  7. Window boundary: ts == now included, ts == now - window_seconds excluded
  8. Threshold boundary: n-1 events → no campaign, n events → a campaign
  9. campaign_id is deterministic and matches the stated formula; report
     ordering is stable regardless of input order
 10. Naive datetimes are refused on ObservedEvent.ts, FloodEvent.ts, and
     analyze()'s now
 11. signer_key_id may only be set alongside chain_verified=True
 12. suggested_remediation is validated against REMEDIATION_VOCABULARY
 13. CampaignThresholds requires positive min_attempts/window_seconds
 14. FloodEvents produce principal-flood campaigns
 15. corpus_refs collects only non-None source_refs
 16. Purity: no boto3/botocore imports, no clock reads, in campaign.py's own
     source text
"""
from __future__ import annotations

import ast
import hashlib
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from safe_agents.watcher import campaign as campaign_module
from safe_agents.watcher.campaign import (
    CampaignReport,
    CampaignThresholds,
    FloodEvent,
    ObservedEvent,
    analyze,
)

NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)
DEFAULT_DIGEST = "sha256:" + "a" * 64
THRESHOLDS = CampaignThresholds(min_attempts=3, window_seconds=3600)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(
    *,
    channel_type: str = "webhook",
    identity_digest: str = DEFAULT_DIGEST,
    reason: str,
    ts: datetime = NOW,
    chain_verified: bool = False,
    signer_key_id: str | None = None,
    source_ref: str | None = None,
) -> ObservedEvent:
    return ObservedEvent(
        channel_type=channel_type,
        identity_digest=identity_digest,
        reason=reason,
        ts=ts,
        chain_verified=chain_verified,
        signer_key_id=signer_key_id,
        source_ref=source_ref,
    )


def _flood(
    *,
    agent_id: str = "agent-1",
    op: str = "peer.publish",
    cap: int = 10,
    ts: datetime = NOW,
    source_ref: str | None = None,
) -> FloodEvent:
    return FloodEvent(agent_id=agent_id, op=op, cap=cap, ts=ts, source_ref=source_ref)


# ---------------------------------------------------------------------------
# Attribution table
# ---------------------------------------------------------------------------

def test_signed_chain_groups_by_signer_key_id_across_channel_types():
    """`screen_refused` is the only dedupe-capped reason (DEDUPE_CAPPED_REASONS):
    an exact replay dedupes silently at gate 6, so this is the one reason
    signer attribution is sound for. See test_pre_dedupe_reasons_never_
    attribute_to_signer_even_when_verified for the reasons it is NOT sound for."""
    events = [
        _event(
            channel_type="webhook", identity_digest="sha256:" + "1" * 64,
            reason="screen_refused", chain_verified=True, signer_key_id="key-a",
        ),
        _event(
            channel_type="email", identity_digest="sha256:" + "2" * 64,
            reason="screen_refused", chain_verified=True, signer_key_id="key-a",
        ),
        _event(
            channel_type="sms", identity_digest="sha256:" + "3" * 64,
            reason="screen_refused", chain_verified=True, signer_key_id="key-a",
        ),
    ]
    reports = analyze(events, [], THRESHOLDS, NOW)
    assert len(reports) == 1
    report = reports[0]
    assert report.kind == "vector"
    assert report.basis == "signed-chain"
    assert report.attribution_key == "key-a"
    assert report.total == 3
    assert report.throttle_eligible is True
    assert report.counts_by_reason == {"screen_refused": 3}
    assert report.suggested_remediation == ["remove_trust_map_entry", "unenroll_verify_key"]


@pytest.mark.parametrize("reason", sorted(campaign_module.VECTOR_AUTH_REASONS))
def test_vector_auth_reason_unverified_groups_under_transport_token(reason):
    events = [_event(reason=reason) for _ in range(3)]
    reports = analyze(events, [], THRESHOLDS, NOW)
    assert len(reports) == 1
    report = reports[0]
    assert report.basis == "transport-token"
    assert report.attribution_key == f"webhook#{DEFAULT_DIGEST}"
    assert report.throttle_eligible is True
    assert report.suggested_remediation == ["remove_trust_map_entry", "rotate_channel_token"]


def test_vector_auth_chain_verified_without_signer_key_id_falls_back_to_transport():
    events = [
        _event(reason="screen_refused", chain_verified=True, signer_key_id=None)
        for _ in range(3)
    ]
    reports = analyze(events, [], THRESHOLDS, NOW)
    assert len(reports) == 1
    assert reports[0].basis == "transport-token"


@pytest.mark.parametrize(
    "reason", sorted(campaign_module.VECTOR_AUTH_REASONS - campaign_module.DEDUPE_CAPPED_REASONS)
)
def test_pre_dedupe_reasons_never_attribute_to_signer_even_when_verified(reason):
    """The replay-amplification negative proof (fix for the adversarial-review
    HIGH finding): expired/unmapped/principal_mismatch fire BEFORE gate 6
    dedupe (safe_agents/channels/dispatch.py), so a captured, genuinely
    victim-signed envelope can be replayed N times to accrue N DropRecords
    all honestly chain_verified=True, signer_key_id=<victim> — signer
    attribution would let the replay count as an attack authored by the
    victim. Transport attribution stays the ceiling for these reasons
    regardless of verification strength; the signer key must never appear in
    any attribution_key produced from them."""
    events = [
        _event(reason=reason, chain_verified=True, signer_key_id="key-victim")
        for _ in range(3)
    ]
    reports = analyze(events, [], THRESHOLDS, NOW)
    assert len(reports) == 1
    report = reports[0]
    assert report.basis == "transport-token"
    assert report.attribution_key == f"webhook#{DEFAULT_DIGEST}"
    assert "key-victim" not in report.attribution_key


def test_mixed_dedupe_capped_and_pre_dedupe_reasons_split_into_separate_campaigns():
    """Same signer, same channel: N pre-dedupe-reason (expired) events and M
    dedupe-capped (screen_refused) events must NOT merge into one signed-chain
    campaign — the pre-dedupe events stay capped at transport-token even
    though every event in this test shares a signer_key_id."""
    events = [
        _event(reason="expired", chain_verified=True, signer_key_id="key-a")
        for _ in range(3)
    ] + [
        _event(reason="screen_refused", chain_verified=True, signer_key_id="key-a")
        for _ in range(4)
    ]
    reports = analyze(events, [], THRESHOLDS, NOW)
    assert len(reports) == 2

    by_basis = {r.basis: r for r in reports}
    assert set(by_basis) == {"transport-token", "signed-chain"}

    expired_report = by_basis["transport-token"]
    assert expired_report.total == 3
    assert expired_report.attribution_key == f"webhook#{DEFAULT_DIGEST}"
    assert expired_report.counts_by_reason == {"expired": 3}

    refused_report = by_basis["signed-chain"]
    assert refused_report.total == 4
    assert refused_report.attribution_key == "key-a"
    assert refused_report.counts_by_reason == {"screen_refused": 4}


@pytest.mark.parametrize("reason", sorted(campaign_module.FORGERY_REASONS))
@pytest.mark.parametrize(
    "chain_verified,signer_key_id",
    [(False, None), (True, "key-victim")],
    ids=["unverified", "verified-conservative-fallback"],
)
def test_forgery_reason_never_attributes_to_signer(reason, chain_verified, signer_key_id):
    events = [
        _event(reason=reason, chain_verified=chain_verified, signer_key_id=signer_key_id)
        for _ in range(3)
    ]
    reports = analyze(events, [], THRESHOLDS, NOW)
    assert len(reports) == 1
    report = reports[0]
    assert report.basis == "transport-token"
    assert report.attribution_key == f"webhook#{DEFAULT_DIGEST}"
    assert "key-victim" not in report.attribution_key


@pytest.mark.parametrize("reason", sorted(campaign_module.UNATTRIBUTABLE_REASONS))
def test_unattributable_reason_not_throttle_eligible(reason):
    events = [_event(reason=reason) for _ in range(3)]
    reports = analyze(events, [], THRESHOLDS, NOW)
    assert len(reports) == 1
    report = reports[0]
    assert report.basis == "unattributable"
    assert report.throttle_eligible is False
    assert report.suggested_remediation == ["review_screen_config"]


def test_unknown_reason_defaults_to_unattributable():
    events = [_event(reason="some_future_reason_not_in_any_table") for _ in range(3)]
    reports = analyze(events, [], THRESHOLDS, NOW)
    assert len(reports) == 1
    assert reports[0].basis == "unattributable"
    assert reports[0].throttle_eligible is False


# ---------------------------------------------------------------------------
# Window / threshold boundaries
# ---------------------------------------------------------------------------

def test_window_boundary_inclusive_upper_exclusive_lower():
    window_seconds = 3600
    thresholds = CampaignThresholds(min_attempts=1, window_seconds=window_seconds)

    at_now = _event(reason="expired", ts=NOW)
    at_lower_bound = _event(reason="expired", ts=NOW - timedelta(seconds=window_seconds))
    just_inside = _event(
        reason="expired",
        ts=NOW - timedelta(seconds=window_seconds) + timedelta(microseconds=1),
    )

    assert len(analyze([at_now], [], thresholds, NOW)) == 1
    assert analyze([at_lower_bound], [], thresholds, NOW) == []
    assert len(analyze([just_inside], [], thresholds, NOW)) == 1


def test_threshold_boundary():
    thresholds = CampaignThresholds(min_attempts=3, window_seconds=3600)

    two_events = [_event(reason="expired") for _ in range(2)]
    assert analyze(two_events, [], thresholds, NOW) == []

    three_events = [_event(reason="expired") for _ in range(3)]
    reports = analyze(three_events, [], thresholds, NOW)
    assert len(reports) == 1
    assert reports[0].total == 3


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_campaign_id_matches_stated_formula():
    thresholds = CampaignThresholds(min_attempts=1, window_seconds=60)
    reports = analyze([_event(reason="expired")], [], thresholds, NOW)

    window_start = NOW - timedelta(seconds=60)
    basis = "transport-token"
    key = f"webhook#{DEFAULT_DIGEST}"
    expected = hashlib.sha256(f"{basis}|{key}|{window_start.isoformat()}".encode()).hexdigest()[:16]

    assert reports[0].campaign_id == f"campaign-{expected}"


def test_ordering_and_campaign_id_stable_regardless_of_input_order():
    events = [
        _event(channel_type="webhook", identity_digest="sha256:" + "b" * 64, reason="malformed"),
        _event(channel_type="webhook", identity_digest="sha256:" + "b" * 64, reason="malformed"),
        _event(channel_type="webhook", identity_digest="sha256:" + "b" * 64, reason="malformed"),
        _event(channel_type="email", identity_digest="sha256:" + "c" * 64, reason="expired"),
        _event(channel_type="email", identity_digest="sha256:" + "c" * 64, reason="expired"),
        _event(channel_type="email", identity_digest="sha256:" + "c" * 64, reason="expired"),
    ]
    thresholds = CampaignThresholds(min_attempts=3, window_seconds=3600)

    forward = analyze(events, [], thresholds, NOW)
    reversed_order = analyze(list(reversed(events)), [], thresholds, NOW)

    assert forward == reversed_order
    assert [r.attribution_key for r in forward] == sorted(r.attribution_key for r in forward)


# ---------------------------------------------------------------------------
# Naive-datetime refusal
# ---------------------------------------------------------------------------

def test_naive_datetime_refused_on_observed_event_ts():
    with pytest.raises(ValidationError):
        _event(reason="expired", ts=datetime(2026, 7, 18, 12, 0, 0))


def test_naive_datetime_refused_on_flood_event_ts():
    with pytest.raises(ValidationError):
        _flood(ts=datetime(2026, 7, 18, 12, 0, 0))


def test_naive_datetime_refused_on_analyze_now():
    with pytest.raises(ValueError):
        analyze([], [], THRESHOLDS, datetime(2026, 7, 18, 12, 0, 0))


# ---------------------------------------------------------------------------
# Schema validators
# ---------------------------------------------------------------------------

def test_signer_key_id_requires_chain_verified():
    with pytest.raises(ValidationError):
        _event(reason="expired", chain_verified=False, signer_key_id="key-a")


def test_remediation_validator_rejects_out_of_vocabulary():
    with pytest.raises(ValidationError):
        CampaignReport(
            campaign_id="campaign-0000000000000000",
            kind="vector",
            basis="unattributable",
            attribution_key=f"webhook#{DEFAULT_DIGEST}",
            throttle_eligible=False,
            window_start=NOW - timedelta(seconds=60),
            window_end=NOW,
            first_ts=NOW,
            last_ts=NOW,
            total=1,
            counts_by_reason={"malformed": 1},
            corpus_refs=[],
            suggested_remediation=["shed_pending_intents"],
        )


@pytest.mark.parametrize(
    "min_attempts,window_seconds",
    [(0, 60), (-1, 60), (1, 0), (1, -60)],
)
def test_thresholds_require_positive_values(min_attempts, window_seconds):
    with pytest.raises(ValidationError):
        CampaignThresholds(min_attempts=min_attempts, window_seconds=window_seconds)


# ---------------------------------------------------------------------------
# Flood events
# ---------------------------------------------------------------------------

def test_flood_events_produce_principal_flood_campaigns():
    thresholds = CampaignThresholds(min_attempts=2, window_seconds=3600)
    floods = [_flood(agent_id="agent-1", op="peer.publish") for _ in range(2)]
    reports = analyze([], floods, thresholds, NOW)
    assert len(reports) == 1
    report = reports[0]
    assert report.kind == "principal-flood"
    assert report.basis == "principal"
    assert report.attribution_key == "agent-1#peer.publish"
    assert report.throttle_eligible is False
    assert report.suggested_remediation == ["review_pending_approvals"]
    assert report.counts_by_reason == {"approval_queue_flood": 2}


def test_vector_and_flood_campaigns_coexist():
    thresholds = CampaignThresholds(min_attempts=2, window_seconds=3600)
    events = [_event(reason="expired") for _ in range(2)]
    floods = [_flood() for _ in range(2)]
    reports = analyze(events, floods, thresholds, NOW)
    kinds = {r.kind for r in reports}
    assert kinds == {"vector", "principal-flood"}


# ---------------------------------------------------------------------------
# corpus_refs
# ---------------------------------------------------------------------------

def test_corpus_refs_collects_only_non_none():
    events = [
        _event(reason="expired", source_ref="s3://bucket/drop-1.json"),
        _event(reason="expired", source_ref=None),
        _event(reason="expired", source_ref="s3://bucket/drop-3.json"),
    ]
    thresholds = CampaignThresholds(min_attempts=3, window_seconds=3600)
    reports = analyze(events, [], thresholds, NOW)
    assert reports[0].corpus_refs == ["s3://bucket/drop-1.json", "s3://bucket/drop-3.json"]


# ---------------------------------------------------------------------------
# Purity
# ---------------------------------------------------------------------------

def test_purity_no_aws_no_clock_reads():
    """AST-based (not substring) so prose mentioning 'boto3' in a docstring
    doesn't false-positive — mirrors the no-naive-datetime conformance guard
    (safe_agents/broker/tests/test_no_naive_datetime_conformance.py)."""
    source = Path(inspect.getfile(campaign_module)).read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module.split(".")[0])
    assert "boto3" not in imported_modules
    assert "botocore" not in imported_modules

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"now", "utcnow", "today"}:
                receiver = node.func.value
                receiver_name = (
                    receiver.id if isinstance(receiver, ast.Name) else getattr(receiver, "attr", None)
                )
                assert receiver_name not in {"datetime", "date", "Date"}, (
                    f"clock read found in campaign.py: {ast.dump(node)}"
                )
