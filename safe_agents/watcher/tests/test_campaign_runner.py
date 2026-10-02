"""
Tests for the campaign watchdog reference runner
(safe_agents/watcher/campaign_runner.py). Mirrors test_liveness.py's style:
fake injected readers, no moto, no network, no live AWS.

Covers:
  1. day_prefixes: single-day window, a window spanning a UTC midnight
     boundary yields both day prefixes, naive datetimes refused
  2. parse_drop_record: field mapping incl. source_ref=key; legacy records
     missing chain_verified/signer_key_id map to the False/None defaults
  3. sweep_drops: a malformed object is counted and the sweep continues over
     the remaining keys; a list_keys failure propagates (not swallowed here)
  4. parse_flood_log_line: a well-formed approval_queue_flood line parses; a
     non-flood line and malformed JSON both filter to None
  5. fetch_flood_events: CloudWatch event timestamp (epoch ms) drives
     FloodEvent.ts
  6. execute() end-to-end: a fake run producing a campaign invokes
     emit_content_alarm/notify_fn once per campaign, prints the full
     CampaignReport JSON, writes --json-out, and never lists a verdicts-
     prefixed key (channels/verdicts/ is deliberately never read — see the
     module docstring / channels/dispatch.py gate 7)
  7. execute() zero campaigns: no content alarm, clean return
  8. execute() reader exception: routes to emit_meta_alarm (SystemExit(1),
     structured stderr JSON per safe_agents/reliability/META-ALARM-STANDARD.md)
  9. Every `DropReason` the airlock can write sits in exactly one of the
     engine's attribution sets; an envelope signed for another receiver and
     replayed here is attributed to the transport, never to its signer
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from safe_agents.channels.dispatch import dispatch
from safe_agents.channels.signing import make_gate
from safe_agents.channels.tests import test_signing as signing_fixtures
from safe_agents.channels.trust_map import DropReason, digest_identity, make_drop_record
from safe_agents.watcher import campaign as campaign_module
from safe_agents.watcher.campaign import CampaignThresholds, analyze
from safe_agents.watcher.campaign_runner import (
    day_prefixes,
    execute,
    fetch_flood_events,
    parse_drop_record,
    parse_flood_log_line,
    sweep_drops,
)

UTC = timezone.utc
DIGEST = "sha256:" + "a" * 64


# ---------------------------------------------------------------------------
# 1. day_prefixes
# ---------------------------------------------------------------------------


def test_day_prefixes_single_day():
    window_start = datetime(2026, 7, 18, 10, 0, 0, tzinfo=UTC)
    now = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)
    assert day_prefixes(window_start, now, base_prefix="channels/drops/") == [
        "channels/drops/2026/07/18/",
    ]


def test_day_prefixes_spans_utc_midnight_boundary():
    """A window that crosses UTC midnight must yield BOTH day prefixes."""
    window_start = datetime(2026, 7, 17, 23, 0, 0, tzinfo=UTC)
    now = datetime(2026, 7, 18, 1, 0, 0, tzinfo=UTC)
    assert day_prefixes(window_start, now, base_prefix="channels/drops/") == [
        "channels/drops/2026/07/17/",
        "channels/drops/2026/07/18/",
    ]


def test_day_prefixes_requires_tz_aware():
    naive = datetime(2026, 7, 18, 10, 0, 0)
    aware = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)
    with pytest.raises(ValueError):
        day_prefixes(naive, aware, base_prefix="channels/drops/")
    with pytest.raises(ValueError):
        day_prefixes(aware, naive, base_prefix="channels/drops/")


# ---------------------------------------------------------------------------
# 2. parse_drop_record
# ---------------------------------------------------------------------------


def test_parse_drop_record_maps_fields():
    record = make_drop_record(
        "webhook", "raw-identity", "screen_refused", "2026-07-18T12:00:00+00:00",
        detail="bad_content", chain_verified=True, signer_key_id="key-a",
    )
    event = parse_drop_record("channels/drops/2026/07/18/key1.json", record.model_dump_json().encode())
    assert event.channel_type == "webhook"
    assert event.identity_digest == record.identity_digest
    assert event.reason == "screen_refused"
    assert event.detail == "bad_content"
    assert event.chain_verified is True
    assert event.signer_key_id == "key-a"
    assert event.source_ref == "channels/drops/2026/07/18/key1.json"
    assert event.ts == datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)


def test_parse_drop_record_legacy_defaults_when_fields_absent():
    """A DropRecord JSON body written before Phase A1 (no chain_verified/
    signer_key_id keys at all) must map to the False/None defaults, not raise."""
    legacy_json = json.dumps({
        "channel_type": "webhook",
        "identity_digest": DIGEST,
        "reason": "unmapped",
        "ts": "2026-07-18T12:00:00+00:00",
    }).encode()
    event = parse_drop_record("k1", legacy_json)
    assert event.chain_verified is False
    assert event.signer_key_id is None


# ---------------------------------------------------------------------------
# 3. sweep_drops
# ---------------------------------------------------------------------------


def test_sweep_drops_malformed_object_counted_sweep_continues():
    valid = make_drop_record(
        "webhook", "identity", "unmapped", "2026-07-18T12:00:00+00:00",
    ).model_dump_json().encode()
    bodies = {
        "channels/drops/2026/07/18/good.json": valid,
        "channels/drops/2026/07/18/bad.json": b"not json at all",
    }

    def list_keys(prefix: str) -> list[str]:
        return sorted(bodies)

    def get_object(key: str) -> bytes:
        return bodies[key]

    events, malformed = sweep_drops(list_keys, get_object, ["channels/drops/2026/07/18/"])
    assert [e.source_ref for e in events] == ["channels/drops/2026/07/18/good.json"]
    assert malformed == ["channels/drops/2026/07/18/bad.json"]


def test_sweep_drops_list_keys_exception_propagates():
    """A list_keys failure is NOT swallowed by sweep_drops — the caller
    (execute()) is responsible for routing it to the meta-alarm."""
    def list_keys(prefix: str):
        raise RuntimeError("bucket unreachable")

    with pytest.raises(RuntimeError, match="bucket unreachable"):
        sweep_drops(list_keys, lambda key: b"{}", ["channels/drops/2026/07/18/"])


# ---------------------------------------------------------------------------
# 4. parse_flood_log_line
# ---------------------------------------------------------------------------


def test_parse_flood_log_line_valid():
    ts = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)
    message = json.dumps({
        "event": "approval_queue_flood", "agentId": "agent-1", "op": "ledger.append", "cap": 10,
    })
    flood = parse_flood_log_line(message, ts)
    assert flood is not None
    assert flood.agent_id == "agent-1"
    assert flood.op == "ledger.append"
    assert flood.cap == 10
    assert flood.ts == ts


def test_parse_flood_log_line_filters_non_flood_line():
    ts = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)
    message = json.dumps({"event": "something_else", "agentId": "agent-1"})
    assert parse_flood_log_line(message, ts) is None


def test_parse_flood_log_line_filters_malformed_json():
    ts = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)
    assert parse_flood_log_line("not json at all", ts) is None


# ---------------------------------------------------------------------------
# 5. fetch_flood_events
# ---------------------------------------------------------------------------


def test_fetch_flood_events_uses_cloudwatch_event_timestamp():
    window_start = datetime(2026, 7, 18, 11, 0, 0, tzinfo=UTC)
    now = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)
    event_ts_ms = int(datetime(2026, 7, 18, 11, 30, 0, tzinfo=UTC).timestamp() * 1000)

    def filter_log_events(log_group, start_ms, end_ms):
        assert log_group == "the-log-group"
        return [
            {"timestamp": event_ts_ms, "message": json.dumps({
                "event": "approval_queue_flood", "agentId": "agent-1", "op": "ledger.append", "cap": 5,
            })},
            {"timestamp": event_ts_ms, "message": json.dumps({"event": "unrelated"})},
        ]

    floods = fetch_flood_events(filter_log_events, "the-log-group", window_start, now)
    assert len(floods) == 1
    assert floods[0].ts == datetime(2026, 7, 18, 11, 30, 0, tzinfo=UTC)
    assert floods[0].agent_id == "agent-1"


# ---------------------------------------------------------------------------
# 6. execute() — end-to-end campaign found
# ---------------------------------------------------------------------------


def _make_drop_bytes(*, reason: str, ts: str, identity: str = "attacker") -> bytes:
    return make_drop_record("webhook", identity, reason, ts).model_dump_json().encode()


def test_execute_end_to_end_produces_campaign_and_content_alarm(tmp_path: Path, capsys):
    now = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)
    bodies = {
        "channels/drops/2026/07/18/a.json": _make_drop_bytes(
            reason="unmapped", ts="2026-07-18T11:50:00+00:00",
        ),
        "channels/drops/2026/07/18/b.json": _make_drop_bytes(
            reason="unmapped", ts="2026-07-18T11:55:00+00:00",
        ),
    }
    listed_prefixes: list[str] = []

    def list_keys(prefix: str) -> list[str]:
        listed_prefixes.append(prefix)
        return sorted(k for k in bodies if k.startswith(prefix))

    def get_object(key: str) -> bytes:
        return bodies[key]

    notifications: list[str] = []
    json_out = tmp_path / "report.json"

    reports = execute(
        now=now,
        min_attempts=2,
        window_seconds=3600,
        list_keys=list_keys,
        get_object=get_object,
        notify_fn=notifications.append,
        json_out=json_out,
    )

    assert len(reports) == 1
    assert reports[0].total == 2
    assert notifications == [
        f"campaign watchdog: campaign_id={reports[0].campaign_id} "
        f"basis={reports[0].basis} attribution_key={reports[0].attribution_key} "
        f"total=2 throttle_eligible={reports[0].throttle_eligible}"
    ]

    # channels/verdicts/ is never read — only channels/drops/... prefixes are listed.
    assert listed_prefixes == ["channels/drops/2026/07/18/"]
    assert all("verdicts" not in p for p in listed_prefixes)

    out = capsys.readouterr().out
    written = json.loads(json_out.read_text(encoding="utf-8"))
    assert written[0]["campaign_id"] == reports[0].campaign_id
    assert reports[0].campaign_id in out  # full JSON dump landed on stdout too


# ---------------------------------------------------------------------------
# 7. execute() — zero campaigns
# ---------------------------------------------------------------------------


def test_execute_zero_campaigns_no_content_alarm(capsys):
    now = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)
    notifications: list[str] = []

    reports = execute(
        now=now,
        min_attempts=5,
        window_seconds=3600,
        list_keys=lambda prefix: [],
        get_object=lambda key: b"{}",
        notify_fn=notifications.append,
    )

    assert reports == []
    assert notifications == []
    out = capsys.readouterr().out
    assert "no campaigns detected" in out
    assert "ALARM" not in out


# ---------------------------------------------------------------------------
# 8. execute() — reader exception -> meta-alarm
# ---------------------------------------------------------------------------


def test_execute_reader_exception_routes_to_meta_alarm(capsys):
    now = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)

    def list_keys(prefix: str):
        raise RuntimeError("bucket unreachable")

    with pytest.raises(SystemExit) as exc_info:
        execute(
            now=now,
            min_attempts=2,
            window_seconds=3600,
            list_keys=list_keys,
            get_object=lambda key: b"{}",
        )
    assert exc_info.value.code == 1

    captured = capsys.readouterr()
    # The heartbeat fires (and lands on stdout) BEFORE the sweep runs and fails
    # — a broken watchdog still proves it was alive right up to the failure.
    assert "HEARTBEAT" in captured.out
    err_lines = [ln for ln in captured.err.splitlines() if ln.strip()]
    assert len(err_lines) == 1
    record = json.loads(err_lines[0])
    assert record["level"] == "META_ALARM"
    assert "bucket unreachable" in record["msg"]
    assert record["component"] == "campaign-watchdog"


# ---------------------------------------------------------------------------
# 9. The airlock's drop vocabulary against the engine's attribution table
# ---------------------------------------------------------------------------


def test_every_drop_reason_sits_in_exactly_one_attribution_set():
    """channels/WATCHDOG.md calls the attribution table exhaustive over
    `DropReason`. A reason the airlock can write and the engine has not placed
    would fall to `unattributable` without anyone having decided that."""
    from typing import get_args

    sets = [
        campaign_module.VECTOR_AUTH_REASONS,
        campaign_module.FORGERY_REASONS,
        campaign_module.UNATTRIBUTABLE_REASONS,
    ]
    placed = [reason for group in sets for reason in group]
    assert sorted(placed) == sorted(get_args(DropReason))
    assert campaign_module.DEDUPE_CAPPED_REASONS <= campaign_module.VECTOR_AUTH_REASONS


def test_a_replayed_envelope_for_another_receiver_is_never_counted_against_its_signer():
    """End to end: broker A signs for another receiver, and the bytes are
    delivered to this airlock three times. A's key is enrolled here and the
    signature would verify. The records the airlock writes, read back the way
    the runner reads them, attribute the campaign to the transport identity."""
    priv, pub = signing_fixtures._keypair()
    signer = signing_fixtures.signer_from_pem("broker:A", "zone-a", priv)
    resolver = signing_fixtures._peer_resolver({"broker:A": (pub, "zone-a", ["peer:example"])})
    elsewhere = signing_fixtures._signed_outbound(signer, audience="another-receiver")
    assert signing_fixtures.verify_chain(elsewhere, resolver).ok

    drops: list = []
    for _ in range(3):
        accepted = dispatch(
            None,
            adapter=signing_fixtures._RecordingAdapter(elsewhere),
            trust_map=signing_fixtures._trust_map(),
            screen=None,
            verify_chain=make_gate(resolver),
            dedupe_store=set(),
            drops=drops,
            now=signing_fixtures._NOW,
            zone=signing_fixtures._RECV,
        )
        assert accepted is None

    events = [
        parse_drop_record(f"channels/drops/k{i}.json", record.model_dump_json().encode())
        for i, record in enumerate(drops)
    ]
    assert [event.reason for event in events] == ["audience_mismatch"] * 3
    reports = analyze(
        events,
        [],
        CampaignThresholds(min_attempts=3, window_seconds=3600),
        signing_fixtures._NOW,
    )
    assert len(reports) == 1
    report = reports[0]
    assert report.basis == "transport-token"
    assert report.attribution_key == f"webhook#{digest_identity('peer:example')}"
    assert "broker:A" not in report.model_dump_json()
