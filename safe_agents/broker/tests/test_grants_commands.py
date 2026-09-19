"""Tests for the grant-ceremony command surface (#123) — grants/commands.py.

Coverage (unit-level: InMemory stores, monkeypatched _caller_identity — no real
STS/AWS; argv goes through the real _parse_args so the argparse wiring is
proven end-to-end):
- propose → ratify happy path through the command functions: level raised,
  promotion record present, proposal burned.
- maker == checker (same STS arn) → structural refusal, proposal stays pending.
- ratify of an expired / rejected / already-consumed proposal → refusal.
- ineligible predicate at propose → refused, nothing stored.
- seed emits grant + bootstrap record PAIRS, stamps the STS identity, and skips
  existing grants cleanly on re-run (create-only, no duplicate records).
- re-seed refuses an HMAC-tamper (store-layer) quarantine loudly and re-attests
  an envelope-hash-mismatched grant at the SAME level with no ledger record.
- ratify DSSE-signs the record when an issuer signer is injected (generated
  Ed25519 key) and the stored envelope verifies via verify_record; the unsigned
  path warns LOUDLY.
- issuer_keys.resolve_record_signer: OFF without the ARN, fails closed on a
  half-configured environment, resolves via the monkeypatched secret fetch.
- _resolve_envelope_hash (#199): manifest mode refuses to stamp when the
  BROKER_MANIFEST principal is not the ceremony's target principal (naming
  both remedies); store mode stays keyed by the principal argument.
"""

from __future__ import annotations

import datetime
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safe_agents.broker.enforcement import InMemoryStore, scoped_counter_key
from safe_agents.broker.grants import commands, issuer_keys
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.grants.commands import (
    FALSE_ACTION_SUFFIX,
    HUMAN_OVERRIDE_SUFFIX,
    OBSERVATIONS_SUFFIX,
    _parse_args,
    acknowledge_command,
    propose_command,
    ratify_command,
    reject_command,
    reseed_command,
    seed_command,
    tighten_command,
)
from safe_agents.broker.grants.proposals import (
    InMemoryProposalStore,
    compute_proposal_hash,
)
from safe_agents.broker.grants.record_signing import (
    canonical_record_payload,
    signer_from_pem,
    verify_record,
)
from safe_agents.broker.grants.runner import RunnerConfigError
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.schemas import Grant
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.schemas.evidence import ConfidenceArtifact, SelfConsistencyEvidence
from safe_agents.channels.keys import key_resolver_from_map

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

MAKER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/maker-session"
CHECKER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/checker-session"
SEEDER_ARN = "arn:aws:sts::111111111111:assumed-role/PromotionRole/seeder-session"

PRINCIPAL = Principal(agentId="agent-cmd", skill="email", user="alice", tier="B")
ACTION_CLASS = "email.send"
ENVELOPE_HASH = "sha256:env-in-force"
NOW = datetime.datetime(2026, 7, 12, 12, 0, tzinfo=datetime.timezone.utc)

_ARTIFACT = ConfidenceArtifact(
    confidence=0.95,
    error_prob=0.05,
    evidence=SelfConsistencyEvidence(samples=5, agreement=0.95),
    computed_at="2026-07-12T00:00:00+00:00",
)


@pytest.fixture
def grant_store():
    return InMemoryGrantStore()


@pytest.fixture
def record_store():
    return InMemoryPromotionRecordStore()


@pytest.fixture
def proposal_store():
    return InMemoryProposalStore()


@pytest.fixture
def enforcement_store():
    return InMemoryStore()


@pytest.fixture
def artifact_path(tmp_path):
    path = tmp_path / "artifact.json"
    path.write_text(_ARTIFACT.model_dump_json())
    return path


def set_caller(monkeypatch, arn: str) -> None:
    monkeypatch.setattr(commands, "_caller_identity", lambda session=None: arn)


def make_grant(
    action_class: str = ACTION_CLASS,
    level: AutonomyLevel = AutonomyLevel.in_loop,
    envelope_hash: str = ENVELOPE_HASH,
) -> Grant:
    return Grant(
        principal=PRINCIPAL,
        actionClass=action_class,
        level=level,
        envelopeHash=envelope_hash,
        promotedBy="human-reviewer",
        evidence="seed-evidence-ref",
        ts="2026-07-01T00:00:00+00:00",
        lastSafeLevel=AutonomyLevel.in_loop,
        demotionTriggers=[],
        demotionReason=None,
        labelLatency="PT1H",
        ownerId="maintainer",
    )


def seed_counters(store, observations=100, false_actions=1, overrides=0) -> None:
    """Seed the durable evidence counters the way the drill does (out-of-band)."""
    for suffix, value in [
        (OBSERVATIONS_SUFFIX, observations),
        (FALSE_ACTION_SUFFIX, false_actions),
        (HUMAN_OVERRIDE_SUFFIX, overrides),
    ]:
        if value:
            key = scoped_counter_key(PRINCIPAL, "email", "send", suffix)
            assert store.try_increment_counter(key, float(value), 1e9)


def seed_counters_on_day(
    store, day_offset: int, observations=100, false_actions=1, overrides=0
) -> None:
    """Seed the evidence counters on the UTC day `day_offset` days before today.

    read_counter_window sums the last window_days UTC-day keys (today
    inclusive), so seeding an earlier day proves the window walks past today.
    """
    day = (
        datetime.datetime.now(datetime.UTC).date() - datetime.timedelta(days=day_offset)
    ).strftime("%Y%m%d")
    for suffix, value in [
        (OBSERVATIONS_SUFFIX, observations),
        (FALSE_ACTION_SUFFIX, false_actions),
        (HUMAN_OVERRIDE_SUFFIX, overrides),
    ]:
        if value:
            key = scoped_counter_key(PRINCIPAL, "email", "send", suffix, day=day)
            assert store.try_increment_counter(key, float(value), 1e9)


def propose_args(artifact_path, **overrides):
    """Parse real argv for propose — proves the argparse wiring end-to-end."""
    flags = {
        "--principal-agent-id": PRINCIPAL.agentId,
        "--skill": PRINCIPAL.skill,
        "--user": PRINCIPAL.user,
        "--tier": PRINCIPAL.tier,
        "--action-class": ACTION_CLASS,
        "--target-level": "on-loop",
        "--evidence-bundle": "evidence-ref-001",
        "--owner-id": "maintainer",
        "--label-latency": "PT1H",
        "--artifact-json": str(artifact_path),
        "--provenance-maturity": "signed-lineage",
        "--window-n": "200",
        "--min-observations": "10",
        "--threshold": "0.05",
        "--ttl-hours": "24",
        "--effect": "write",
    }
    flags.update(overrides)
    argv = ["propose"]
    for flag, value in flags.items():
        if value is not None:
            argv.extend([flag, value])
    argv.append("--covered")
    return _parse_args(argv)


def ratify_args(proposal_id: str, *, allow_unsigned: bool = True):
    """Parsed ratify args. allow_unsigned defaults True because most tests
    exercise the ceremony with signer=None (#205: unsigned-without-flag
    refuses; the refusal itself is covered by a dedicated regression test)."""
    argv = [
        "ratify",
        "--principal-agent-id", PRINCIPAL.agentId,
        "--skill", PRINCIPAL.skill,
        "--user", PRINCIPAL.user,
        "--tier", PRINCIPAL.tier,
        "--action-class", ACTION_CLASS,
        "--proposal-id", proposal_id,
    ]
    if allow_unsigned:
        argv.append("--allow-unsigned")
    return _parse_args(argv)


def reject_args(proposal_id: str):
    return _parse_args(
        [
            "reject",
            "--principal-agent-id", PRINCIPAL.agentId,
            "--skill", PRINCIPAL.skill,
            "--user", PRINCIPAL.user,
            "--tier", PRINCIPAL.tier,
            "--action-class", ACTION_CLASS,
            "--proposal-id", proposal_id,
        ]
    )


def tighten_args(**overrides):
    argv = [
        "tighten",
        "--principal-agent-id", PRINCIPAL.agentId,
        "--skill", PRINCIPAL.skill,
        "--user", PRINCIPAL.user,
        "--tier", PRINCIPAL.tier,
        "--action-class", ACTION_CLASS,
    ]
    for flag, value in overrides.items():
        argv.extend([flag, value])
    return _parse_args(argv)


def run_propose(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store, **overrides
) -> int:
    set_caller(monkeypatch, MAKER_ARN)
    return propose_command(
        propose_args(artifact_path, **overrides),
        grant_store=grant_store,
        proposal_store=proposal_store,
        enforcement_store=enforcement_store,
        envelope_hash=ENVELOPE_HASH,
        now=NOW,
    )


def stored_proposal_id(proposal_store) -> str:
    pending = proposal_store.list_pending(PRINCIPAL, ACTION_CLASS)
    assert len(pending) == 1
    return pending[0].proposal_id


# ---------------------------------------------------------------------------
# propose → ratify happy path
# ---------------------------------------------------------------------------


def test_propose_then_ratify_happy_path(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store
):
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters(enforcement_store)

    rc = run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    )
    assert rc == 0
    proposal_id = stored_proposal_id(proposal_store)

    set_caller(monkeypatch, CHECKER_ARN)
    rc = ratify_command(
        ratify_args(proposal_id),
        grant_store=grant_store,
        record_store=record_store,
        proposal_store=proposal_store,
        signer=None,
        now=NOW,
    )
    assert rc == 0

    # Level raised through the ceremony...
    raised = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert not raised.quarantined
    assert raised.grant.level is AutonomyLevel.on_loop
    assert raised.grant.promotedBy == CHECKER_ARN
    # ...with a promotion record carrying the two DERIVED identities...
    assert len(record_store.records) == 1
    record = record_store.records[0]
    assert record.recordType == "promotion"
    assert record.proposedBy == MAKER_ARN
    assert record.ratifiedBy == CHECKER_ARN
    assert record.fromLevel is AutonomyLevel.in_loop
    assert record.toLevel is AutonomyLevel.on_loop
    # ...and the proposal burned single-shot.
    _, status = proposal_store.get_proposal(PRINCIPAL, ACTION_CLASS, proposal_id)
    assert status == "ratified"


def test_maker_equals_checker_is_refused(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
    capsys,
):
    grant_store.put_grant(make_grant())
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    # The SAME credential identity attempts to ratify its own proposal.
    set_caller(monkeypatch, MAKER_ARN)
    rc = ratify_command(
        ratify_args(proposal_id),
        grant_store=grant_store,
        record_store=record_store,
        proposal_store=proposal_store,
        signer=None,
        now=NOW,
    )
    assert rc == 1
    assert "must differ" in capsys.readouterr().out
    # Nothing changed: no record, level intact, proposal NOT burned (the
    # identity gate rejects before consumption).
    assert record_store.records == []
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop
    _, status = proposal_store.get_proposal(PRINCIPAL, ACTION_CLASS, proposal_id)
    assert status == "pending"


# ---------------------------------------------------------------------------
# ratify refusals: expired / rejected / consumed / absent
# ---------------------------------------------------------------------------


def _ratify(monkeypatch, proposal_id, stores, *, now=NOW, arn=CHECKER_ARN):
    grant_store, record_store, proposal_store = stores
    set_caller(monkeypatch, arn)
    return ratify_command(
        ratify_args(proposal_id),
        grant_store=grant_store,
        record_store=record_store,
        proposal_store=proposal_store,
        signer=None,
        now=now,
    )


def test_ratify_expired_proposal_is_refused(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
    capsys,
):
    grant_store.put_grant(make_grant())
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--ttl-hours": "1"},
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    rc = _ratify(
        monkeypatch,
        proposal_id,
        (grant_store, record_store, proposal_store),
        now=NOW + datetime.timedelta(hours=2),
    )
    assert rc == 1
    assert "expired" in capsys.readouterr().out
    assert record_store.records == []


def test_ratify_rejected_proposal_is_refused(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
    capsys,
):
    grant_store.put_grant(make_grant())
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    set_caller(monkeypatch, CHECKER_ARN)
    assert reject_command(reject_args(proposal_id), proposal_store=proposal_store) == 0
    out = capsys.readouterr().out
    assert CHECKER_ARN in out  # the rejecting identity is recorded in the output

    rc = _ratify(monkeypatch, proposal_id, (grant_store, record_store, proposal_store))
    assert rc == 1
    assert "'rejected', not pending" in capsys.readouterr().out
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is AutonomyLevel.in_loop


def test_ratify_consumed_proposal_is_refused(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
    capsys,
):
    grant_store.put_grant(make_grant())
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    stores = (grant_store, record_store, proposal_store)
    assert _ratify(monkeypatch, proposal_id, stores) == 0
    # Second ratification of the same (already-consumed) proposal.
    rc = _ratify(monkeypatch, proposal_id, stores)
    assert rc == 1
    assert "'ratified', not pending" in capsys.readouterr().out
    assert len(record_store.records) == 1  # no double promotion


def test_ratify_absent_proposal_is_refused(
    monkeypatch, grant_store, record_store, proposal_store, capsys
):
    rc = _ratify(monkeypatch, "no-such-id", (grant_store, record_store, proposal_store))
    assert rc == 1
    assert "no proposal" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# propose refusals
# ---------------------------------------------------------------------------


def test_ineligible_predicate_stores_nothing(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store, capsys
):
    grant_store.put_grant(make_grant())
    seed_counters(enforcement_store, observations=2, false_actions=0)  # below min 10

    rc = run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "insufficient observations" in out  # the predicate REASON is printed
    assert "ineligible proposal is not stored" in out
    assert proposal_store.list_pending(PRINCIPAL, ACTION_CLASS) == []


def test_propose_level_skip_is_refused(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store, capsys
):
    """No grant exists (the Recommend rung) — the only valid target is in-loop."""
    seed_counters(enforcement_store)
    rc = run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--target-level": "on-loop"},
    )
    assert rc == 1
    assert "Level-skipping" in capsys.readouterr().out
    assert proposal_store.list_pending(PRINCIPAL, ACTION_CLASS) == []


# ---------------------------------------------------------------------------
# --window-days — the honest multi-day evidence window (#193)
# ---------------------------------------------------------------------------


def test_default_window_sees_today_only(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store, capsys
):
    """No --window-days flag ⇒ window_days=1 ⇒ only today's counters are read.

    The evidence was accumulated three UTC days ago, so a single-day read finds
    zero observations and the predicate refuses on the thin sample."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters_on_day(enforcement_store, day_offset=3)

    rc = run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    )
    assert rc == 1
    assert "insufficient observations" in capsys.readouterr().out
    assert proposal_store.list_pending(PRINCIPAL, ACTION_CLASS) == []


def test_window_days_sees_earlier_utc_days(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
):
    """--window-days 7 sums the last seven UTC-day keys, so evidence written
    three days ago becomes visible and the proposal stores."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters_on_day(enforcement_store, day_offset=3)

    rc = run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--window-days": "7"},
    )
    assert rc == 0
    pending = proposal_store.list_pending(PRINCIPAL, ACTION_CLASS)
    assert len(pending) == 1
    # The windowed metrics were baked onto the proposal (ratify re-reads no
    # counters — ceremony.execute runs the predicate over proposal.metrics).
    assert pending[0].metrics.observation_count == 100
    assert pending[0].metrics.false_action_count == 1
    # The window span rides the proposal as checker-visible provenance (#193).
    assert pending[0].window_periods == 7
    assert pending[0].period == "utc-day"


def _only_stored_item(proposal_store) -> dict:
    items = list(proposal_store._items.values())
    assert len(items) == 1
    return items[0]


def test_ratify_surfaces_window_provenance(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
    capsys,
):
    """The ratify command prints the evidence day-span for the checker."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters_on_day(enforcement_store, day_offset=2)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--window-days": "5"},
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)
    capsys.readouterr()  # drop propose output

    assert _ratify(
        monkeypatch, proposal_id, (grant_store, record_store, proposal_store)
    ) == 0
    out = capsys.readouterr().out
    assert "summed over 5 utc-day period(s)" in out
    assert "window_n=200" in out


def test_ratify_refuses_tampered_window_days(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
    capsys,
):
    """window_days is HMAC-bound: editing it on the stored item is refused like
    any other tamper (it launders a thin-sample proposal into a signed grant)."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    # Bump window_periods in the stored data WITHOUT recomputing the HMAC.
    item = _only_stored_item(proposal_store)
    payload = json.loads(item["data"])
    payload["window_periods"] = 366
    item["data"] = json.dumps(payload, sort_keys=True, ensure_ascii=True)

    rc = _ratify(monkeypatch, proposal_id, (grant_store, record_store, proposal_store))
    assert rc == 1
    assert "integrity verification" in capsys.readouterr().out
    assert record_store.records == []


def test_ratify_defaults_absent_window_keys_to_day_one(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
):
    """A proposal stored before #193 has no window keys at all; it must still
    load (defaulting to 1 utc-day period) and ratify."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    # Simulate the pre-#193 item: drop the keys and RE-HASH so integrity passes
    # (the fields genuinely never existed for that proposal).
    item = _only_stored_item(proposal_store)
    payload = json.loads(item["data"])
    del payload["window_periods"]
    del payload["period"]
    new_data = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    item["data"] = new_data
    item["proposalHash"] = compute_proposal_hash(new_data, b"test-hmac-key")

    loaded, _ = proposal_store.get_proposal(PRINCIPAL, ACTION_CLASS, proposal_id)
    assert loaded.window_periods == 1  # proposal_from_json defaulted it
    assert loaded.period == "utc-day"
    assert _ratify(
        monkeypatch, proposal_id, (grant_store, record_store, proposal_store)
    ) == 0
    assert len(record_store.records) == 1


def test_legacy_window_days_key_loads_as_window_periods(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
):
    """A pre-#212 stored proposal spelled the span 'window_days'; it must load
    as window_periods (day-period semantics, which is what it always meant)."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--window-days": "3"},
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    # Rewrite the item in the pre-#212 wire shape and RE-HASH (a genuine old item).
    item = _only_stored_item(proposal_store)
    payload = json.loads(item["data"])
    payload["window_days"] = payload.pop("window_periods")
    del payload["period"]
    new_data = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    item["data"] = new_data
    item["proposalHash"] = compute_proposal_hash(new_data, b"test-hmac-key")

    loaded, _ = proposal_store.get_proposal(PRINCIPAL, ACTION_CLASS, proposal_id)
    assert loaded.window_periods == 3
    assert loaded.period == "utc-day"


def seed_counters_on_hour(
    store, hour_offset: int, observations=100, false_actions=1, overrides=0
) -> None:
    """Seed the evidence counters on the UTC hour `hour_offset` hours before now."""
    bucket = (
        datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=hour_offset)
    ).strftime("%Y%m%dT%H")
    for suffix, value in [
        (OBSERVATIONS_SUFFIX, observations),
        (FALSE_ACTION_SUFFIX, false_actions),
        (HUMAN_OVERRIDE_SUFFIX, overrides),
    ]:
        if value:
            key = scoped_counter_key(
                PRINCIPAL, "email", "send", suffix, period="utc-hour", bucket=bucket
            )
            assert store.try_increment_counter(key, float(value), 1e9)


def test_propose_at_hour_period_reads_hour_buckets(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
):
    """--period utc-hour sums hour-bucketed evidence and stamps the period onto
    the HMAC-bound proposal (#212). The full lifecycle at development speed."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters_on_hour(enforcement_store, hour_offset=2)

    rc = run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--period": "utc-hour", "--window-periods": "3"},
    )
    assert rc == 0
    pending = proposal_store.list_pending(PRINCIPAL, ACTION_CLASS)
    assert len(pending) == 1
    assert pending[0].metrics.observation_count == 100
    assert pending[0].window_periods == 3
    assert pending[0].period == "utc-hour"


def test_period_mismatch_reads_zero_evidence(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store, capsys,
):
    """Evidence written at hour period is INVISIBLE to a day-period propose —
    a period mismatch fails toward less authority (refused on the thin sample),
    never a wrong sum."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters_on_hour(enforcement_store, hour_offset=0)

    rc = run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--window-periods": "7"},  # day period (default) over hour-keyed evidence
    )
    assert rc == 1
    assert "insufficient observations" in capsys.readouterr().out
    assert proposal_store.list_pending(PRINCIPAL, ACTION_CLASS) == []


@pytest.mark.parametrize("window_days", ["0", "367"], ids=["below-min", "above-max"])
def test_out_of_range_window_days_is_refused(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store, capsys,
    window_days,
):
    """--window-days outside 1..366 is refused by read_counter_window's own
    ValueError — a bad window can never produce a partial read."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters_on_day(enforcement_store, day_offset=0)

    rc = run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--window-days": window_days},
    )
    assert rc == 1
    assert "window_periods must be between 1 and 366" in capsys.readouterr().out
    assert proposal_store.list_pending(PRINCIPAL, ACTION_CLASS) == []


# ---------------------------------------------------------------------------
# seed — grant + bootstrap record pairs
# ---------------------------------------------------------------------------


def test_seed_emits_grant_and_bootstrap_record_pairs(
    monkeypatch, grant_store, record_store
):
    set_caller(monkeypatch, SEEDER_ARN)
    templates = [make_grant("email.send"), make_grant("email.draft")]

    rc = seed_command(
        grant_store=grant_store, record_store=record_store, grants=templates, now=NOW
    )
    assert rc == 0

    for action_class in ("email.send", "email.draft"):
        read = grant_store.get_grant(PRINCIPAL, action_class)
        assert read.grant is not None and not read.quarantined
        assert read.grant.promotedBy == SEEDER_ARN  # seededBy = the STS identity
    assert len(record_store.records) == 2
    for record in record_store.records:
        assert record.recordType == "bootstrap"
        assert record.fromLevel is None  # the seed creates the grant from Recommend
        assert record.proposedBy == SEEDER_ARN
        assert record.ratifiedBy == SEEDER_ARN  # maker != checker NOT enforced here
        assert record.envelopeHash == ENVELOPE_HASH


def test_seed_skips_existing_grants_cleanly(monkeypatch, grant_store, record_store, capsys):
    set_caller(monkeypatch, SEEDER_ARN)
    templates = [make_grant("email.send")]
    assert seed_command(
        grant_store=grant_store, record_store=record_store, grants=templates, now=NOW
    ) == 0

    # Re-run: the existing grant is a clean per-class skip, no duplicate record.
    rc = seed_command(
        grant_store=grant_store,
        record_store=record_store,
        grants=templates,
        now=NOW + datetime.timedelta(hours=1),
    )
    assert rc == 0
    assert "SKIP" in capsys.readouterr().out
    assert len(record_store.records) == 1


# ---------------------------------------------------------------------------
# re-seed — envelope-hash re-attestation
# ---------------------------------------------------------------------------


def test_reseed_reattests_envelope_mismatch_at_same_level(
    monkeypatch, grant_store, record_store, capsys
):
    grant_store.put_grant(make_grant(level=AutonomyLevel.on_loop, envelope_hash="sha256:old"))
    set_caller(monkeypatch, CHECKER_ARN)

    rc = reseed_command(
        grant_store=grant_store,
        principal=PRINCIPAL,
        granted_classes=[ACTION_CLASS],
        envelope_hash="sha256:new",
        now=NOW,
    )
    assert rc == 0
    assert "re-attested" in capsys.readouterr().out
    read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert not read.quarantined
    assert read.grant.envelopeHash == "sha256:new"
    assert read.grant.level is AutonomyLevel.on_loop  # SAME level carried
    assert read.grant.promotedBy == CHECKER_ARN  # the ratifying STS identity stamped
    assert record_store.records == []  # no level change -> no PromotionRecord


def test_reseed_refuses_hmac_tamper_quarantine(monkeypatch, grant_store, capsys):
    grant_store.put_grant(make_grant(envelope_hash="sha256:old"))
    # Tamper the stored payload without recomputing the HMAC — the store-layer
    # quarantine (grants/store.py), the kind that is NEVER re-attestable.
    key = (f"{PRINCIPAL.agentId}#{PRINCIPAL.skill}#{PRINCIPAL.user}#{PRINCIPAL.tier}",
           ACTION_CLASS)
    grant_store._store[key]["data"] = grant_store._store[key]["data"].replace(
        '"evidence":"', '"evidence":"tampered-', 1
    )
    set_caller(monkeypatch, CHECKER_ARN)

    rc = reseed_command(
        grant_store=grant_store,
        principal=PRINCIPAL,
        granted_classes=[ACTION_CLASS],
        envelope_hash="sha256:new",
        now=NOW,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "NEVER re-attestable" in err
    assert "incident" in err
    # The tampered grant was not written over (the tamper evidence survives).
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).quarantined


def test_reseed_skips_grant_already_in_force(monkeypatch, grant_store, capsys):
    grant_store.put_grant(make_grant(envelope_hash="sha256:new"))
    set_caller(monkeypatch, CHECKER_ARN)

    rc = reseed_command(
        grant_store=grant_store,
        principal=PRINCIPAL,
        granted_classes=[ACTION_CLASS],
        envelope_hash="sha256:new",
        now=NOW,
    )
    assert rc == 0
    assert "nothing to re-attest" in capsys.readouterr().out


def test_reseed_fails_on_absent_grant(monkeypatch, grant_store, capsys):
    set_caller(monkeypatch, CHECKER_ARN)
    rc = reseed_command(
        grant_store=grant_store,
        principal=PRINCIPAL,
        granted_classes=[ACTION_CLASS],
        envelope_hash="sha256:new",
        now=NOW,
    )
    assert rc == 1
    assert "bootstrap it with `seed`" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# tighten — voluntary tightening: any level -> in-loop
# ---------------------------------------------------------------------------


def test_tighten_lowers_on_loop_grant_and_appends_record(
    monkeypatch, grant_store, record_store, capsys
):
    grant_store.put_grant(make_grant(level=AutonomyLevel.on_loop))
    set_caller(monkeypatch, SEEDER_ARN)

    rc = tighten_command(
        tighten_args(), grant_store=grant_store, record_store=record_store, now=NOW
    )
    assert rc == 0
    read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert not read.quarantined
    assert read.grant.level is AutonomyLevel.in_loop
    assert len(record_store.records) == 1
    record = record_store.records[0]
    assert record.recordType == "tightening"
    assert record.toLevel is AutonomyLevel.in_loop
    assert record.evidence == "voluntary tightening"  # the CLI default
    assert record.proposedBy == SEEDER_ARN
    out = capsys.readouterr().out
    assert "TIGHTENED: on-loop -> in-loop" in out
    assert f"ts={record.ts}" in out


def test_tighten_already_in_loop_is_refused(monkeypatch, grant_store, record_store, capsys):
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    set_caller(monkeypatch, SEEDER_ARN)

    rc = tighten_command(
        tighten_args(), grant_store=grant_store, record_store=record_store, now=NOW
    )
    assert rc == 1
    assert "already at in-loop — nothing to tighten" in capsys.readouterr().out
    assert record_store.records == []


def test_tighten_refuses_quarantined_grant(monkeypatch, grant_store, record_store, capsys):
    grant_store.put_grant(make_grant(level=AutonomyLevel.on_loop))
    # Tamper the stored payload without recomputing the HMAC — the store-layer
    # quarantine; tighten must refuse and never write over it.
    key = (
        f"{PRINCIPAL.agentId}#{PRINCIPAL.skill}#{PRINCIPAL.user}#{PRINCIPAL.tier}",
        ACTION_CLASS,
    )
    grant_store._store[key]["data"] = grant_store._store[key]["data"].replace(
        '"evidence":"', '"evidence":"tampered-', 1
    )
    set_caller(monkeypatch, SEEDER_ARN)

    rc = tighten_command(
        tighten_args(), grant_store=grant_store, record_store=record_store, now=NOW
    )
    assert rc == 1
    assert "quarantined" in capsys.readouterr().out
    assert record_store.records == []
    # The tampered grant was not written over (the quarantine survives).
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).quarantined


# ---------------------------------------------------------------------------
# issuer signing — signed and unsigned ratification paths
# ---------------------------------------------------------------------------


def _generate_issuer_key():
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def test_ratify_signs_record_when_issuer_key_injected(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store
):
    grant_store.put_grant(make_grant())
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    private_pem, public_pem = _generate_issuer_key()
    signer = signer_from_pem("issuer-key-1", "development", private_pem)

    set_caller(monkeypatch, CHECKER_ARN)
    rc = ratify_command(
        # A configured signer needs no --allow-unsigned opt-in (#205).
        ratify_args(proposal_id, allow_unsigned=False),
        grant_store=grant_store,
        record_store=record_store,
        proposal_store=proposal_store,
        signer=signer,
        now=NOW,
    )
    assert rc == 0

    record = record_store.records[0]
    envelope = record_store.signature_for(record)
    assert envelope is not None
    # The stored DSSE envelope verifies against the STORED record.
    result = verify_record(
        canonical_record_payload(record), envelope, key_resolver_from_map({"issuer-key-1": public_pem})
    )
    assert result.ok, result.reason


def test_ratify_without_issuer_key_warns_loudly(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
    capsys,
):
    grant_store.put_grant(make_grant())
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    set_caller(monkeypatch, CHECKER_ARN)
    rc = ratify_command(
        ratify_args(proposal_id),
        grant_store=grant_store,
        record_store=record_store,
        proposal_store=proposal_store,
        signer=None,
        now=NOW,
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "UNSIGNED" in err
    assert "--allow-unsigned" in err
    assert record_store.signature_for(record_store.records[0]) is None


def test_ratify_unsigned_without_flag_refuses_and_writes_nothing(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
    capsys,
):
    """#205 regression: signer=None without --allow-unsigned refuses — no
    PromotionRecord, no grant mutation, proposal still pending (not burned)."""
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    set_caller(monkeypatch, CHECKER_ARN)
    rc = ratify_command(
        ratify_args(proposal_id, allow_unsigned=False),
        grant_store=grant_store,
        record_store=record_store,
        proposal_store=proposal_store,
        signer=None,
        now=NOW,
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "REFUSED: issuer signing key not configured" in out
    assert "--allow-unsigned" in out
    # Nothing written: no record, grant level unchanged, proposal not consumed.
    assert record_store.records == []
    stored = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert stored.grant.level is AutonomyLevel.in_loop
    _, status = proposal_store.get_proposal(PRINCIPAL, ACTION_CLASS, proposal_id)
    assert status == "pending"


# ---------------------------------------------------------------------------
# acknowledge — signed waiver ceremony for TRUE audit findings (#196)
# ---------------------------------------------------------------------------


def ack_args(rule: str = "GRANT_ENVELOPE_IN_FORCE", **overrides):
    import argparse

    defaults = dict(
        rule=rule,
        coordinate="agent-cmd#trading#maintainer#B#ledger.append",
        detail="grant envelopeHash 'sha256:old' does not match ...",
        rationale="expected stale window pending re-seed",
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_acknowledge_appends_signed_verifying_record(monkeypatch, capsys):
    from safe_agents.broker.grants.acknowledgments import (
        AcknowledgmentRecord,
        InMemoryAcknowledgmentStore,
        verify_acknowledgment,
        violation_detail_digest,
    )

    private_pem, public_pem = _generate_issuer_key()
    signer = signer_from_pem("issuer-key-1", "development", private_pem)
    store = InMemoryAcknowledgmentStore()
    set_caller(monkeypatch, CHECKER_ARN)

    rc = acknowledge_command(ack_args(), ack_store=store, signer=signer, now=NOW)
    assert rc == 0
    assert "ACKNOWLEDGED" in capsys.readouterr().out

    (item,) = store.items()
    ack = AcknowledgmentRecord.model_validate_json(item["data"])
    assert ack.acknowledgedBy == CHECKER_ARN  # STS-derived, never asserted
    assert ack.detailDigest == violation_detail_digest(ack_args().detail)
    # Verify from the STORED bytes (#246 instance 7)
    result = verify_acknowledgment(
        item["data"], json.loads(item["signature"]), key_resolver_from_map({"issuer-key-1": public_pem})
    )
    assert result.ok, result.reason

    # Append-only: the same slot can never be replaced
    rc = acknowledge_command(ack_args(), ack_store=store, signer=signer, now=NOW)
    assert rc == 1
    assert "REFUSED" in capsys.readouterr().out


def test_acknowledge_refuses_unwaivable_rule(monkeypatch, capsys):
    from safe_agents.broker.grants.acknowledgments import InMemoryAcknowledgmentStore

    private_pem, _ = _generate_issuer_key()
    signer = signer_from_pem("issuer-key-1", "development", private_pem)
    store = InMemoryAcknowledgmentStore()
    set_caller(monkeypatch, CHECKER_ARN)

    rc = acknowledge_command(
        ack_args(rule="GRANT_TAMPER"), ack_store=store, signer=signer, now=NOW
    )
    assert rc == 1
    assert "not waivable" in capsys.readouterr().out
    assert store.items() == []


def test_acknowledge_refuses_unsigned(monkeypatch, capsys):
    from safe_agents.broker.grants.acknowledgments import InMemoryAcknowledgmentStore

    store = InMemoryAcknowledgmentStore()
    set_caller(monkeypatch, CHECKER_ARN)

    rc = acknowledge_command(ack_args(), ack_store=store, signer=None, now=NOW)
    assert rc == 1
    assert "must be issuer-signed" in capsys.readouterr().out
    assert store.items() == []


# ---------------------------------------------------------------------------
# issuer_keys — cold-start resolution seam
# ---------------------------------------------------------------------------


def test_resolve_record_signer_off_without_arn(monkeypatch):
    monkeypatch.delenv(issuer_keys.ISSUER_SIGNING_KEY_SECRET_ARN_ENV, raising=False)
    monkeypatch.delenv(issuer_keys.ISSUER_SIGNING_KEY_ID_ENV, raising=False)
    assert issuer_keys.resolve_record_signer(zone="development") is None


def test_resolve_record_signer_refuses_half_configured(monkeypatch):
    """#196: key_id without the key ARN REFUSES — never an unsigned record."""
    monkeypatch.delenv(issuer_keys.ISSUER_SIGNING_KEY_SECRET_ARN_ENV, raising=False)
    monkeypatch.setenv(issuer_keys.ISSUER_SIGNING_KEY_ID_ENV, "issuer-key-1")
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="half-configured"):
        issuer_keys.resolve_record_signer(zone="development")


def test_resolve_record_signer_requires_key_id(monkeypatch):
    monkeypatch.setenv(issuer_keys.ISSUER_SIGNING_KEY_SECRET_ARN_ENV, "arn:aws:sm:key")
    monkeypatch.delenv(issuer_keys.ISSUER_SIGNING_KEY_ID_ENV, raising=False)
    with pytest.raises(issuer_keys.IssuerSigningConfigError):
        issuer_keys.resolve_record_signer(zone="development")


def test_resolve_record_signer_requires_zone(monkeypatch):
    monkeypatch.setenv(issuer_keys.ISSUER_SIGNING_KEY_SECRET_ARN_ENV, "arn:aws:sm:key")
    monkeypatch.setenv(issuer_keys.ISSUER_SIGNING_KEY_ID_ENV, "issuer-key-1")
    monkeypatch.delenv(issuer_keys.ISSUER_SIGNING_ZONE_ENV, raising=False)
    with pytest.raises(issuer_keys.IssuerSigningConfigError):
        issuer_keys.resolve_record_signer()


def test_resolve_record_signer_via_monkeypatched_secret_fetch(monkeypatch):
    private_pem, _ = _generate_issuer_key()
    monkeypatch.setenv(issuer_keys.ISSUER_SIGNING_KEY_SECRET_ARN_ENV, "arn:aws:sm:key")
    monkeypatch.setenv(issuer_keys.ISSUER_SIGNING_KEY_ID_ENV, "issuer-key-1")
    monkeypatch.setattr(issuer_keys, "_fetch_secret", lambda arn: private_pem)

    signer = issuer_keys.resolve_record_signer(zone="development")
    assert signer is not None
    assert signer.key_id == "issuer-key-1"
    assert signer.zone == "development"


def test_resolve_record_signer_fails_closed_on_bad_secret(monkeypatch):
    monkeypatch.setenv(issuer_keys.ISSUER_SIGNING_KEY_SECRET_ARN_ENV, "arn:aws:sm:key")
    monkeypatch.setenv(issuer_keys.ISSUER_SIGNING_KEY_ID_ENV, "issuer-key-1")
    monkeypatch.setattr(issuer_keys, "_fetch_secret", lambda arn: "not-a-pem")
    with pytest.raises(issuer_keys.IssuerSigningConfigError):
        issuer_keys.resolve_record_signer(zone="development")


# ---------------------------------------------------------------------------
# issuer_keys — read-only verify-keys resolution seam (#194)
# ---------------------------------------------------------------------------


def test_resolve_issuer_verify_keys_off_without_param(monkeypatch):
    monkeypatch.delenv(issuer_keys.ISSUER_VERIFY_KEYS_PARAM_ENV, raising=False)
    assert issuer_keys.resolve_issuer_verify_keys() is None


def test_resolve_issuer_verify_keys_resolves_known_key_id(monkeypatch):
    """The happy path: a {key_id: public_pem} map resolves the known key and
    maps an unknown key_id to None (verification treats that as an unknown
    signer and fails the record closed)."""
    private_pem, public_pem = _generate_issuer_key()
    monkeypatch.setenv(issuer_keys.ISSUER_VERIFY_KEYS_PARAM_ENV, "/safe-agents/x/issuer/verify-keys")
    monkeypatch.setattr(
        issuer_keys, "_fetch_parameter", lambda name: json.dumps({"issuer-key-1": public_pem})
    )

    resolver = issuer_keys.resolve_issuer_verify_keys()
    assert resolver is not None
    assert resolver("issuer-key-1") is not None
    assert resolver("unknown-key") is None


def test_resolve_issuer_verify_keys_empty_map_is_valid(monkeypatch):
    """An empty map is a legitimate not-yet-provisioned state: the rule RUNS
    and any signed record fails loud (unknown signer) — never a silent skip."""
    monkeypatch.setenv(issuer_keys.ISSUER_VERIFY_KEYS_PARAM_ENV, "/safe-agents/x/issuer/verify-keys")
    monkeypatch.setattr(issuer_keys, "_fetch_parameter", lambda name: "{}")

    resolver = issuer_keys.resolve_issuer_verify_keys()
    assert resolver is not None
    assert resolver("any-key-id") is None


@pytest.mark.parametrize(
    "value",
    ["not json", '["a-list"]', '{"issuer-key-1": "not-a-pem"}'],
    ids=["bad-json", "non-object", "malformed-pem"],
)
def test_resolve_issuer_verify_keys_fails_closed_on_bad_value(monkeypatch, value):
    monkeypatch.setenv(issuer_keys.ISSUER_VERIFY_KEYS_PARAM_ENV, "/safe-agents/x/issuer/verify-keys")
    monkeypatch.setattr(issuer_keys, "_fetch_parameter", lambda name: value)
    with pytest.raises(issuer_keys.IssuerSigningConfigError):
        issuer_keys.resolve_issuer_verify_keys()


def test_resolve_issuer_verify_keys_fails_closed_on_unfetchable_param(monkeypatch):
    def boom(name):
        raise RuntimeError("ParameterNotFound")

    monkeypatch.setenv(issuer_keys.ISSUER_VERIFY_KEYS_PARAM_ENV, "/safe-agents/x/issuer/verify-keys")
    monkeypatch.setattr(issuer_keys, "_fetch_parameter", boom)
    with pytest.raises(issuer_keys.IssuerSigningConfigError):
        issuer_keys.resolve_issuer_verify_keys()


# ---------------------------------------------------------------------------
# _resolve_envelope_hash (#199) — manifest mode refuses a principal mismatch;
# store mode stays keyed by the principal argument
# ---------------------------------------------------------------------------

_MANIFEST_PRINCIPAL = Principal(agentId="example-advisor", skill="demo", user="demo-user", tier="B")
_TARGET_PRINCIPAL = Principal(agentId="owner-example-agent", skill="observer", user="owner-relay", tier="B")


def _fake_manifest(principal: Principal | None):
    from safe_agents.broker.schemas import AgentManifest

    block = {
        "envelope": {
            "polarity": "abstain",
            "caps": {"actions_per_run": 1},
            "allowlists": {"tools": []},
            "high_stakes": False,
        }
    }
    if principal is not None:
        block["principal"] = principal.model_dump(mode="json")
    return AgentManifest.model_validate(block)


def _set_manifest(monkeypatch, principal: Principal | None):
    from safe_agents.broker.prototype import broker_server

    monkeypatch.delenv("BROKER_ENVELOPE_LOAD", raising=False)
    manifest = _fake_manifest(principal)
    monkeypatch.setattr(broker_server, "_MANIFEST", manifest)
    return manifest


def test_resolve_envelope_hash_manifest_mode_mismatch_refused(monkeypatch):
    """The #199 shape: ceremony target owner-example-agent, _MANIFEST left at
    the example-advisor default — refused loudly, naming both principals and
    both remedies, instead of silently stamping the wrong envelope hash."""
    from safe_agents.broker.grants._commands_common import _resolve_envelope_hash

    _set_manifest(monkeypatch, _MANIFEST_PRINCIPAL)

    with pytest.raises(RunnerConfigError) as exc_info:
        _resolve_envelope_hash(_TARGET_PRINCIPAL, "test-grants-table")
    message = str(exc_info.value)
    assert "owner-example-agent" in message
    assert "example-advisor" in message
    assert "BROKER_MANIFEST" in message
    assert "BROKER_ENVELOPE_LOAD=store" in message


def test_resolve_envelope_hash_manifest_mode_no_principal_refused(monkeypatch):
    """A manifest with no principal block cannot vouch for ANY ceremony target."""
    from safe_agents.broker.grants._commands_common import _resolve_envelope_hash

    _set_manifest(monkeypatch, None)

    with pytest.raises(RunnerConfigError):
        _resolve_envelope_hash(_TARGET_PRINCIPAL, "test-grants-table")


def test_resolve_envelope_hash_manifest_mode_match_succeeds(monkeypatch):
    """Matching principals is the legitimate local-loop shape — the manifest's
    envelope hash comes back unchanged."""
    from safe_agents.broker.grants._commands_common import _resolve_envelope_hash
    from safe_agents.broker.schemas import compute_envelope_hash

    manifest = _set_manifest(monkeypatch, _MANIFEST_PRINCIPAL)

    result = _resolve_envelope_hash(_MANIFEST_PRINCIPAL, "test-grants-table")
    assert result == compute_envelope_hash(manifest.envelope)


def test_resolve_envelope_hash_store_mode_unchanged(monkeypatch):
    """Store mode reads the seeded envelope keyed by the PRINCIPAL argument —
    it never consults _MANIFEST, so a mismatched manifest is irrelevant."""
    from safe_agents.broker.envelope import read as envelope_read
    from safe_agents.broker.envelope import store as envelope_store
    from safe_agents.broker.grants._commands_common import _resolve_envelope_hash
    from safe_agents.broker.schemas import Envelope, compute_envelope_hash

    _set_manifest(monkeypatch, _MANIFEST_PRINCIPAL)
    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")

    seeded = Envelope.model_validate(
        {
            "polarity": "abstain",
            "caps": {"actions_per_run": 7},
            "allowlists": {"tools": ["ledger.append"]},
            "high_stakes": False,
        }
    )
    seen: dict = {}

    def fake_load(store, principal):
        seen["principal"] = principal
        return seeded

    monkeypatch.setattr(envelope_store, "DynamoDBEnvelopeStore", lambda table_name: object())
    monkeypatch.setattr(envelope_read, "load_inforce_envelope", fake_load)

    result = _resolve_envelope_hash(_TARGET_PRINCIPAL, "test-grants-table")
    assert result == compute_envelope_hash(seeded)
    assert seen["principal"] == _TARGET_PRINCIPAL


# ---------------------------------------------------------------------------
# #255 — the certification term rides the ceremony CLI, and only the ceremony
# ---------------------------------------------------------------------------

_TERM = "2026-10-01T00:00:00+00:00"


def test_propose_then_ratify_carries_the_term(
    monkeypatch, artifact_path, grant_store, record_store, proposal_store, enforcement_store,
    capsys,
):
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--certified-until": _TERM},
    ) == 0
    proposal_id = stored_proposal_id(proposal_store)

    set_caller(monkeypatch, CHECKER_ARN)
    assert ratify_command(
        ratify_args(proposal_id),
        grant_store=grant_store,
        record_store=record_store,
        proposal_store=proposal_store,
        signer=None,
        now=NOW,
    ) == 0

    out = capsys.readouterr().out
    # the checker is SHOWN the term it ratifies
    assert f"certifiedUntil={_TERM} (the grant lapses to 'in-loop' then)" in out
    raised = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    assert raised.certifiedUntil == _TERM
    assert record_store.records[-1].certifiedUntil == _TERM


def test_propose_refuses_a_malformed_term(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store, capsys
):
    grant_store.put_grant(make_grant(level=AutonomyLevel.in_loop))
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--certified-until": "2026-10-01T00:00:00"},  # naive: refused, not assumed
    ) == 1
    assert "REFUSED" in capsys.readouterr().out
    assert proposal_store.list_pending(PRINCIPAL, ACTION_CLASS) == []


def test_propose_refuses_to_anchor_on_an_unrecorded_lapse(
    monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store, capsys
):
    lapsed = make_grant(level=AutonomyLevel.on_loop).model_copy(
        update={"certifiedUntil": "2026-07-01T00:00:00+00:00"}  # before NOW
    )
    grant_store.put_grant(lapsed)
    seed_counters(enforcement_store)
    assert run_propose(
        monkeypatch, artifact_path, grant_store, proposal_store, enforcement_store,
        **{"--target-level": "out-of-loop"},
    ) == 1
    assert "lapse is not yet recorded" in capsys.readouterr().out
    assert proposal_store.list_pending(PRINCIPAL, ACTION_CLASS) == []


def test_reseed_carries_the_term_forward_unchanged(monkeypatch, grant_store):
    termed = make_grant(envelope_hash="sha256:old").model_copy(update={"certifiedUntil": _TERM})
    grant_store.put_grant(termed)
    set_caller(monkeypatch, CHECKER_ARN)
    assert reseed_command(
        grant_store=grant_store,
        principal=PRINCIPAL,
        granted_classes=[ACTION_CLASS],
        envelope_hash=ENVELOPE_HASH,
        now=NOW,
    ) == 0
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.certifiedUntil == _TERM
