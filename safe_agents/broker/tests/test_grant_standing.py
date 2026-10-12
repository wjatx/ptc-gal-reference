"""The enforcer's issuer standing and the withdrawal runner (GAL §6.10, GAL-41, #179).

What this file pins, in four groups:

  fall        a grant whose level rests on a withdrawn issuer key acts at the
              lower of its level and lastSafeLevel, through the real PIP, and
              says why once; a retired key keeps its standing; the fall never
              raises a level below lastSafeLevel
  age         standing past the document's maximum age is not established, the
              age runs from the earlier of issuedAt and the fetch, and the age
              lowers a level and never refuses the decision (#176's machinery)
  key         the key behind a level is the verified signer of the last
              licensing record, cached on the grant's ts; unsigned history
              before the record-signing epoch is not "not established"; an
              evaluator key's withdrawal changes no enforced level
  runner      a withdrawal appends a ``withdrawal`` record and lowers the stored
              grant; nothing is written for "not established"
"""

from __future__ import annotations

import ast
import datetime
import json
from pathlib import Path

import pytest

from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.grants import grant_standing as gs
from safe_agents.broker.grants import key_standing as ks
from safe_agents.broker.grants.grant_standing import GrantStandingCheck
from safe_agents.broker.grants.record_signing import canonical_record_payload
from safe_agents.broker.grants.term import effective_level
from safe_agents.broker.grants.withdrawal import run_withdrawal
from safe_agents.broker.prototype.broker_server import _make_pip
from safe_agents.broker.runtime.input_age import DecisionInputs, InputAgePolicy
from safe_agents.broker.schemas.clock_skew import skew_bound
from safe_agents.broker.tests.grant_standing_scaffold import (
    HOUR,
    IN,
    MAX_AGE,
    ON,
    OUT,
    PROMOTION_TS,
    T0,
    World,
    grant,
    record,
)
from safe_agents.broker.tests import test_grant_term_lapse as lapse_base
from safe_agents.broker.tests.test_grant_term_lapse import (
    ACTION_CLASS,
    COUNTER_CAP,
    ENV_HASH,
    PRINCIPAL,
    _call,
)

MINUTE = datetime.timedelta(minutes=1)


@pytest.fixture
def world():
    return World()


def _facts(world, check, *, at=None):
    pip = _make_pip(
        world.grants, InMemoryStore(), COUNTER_CAP, ENV_HASH,
        clock=lambda: at or world.clock.now, standing_check=check,
    )
    facts = pip(_call())
    assert facts.grant_present and not facts.quarantined
    return facts


# ---------------------------------------------------------------------------
# Fall
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reason", ["keyCompromise", "privilegeWithdrawn"])
def test_a_withdrawn_issuer_key_lowers_the_grant_through_the_real_pip(world, reason):
    world.promoted()
    check = world.check()
    assert _facts(world, check).grant_level is ON
    world.clock.now += MINUTE
    # Withdrawn AFTER the promotion was signed: a withdrawal voids it whatever its ts.
    world.withdraw(reason=reason)
    check.refresh(world.clock.now)
    facts = _facts(world, check)
    assert facts.grant_level is IN, "GAL-41: a withdrawn key's grant acts at lastSafeLevel"
    assert facts.standing_fall_reason.startswith(gs.FALL_KEY_WITHDRAWN)
    assert "issuer-a" in facts.standing_fall_reason and reason in facts.standing_fall_reason
    # The stored grant is untouched: the enforcer writes nothing.
    assert world.stored_grant().level is ON


def test_a_retired_key_keeps_the_grants_it_signed(world):
    world.promoted()
    check = world.check()
    world.clock.now += MINUTE
    world.retire()
    check.refresh(world.clock.now)
    facts = _facts(world, check)
    assert facts.grant_level is ON, "GAL-41: rotation does not lower the grants a key signed"
    assert facts.standing_fall_reason is None


def test_a_grant_whose_key_stays_in_standing_keeps_its_level(world):
    world.promoted()
    check = world.check()
    world.clock.now += MINUTE
    world.withdraw("issuer-b")
    check.refresh(world.clock.now)
    assert _facts(world, check).grant_level is ON


@pytest.mark.parametrize(
    ("level", "last_safe", "expected"),
    [
        (ON, IN, IN),      # the ordinary fall
        (IN, ON, IN),      # demoted below lastSafeLevel: the fall never raises it
        (OUT, ON, ON),
        (IN, IN, IN),
    ],
)
def test_the_fall_is_to_the_lower_of_the_level_and_last_safe_level(level, last_safe, expected):
    g = grant(level=level, lastSafeLevel=last_safe)
    assert effective_level(g, T0, standing_held=False) is expected
    assert effective_level(g, T0, standing_held=True) is level


def test_the_pip_is_unchanged_without_a_standing_check(world):
    world.promoted()
    world.withdraw()
    pip = _make_pip(world.grants, InMemoryStore(), COUNTER_CAP, ENV_HASH, clock=world.clock)
    facts = pip(_call())
    assert (facts.grant_level, facts.standing_fall_reason) == (ON, None)


def test_a_replayed_older_document_does_not_restore_the_level(world):
    world.promoted()
    check = world.check()
    check.refresh(world.clock.now)
    first = world.served["text"]
    world.clock.now += MINUTE
    world.withdraw()
    check.refresh(world.clock.now)
    world.served["text"] = first
    load = check.refresh(world.clock.now)
    assert not load.accepted
    assert _facts(world, check).grant_level is IN


def test_an_unsigned_document_is_not_standing_and_the_grant_falls(world):
    world.promoted()
    envelope = json.loads(ks.sign_standing_document(world.document, world.authority))
    envelope["signatures"] = []
    world.served["text"] = json.dumps(envelope)
    check = world.check()
    assert not check.refresh(world.clock.now).accepted
    facts = _facts(world, check)
    assert facts.grant_level is IN
    assert facts.standing_fall_reason.startswith(gs.FALL_NOT_ESTABLISHED)


# ---------------------------------------------------------------------------
# Age
# ---------------------------------------------------------------------------


def test_standing_past_its_maximum_age_is_not_established(world):
    world.promoted()
    check = world.check(refresh_every=1000 * HOUR)  # no lazy refetch in this test
    check.refresh(world.clock.now)
    # as-of = issuedAt (T0), earlier than the fetch (T0 + 5 min): the horizon is T0 + age.
    assert _facts(world, check, at=T0 + MAX_AGE - MINUTE).grant_level is ON
    late = _facts(world, check, at=T0 + MAX_AGE)
    assert late.grant_level is IN
    assert late.standing_fall_reason.startswith(gs.FALL_NOT_ESTABLISHED)
    assert "past its maximum age" in late.standing_fall_reason


def test_the_age_runs_from_issued_at_not_the_fetch(world):
    world.promoted()
    world.clock.now = T0 + 3 * HOUR  # fetched three hours after it was issued
    check = world.check(refresh_every=1000 * HOUR)
    check.refresh(world.clock.now)
    # Judged from the fetch it would hold until T0 + 7h; from issuedAt it ends at T0 + 4h.
    assert _facts(world, check, at=T0 + MAX_AGE + MINUTE).grant_level is IN


def test_a_skew_bound_ends_standing_earlier(world):
    world.promoted()
    check = world.check(refresh_every=1000 * HOUR, skew=skew_bound(600))
    check.refresh(world.clock.now)
    assert _facts(world, check, at=T0 + MAX_AGE - 5 * MINUTE).grant_level is IN


def test_the_document_is_refetched_lazily_and_a_fresh_one_restores_standing(world):
    world.promoted()
    check = world.check()  # refresh every quarter of the age
    check.refresh(world.clock.now)
    world.clock.now = T0 + MAX_AGE + MINUTE
    # Refetched on this call: the same bytes, so the same as-of, still past its age.
    assert _facts(world, check).grant_level is IN
    world.publish(dict(world.document.keys), at=world.clock.now)  # the authority reissues
    world.clock.now += MAX_AGE / 4
    assert _facts(world, check).grant_level is ON, "standing recovers with no write"


def test_the_age_lowers_and_never_refuses_and_rides_on_the_decision(world):
    world.promoted()
    check = world.check(refresh_every=1000 * HOUR)
    check.refresh(world.clock.now)
    late = T0 + MAX_AGE + MINUTE
    policy = InputAgePolicy(lowering={"issuer_standing": MAX_AGE})
    inputs = DecisionInputs(policy, lambda: late)
    pip = _make_pip(world.grants, InMemoryStore(), COUNTER_CAP, ENV_HASH,
                    clock=lambda: late, standing_check=check)
    facts = inputs.timed(pip, ("grant",))(_call())
    assert facts.grant_level is IN
    fields = inputs.audit_fields()
    assert fields["inputs_as_of"]["issuer_standing"] == T0.isoformat()
    assert fields["horizon"] == (T0 + MAX_AGE).isoformat()
    assert inputs.stale(late) == [], "issuer_standing past its age lowers; it never refuses"


# ---------------------------------------------------------------------------
# The key behind a level
# ---------------------------------------------------------------------------


class _CountingRecords:
    def __init__(self, inner, fail=False):
        self.inner, self.calls, self.fail = inner, 0, fail

    def list_stored_records(self, principal, action_class, session=None):
        self.calls += 1
        if self.fail:
            raise PermissionError("denied")
        return self.inner.list_stored_records(principal, action_class)


def test_the_key_is_read_once_per_grant_write(world):
    world.promoted()
    counting = _CountingRecords(world.records)
    check = GrantStandingCheck(source=world.source, records=counting)
    check.refresh(world.clock.now)
    for _ in range(3):
        assert check.assess(world.stored_grant(), world.clock.now).held
    assert counting.calls == 1
    world.write(record("reattestation", "2026-09-03T00:00:00+00:00"),
                grant(ts="2026-09-03T00:00:00+00:00", promotedBy="op"), signer="issuer-b")
    assert check.assess(world.stored_grant(), world.clock.now).held
    assert counting.calls == 2


def test_an_error_inside_the_check_is_a_fall_and_never_a_pass(world):
    world.promoted()
    check = world.check()
    check.refresh(world.clock.now)

    def boom(*args, **kwargs):
        raise RuntimeError("broken")

    check.source.standing_of = boom
    assessment = check.assess(world.stored_grant(), world.clock.now)
    assert not assessment.held
    assert assessment.reason == f"{gs.FALL_NOT_ESTABLISHED}: the standing check failed (RuntimeError)"


def test_an_unreadable_ledger_falls_and_is_not_cached(world):
    world.promoted()
    counting = _CountingRecords(world.records, fail=True)
    check = GrantStandingCheck(source=world.source, records=counting)
    check.refresh(world.clock.now)
    first = check.assess(world.stored_grant(), world.clock.now)
    assert not first.held and "could not be read" in first.reason
    counting.fail = False
    assert check.assess(world.stored_grant(), world.clock.now).held


def test_a_reattestation_after_the_promotion_is_the_record_the_level_rests_on(world):
    world.promoted()
    world.write(record("reattestation", "2026-09-03T00:00:00+00:00"),
                grant(ts="2026-09-03T00:00:00+00:00", promotedBy="op"), signer="issuer-b")
    check = world.check()
    world.clock.now += MINUTE
    world.withdraw("issuer-b")
    check.refresh(world.clock.now)
    assessment = check.assess(world.stored_grant(), world.clock.now)
    assert not assessment.held and "issuer-b" in assessment.reason


def test_an_evaluator_record_after_the_promotion_moves_no_key(world):
    """An evaluator key's withdrawal changes no enforced level (the #179 ruling).

    The latest record is a demotion signed by the evaluator. If the enforcer
    took the key from the latest record of any type, it would ask the issuer's
    document about an evaluator key and fall."""
    world.promoted()
    world.write(record("demotion", "2026-09-03T00:00:00+00:00", fromLevel=ON, toLevel=ON),
                grant(ts="2026-09-03T00:00:00+00:00"), signer="evaluator")
    check = world.check()
    check.refresh(world.clock.now)
    assert check.assess(world.stored_grant(), world.clock.now).held
    with pytest.raises(ValueError, match="evaluator key's withdrawal"):
        GrantStandingCheck(source=world.evaluator_source(withdrawn=True), records=world.records)


def test_a_tampered_licensing_record_leaves_standing_not_established(world):
    world.promoted()
    key = next(k for k in world.records._records if k[1].endswith("#promotion"))
    data, signature = world.records._records[key]
    world.records._records[key] = (data.replace("maker-alice", "maker-mallory"), signature)
    check = world.check()
    check.refresh(world.clock.now)
    assessment = check.assess(world.stored_grant(), world.clock.now)
    assert not assessment.held and gs.FALL_NOT_ESTABLISHED in assessment.reason


def test_a_key_the_document_adds_later_is_picked_up_by_the_next_version(world):
    world.promoted(signer="issuer-c")  # issuer-c is not in version 1
    check = world.check()
    check.refresh(world.clock.now)
    assert not check.assess(world.stored_grant(), world.clock.now).held
    world.clock.now += MINUTE
    world.publish(ks.add_key(world.document.keys, "issuer-c", world.keys["issuer-c"][1]),
                  at=world.clock.now)
    check.refresh(world.clock.now)
    assert check.assess(world.stored_grant(), world.clock.now).held


@pytest.mark.parametrize(
    ("epoch", "held"),
    [
        (None, True),                                   # no epoch: unsigned is history
        (datetime.datetime(2026, 9, 10, tzinfo=datetime.UTC), True),   # before the epoch
        (datetime.datetime(2026, 9, 1, 12, tzinfo=datetime.UTC), False),  # at or after it
    ],
)
def test_unsigned_history_before_the_epoch_is_not_unestablished(world, epoch, held):
    world.promoted(signer=None, bootstrap_signer=None)
    check = world.check(signing_epoch=epoch)
    check.refresh(world.clock.now)
    assert check.assess(world.stored_grant(), world.clock.now).held is held


def test_the_epoch_is_judged_with_the_skew_toward_less_authority(world):
    world.promoted(signer=None, bootstrap_signer=None)
    promoted_at = datetime.datetime.fromisoformat(PROMOTION_TS)
    check = world.check(signing_epoch=promoted_at + MINUTE, skew=skew_bound(120))
    check.refresh(world.clock.now)
    assert not check.assess(world.stored_grant(), world.clock.now).held


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


def _run(world, **kwargs):
    world.source.refresh()
    return run_withdrawal(
        PRINCIPAL, ACTION_CLASS, grant_store=world.grants, record_store=world.records,
        standing=world.source, now=world.clock.now, **kwargs,
    )


def test_the_runner_records_a_withdrawal_and_lowers_the_grant(world):
    world.promoted()
    world.clock.now += MINUTE
    world.withdraw()
    outcome = _run(world, record_signer=world.evaluator)
    assert outcome.status == "lowered"
    assert outcome.record.recordType == "withdrawal"
    assert (outcome.record.fromLevel, outcome.record.toLevel) == (ON, IN)
    assert outcome.record.triggeredBy == [] and outcome.record.demotionReason == "pending-evidence"
    stored = world.stored_grant()
    assert (stored.level, stored.ts) == (IN, outcome.record.ts)
    (last,) = [r for r in world.records.records if r.recordType == "withdrawal"]
    assert world.records.signature_for(last)["signatures"][0]["keyid"] == "evaluator-e"
    assert _run(world).status == "nothing-to-lower"


@pytest.mark.parametrize(
    ("change", "status"),
    [
        ("none", "in-standing"),
        ("retire", "in-standing"),
        ("stale", "not-established"),
    ],
)
def test_the_runner_writes_nothing_unless_the_key_is_withdrawn(world, change, status):
    world.promoted()
    if change == "retire":
        world.clock.now += MINUTE
        world.retire()
    world.source.refresh()
    if change == "stale":
        world.clock.now = T0 + MAX_AGE + MINUTE
        world.served["text"] = "unreadable"
    before = len(world.records.records)
    outcome = run_withdrawal(
        PRINCIPAL, ACTION_CLASS, grant_store=world.grants, record_store=world.records,
        standing=world.source, now=world.clock.now,
    )
    assert outcome.status == status
    assert len(world.records.records) == before
    assert world.stored_grant().level is ON


def test_the_runner_ignores_an_evaluator_record_after_the_promotion(world):
    world.promoted()
    world.write(record("demotion", "2026-09-03T00:00:00+00:00", fromLevel=ON, toLevel=ON),
                grant(ts="2026-09-03T00:00:00+00:00"), signer="evaluator")
    assert _run(world).status == "in-standing"


# ---------------------------------------------------------------------------
# Every backend reads a ledger as stored, and the runner writes through it
# ---------------------------------------------------------------------------

#: The three-backend fixture (memory, sqlite, DynamoDB under moto), re-bound by name.
stores = lapse_base.stores


def test_every_backend_returns_records_as_stored_and_the_runner_lowers_through_it(world, stores):
    grant_store, record_store = stores
    world.grants, world.records = grant_store, record_store
    world.promoted()
    stored = record_store.list_stored_records(PRINCIPAL, ACTION_CLASS)
    assert [s.record.recordType for s in stored] == ["bootstrap", "promotion"]
    assert all(isinstance(s.signature, dict) for s in stored)
    assert stored[1].data == canonical_record_payload(stored[1].record)

    world.clock.now += MINUTE
    world.withdraw()
    check = world.check()
    check.refresh(world.clock.now)
    assert not check.assess(world.stored_grant(), world.clock.now).held
    outcome = _run(world, record_signer=world.evaluator)
    assert outcome.status == "lowered"
    assert world.stored_grant().level is IN
    assert [s.record.recordType for s in record_store.list_stored_records(
        PRINCIPAL, ACTION_CLASS)] == ["bootstrap", "promotion", "withdrawal"]


def test_the_enforcers_standing_input_names_no_store():
    """The document the enforcer trusts is deploy-bound (grants/standing_keys.py).

    grant_standing reads records through an injected reader and never imports a
    store, the envelope store or anything ceremony-side, so no store row can
    become the source a grant's standing is judged against."""
    tree = ast.parse(Path(gs.__file__).read_text(encoding="utf-8"))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(
        name and any(part in name for part in ("store", "ceremony", "proposals", "envelope"))
        for name in imported
    ), imported


@pytest.mark.parametrize(
    ("withdraw", "code", "level"),
    [(True, 0, IN), (False, 1, ON)],  # a document far past its age: not established, exit 1
)
def test_runner_main_runs_the_withdrawal_pass_first(world, monkeypatch, tmp_path, capsys,
                                                    withdraw, code, level):
    from safe_agents.broker.grants import issuer_keys, runner

    for role_env in issuer_keys.ALL_ROLE_ENVS:
        for name in issuer_keys.role_env_names(role_env):
            monkeypatch.delenv(name, raising=False)
    world.promoted()
    if withdraw:
        world.clock.now += MINUTE
        world.withdraw()
    doc_file = tmp_path / "issuer-standing.json"
    doc_file.write_text(world.served["text"], encoding="utf-8")
    authority_file = tmp_path / "authority.json"
    authority_file.write_text(json.dumps({"authority-1": world.authority_pem}), encoding="utf-8")
    monkeypatch.setenv(issuer_keys.ISSUER_STANDING_FILE_ENV, str(doc_file))
    monkeypatch.setenv(issuer_keys.ISSUER_STANDING_MAX_AGE_SECONDS_ENV, "3600")
    monkeypatch.setenv(issuer_keys.STANDING_AUTHORITY_VERIFY_KEYS_FILE_ENV, str(authority_file))
    monkeypatch.setattr(runner, "_build_stores", lambda table: (world.grants, world.records))
    monkeypatch.setattr(issuer_keys, "resolve_evaluator_signer", lambda: world.evaluator)
    rc = runner.main([
        "--principal-agent-id", PRINCIPAL.agentId, "--skill", PRINCIPAL.skill,
        "--user", PRINCIPAL.user, "--tier", PRINCIPAL.tier, "--action-class", ACTION_CLASS,
    ])
    out = capsys.readouterr().out
    assert rc == code, out
    assert '"event": "withdrawal_runner"' in out
    assert world.stored_grant().level is level
