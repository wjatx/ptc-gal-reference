"""Tests for the Envelope liveness contract + deterministic monitor (sa#160).

Three concerns:
  1. The `Liveness` schema validates/rejects correctly and carries into the
     envelope hash (it is authority, tied to the envelope in force).
  2. `Liveness.overdue()` is a pure, deterministic timestamp predicate — no
     model, exercised across the window boundary and the never-seen case.
  3. **Safe-by-default + polarity-absent** — the load-bearing invariant. An
     `act`-polarity Envelope does NOT auto-enable liveness; `liveness` is None
     unless explicitly set. The polarity->default derivation lives ONLY in the
     consumer example, never in the base schema.
  4. The consumer example (`examples/liveness_policy.py`) derives the default
     from polarity and honors a per-agent override.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from safe_agents.broker.schemas.envelope import (
    Envelope,
    Liveness,
    compute_envelope_hash,
)


# ---------------------------------------------------------------------------
# 1. Liveness schema
# ---------------------------------------------------------------------------

def test_liveness_validates() -> None:
    lv = Liveness.model_validate({"expected_op": "notify.send", "deadline_seconds": 900})
    assert lv.expected_op == "notify.send"
    assert lv.deadline_seconds == 900


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param({"expected_op": "notify.send", "deadline_seconds": 0}, id="zero_deadline"),
        pytest.param({"expected_op": "notify.send", "deadline_seconds": -5}, id="negative_deadline"),
        pytest.param({"deadline_seconds": 900}, id="missing_expected_op"),
        pytest.param({"expected_op": "notify.send"}, id="missing_deadline"),
        pytest.param(
            {"expected_op": "notify.send", "deadline_seconds": 900, "extra": 1},
            id="extra_forbidden",
        ),
    ],
)
def test_liveness_rejects_invalid(bad: dict) -> None:
    with pytest.raises(ValidationError):
        Liveness.model_validate(bad)


def test_liveness_is_part_of_envelope_hash() -> None:
    """Adding/altering the liveness contract changes the envelope hash — the
    contract is authority, bound to the envelope in force."""
    base = Envelope.model_validate({"polarity": "act"})
    with_lv = Envelope.model_validate(
        {"polarity": "act", "liveness": {"expected_op": "notify.send", "deadline_seconds": 900}}
    )
    tighter = Envelope.model_validate(
        {"polarity": "act", "liveness": {"expected_op": "notify.send", "deadline_seconds": 60}}
    )
    hashes = {
        compute_envelope_hash(base),
        compute_envelope_hash(with_lv),
        compute_envelope_hash(tighter),
    }
    assert len(hashes) == 3  # all distinct


def test_liveness_hash_stable_round_trip() -> None:
    env = Envelope.model_validate(
        {"polarity": "act", "liveness": {"expected_op": "notify.send", "deadline_seconds": 900}}
    )
    digest = compute_envelope_hash(env)
    reloaded = Envelope.model_validate(env.model_dump(mode="json"))
    assert compute_envelope_hash(reloaded) == digest


# ---------------------------------------------------------------------------
# 2. The deterministic monitor predicate
# ---------------------------------------------------------------------------

_LV = Liveness(expected_op="notify.send", deadline_seconds=900)


@pytest.mark.parametrize(
    "last_seen_epoch,now_epoch,expected_overdue",
    [
        # within the window -> not overdue
        pytest.param(1_000.0, 1_000.0 + 899, False, id="just_inside"),
        pytest.param(1_000.0, 1_000.0 + 900, False, id="exactly_at_deadline"),
        # past the window -> overdue
        pytest.param(1_000.0, 1_000.0 + 901, True, id="just_past"),
        pytest.param(1_000.0, 1_000.0 + 10_000, True, id="long_past"),
        # never seen -> overdue
        pytest.param(None, 1_000.0, True, id="never_seen"),
    ],
)
def test_overdue_is_deterministic_boundary(
    last_seen_epoch, now_epoch, expected_overdue
) -> None:
    assert _LV.overdue(last_seen_epoch=last_seen_epoch, now_epoch=now_epoch) is expected_overdue


def test_overdue_is_pure_no_side_channel() -> None:
    """Same inputs -> same output, repeatably (no clock/model in the path)."""
    args = {"last_seen_epoch": 1_000.0, "now_epoch": 1_950.0}
    assert _LV.overdue(**args) == _LV.overdue(**args) is True


# ---------------------------------------------------------------------------
# 3. Safe-by-default + polarity-absent (the load-bearing invariant)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("polarity", ["act", "abstain"])
def test_envelope_liveness_unset_is_off_regardless_of_polarity(polarity: str) -> None:
    """Neither polarity auto-enables liveness in the BASE. Unset stays None —
    the polarity->default derivation is not a base behavior."""
    env = Envelope.model_validate({"polarity": polarity})
    assert env.liveness is None


def test_base_schema_has_no_polarity_liveness_coupling() -> None:
    """Two envelopes differing ONLY in polarity have identical liveness (None) —
    the base does not derive a liveness default from polarity."""
    act = Envelope.model_validate({"polarity": "act"})
    abstain = Envelope.model_validate({"polarity": "abstain"})
    assert act.liveness is None and abstain.liveness is None


# ---------------------------------------------------------------------------
# 4. Consumer-side derivation (examples/liveness_policy.py)
# ---------------------------------------------------------------------------

def test_consumer_act_safe_defaults_liveness_on() -> None:
    from examples.liveness_policy import resolve_liveness

    lv = resolve_liveness("act")
    assert lv is not None
    assert lv.expected_op == "notify.send"
    assert lv.deadline_seconds > 0


def test_consumer_abstain_safe_defaults_liveness_off() -> None:
    from examples.liveness_policy import resolve_liveness

    assert resolve_liveness("abstain") is None


def test_consumer_override_turns_abstain_agent_on() -> None:
    from examples.liveness_policy import resolve_liveness

    override = Liveness(expected_op="ledger.append", deadline_seconds=3600)
    assert resolve_liveness("abstain", override=override) is override


def test_consumer_override_can_loosen_act_agent() -> None:
    from examples.liveness_policy import resolve_liveness

    override = Liveness(expected_op="notify.send", deadline_seconds=7200)
    resolved = resolve_liveness("act", override=override)
    assert resolved is override
    assert resolved.deadline_seconds == 7200  # departs from the tight default
