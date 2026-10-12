"""The age of the airlock's fetched inputs (PTC §6.13, GAL §6.15, #176).

The airlock decides on three fetched inputs: the channels manifest (the trust
map), the webhook token, and the verification keys with their custody records.

  AS-OF    every drop and verdict record, and the acceptance log line, carries
           the instant each input was fetched, read before the fetch;
  HORIZON  and the earliest instant any of them passes its declared age;
  MAX-AGE  past a declared age the airlock fetches the input again before it
           decides, so a token or key withdrawn since the cold start stops
           working within that age;
  FAILED   a fetch that fails past the age decides nothing on the old input;
  OFF      with no age declared every input lasts the container, as before.

Drives the real handler with the hand-rolled AWS fakes of
`test_airlock_handler.py`; a hand-advanced clock stands in for elapsed time.
"""

# The `wired` and `verifying` fixtures are imported from the handler suite, so
# every test parameter that names one reads to ruff as a redefinition.
# ruff: noqa: F811

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import pydantic
import pytest

import safe_agents.channels.airlock.handler as h
from safe_agents.broker.schemas.common import MAX_DECLARABLE_AGE_SECONDS
from safe_agents.channels import keys as keys_mod
from safe_agents.channels.manifest import ChannelsManifest
from safe_agents.channels.tests.test_airlock_handler import (  # noqa: F401 - fixtures
    _MANIFEST_YAML,
    _TRANSIENT,
    _UNIFORM,
    _WEBHOOK_SECRET,
    _ZONE,
    _envelope_json,
    _event,
    _outbound,
    verifying,
    wired,
)

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
SEC = timedelta(seconds=1)


class _Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(h, "_now", c)
    return c


def _declare(monkeypatch: pytest.MonkeyPatch, tmp_path, ages: dict[str, int]) -> None:
    """Point the airlock at the test manifest with `ages` declared."""
    path = tmp_path / "aged-manifest.yaml"
    path.write_text(
        _MANIFEST_YAML + "input_max_age_seconds:\n"
        + "".join(f"  {name}: {seconds}\n" for name, seconds in ages.items()),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHANNELS_MANIFEST", str(path))
    monkeypatch.setattr(h, "_STATE", None)


def _records(wired, prefix: str = "channels/drops/") -> list[dict]:
    return [json.loads(put["Body"]) for put in wired.s3.puts if put["Key"].startswith(prefix)]


# ---------------------------------------------------------------------------
# AS-OF and OFF
# ---------------------------------------------------------------------------


def test_as_of_every_record_carries_the_instants_read_before_each_fetch(
    wired, clock, monkeypatch
) -> None:
    def _slow_token(arn: str) -> str:
        clock.now += 10 * SEC  # the fetch takes 10s; its stamp is the start
        return _WEBHOOK_SECRET

    monkeypatch.setattr(h, "_fetch_webhook_token", _slow_token)
    clock.now = T0
    h.handler(_event(_envelope_json(), token="wrong-token"), None)

    record = _records(wired)[-1]
    assert record["reason"] == "authenticity_failed"
    assert record["inputs_as_of"] == {"manifest": T0.isoformat(), "webhook_token": T0.isoformat()}
    assert record["horizon"] is None  # OFF: nothing declared


def test_as_of_the_verification_keys_are_stamped_before_their_fetch(verifying, clock, monkeypatch):
    wired, _ = verifying
    real_fetch = keys_mod._fetch_secret

    def _slow_keys(arn: str) -> str:
        clock.now += 7 * SEC
        return real_fetch(arn)

    monkeypatch.setattr(keys_mod, "_fetch_secret", _slow_keys)
    h.handler(_event(_outbound().to_wire()), None)  # unsigned: dropped at gate 3.5
    record = _records(wired)[-1]
    assert record["reason"] == "chain_signature_missing"
    assert record["inputs_as_of"]["verify_keys"] == T0.isoformat()


def test_as_of_the_acceptance_log_line_carries_the_instants(wired, clock, caplog) -> None:
    caplog.set_level(logging.INFO, logger=h.__name__)
    h.handler(_event(_envelope_json()), None)
    accepted = [
        json.loads(r.getMessage())
        for r in caplog.records
        if r.getMessage().startswith('{"event": "channel_accepted"')
    ]
    assert accepted[-1]["inputs_as_of"] == {
        "manifest": T0.isoformat(),
        "webhook_token": T0.isoformat(),
    }


def test_off_every_input_lasts_the_container(wired, clock, monkeypatch) -> None:
    h.handler(_event(_envelope_json("evt-1")), None)
    monkeypatch.setattr(h, "_fetch_webhook_token", lambda arn: json.dumps({"peer:example": "new"}))
    clock.now = T0 + 10**7 * SEC
    h.handler(_event(_envelope_json("evt-2")), None)
    assert len(wired.sqs.messages) == 2  # the cold-start token still admits


# ---------------------------------------------------------------------------
# MAX-AGE and HORIZON — the webhook token
# ---------------------------------------------------------------------------


def test_max_age_a_revoked_token_stops_admitting_at_its_age(
    wired, clock, monkeypatch, tmp_path
) -> None:
    _declare(monkeypatch, tmp_path, {"webhook_token": 60})
    h.handler(_event(_envelope_json("evt-1")), None)  # cold start at T0
    # The peer's token is rotated in Secrets Manager after the cold start.
    monkeypatch.setattr(h, "_fetch_webhook_token", lambda arn: json.dumps({"peer:example": "new"}))

    clock.now = T0 + 59 * SEC
    h.handler(_event(_envelope_json("evt-2")), None)
    assert len(wired.sqs.messages) == 2  # within its age the old token holds

    clock.now = T0 + 60 * SEC
    resp = h.handler(_event(_envelope_json("evt-3")), None)
    assert resp["body"] == _UNIFORM
    assert len(wired.sqs.messages) == 2  # not admitted on the old token
    record = _records(wired)[-1]
    assert record["reason"] == "authenticity_failed"
    assert record["inputs_as_of"]["webhook_token"] == (T0 + 60 * SEC).isoformat()
    assert record["horizon"] == (T0 + 120 * SEC).isoformat()


def test_failed_a_rebuild_past_the_age_decides_nothing_on_the_old_state(
    wired, clock, monkeypatch, tmp_path
) -> None:
    _declare(monkeypatch, tmp_path, {"manifest": 60})
    h.handler(_event(_envelope_json("evt-1")), None)

    def _down(arn: str) -> str:
        raise ConnectionError("secrets manager unreachable")

    monkeypatch.setattr(h, "_fetch_webhook_token", _down)
    clock.now = T0 + 60 * SEC
    resp = h.handler(_event(_envelope_json("evt-2")), None)
    assert (resp["statusCode"], resp["body"]) == (200, _UNIFORM)
    assert len(wired.sqs.messages) == 1  # nothing sent on the old state
    assert h._STATE is None  # the old state is gone, not kept for the next request


# ---------------------------------------------------------------------------
# MAX-AGE — the verification keys
# ---------------------------------------------------------------------------


def test_max_age_a_withdrawn_key_stops_verifying_at_its_age(
    verifying, clock, monkeypatch, tmp_path
) -> None:
    wired, signer = verifying
    _declare(monkeypatch, tmp_path, {"verify_keys": 60})
    h.handler(_event(_outbound(signer, event_id="evt-1").to_wire()), None)  # cold start at T0
    assert len(wired.sqs.messages) == 1

    # broker:A is withdrawn from the key map; another key replaces it.
    enrolled = json.loads(keys_mod._fetch_secret("arn:verify"))
    monkeypatch.setattr(
        keys_mod, "_fetch_secret", lambda arn: json.dumps({"broker:B": enrolled["broker:A"]})
    )

    clock.now = T0 + 59 * SEC
    h.handler(_event(_outbound(signer, event_id="evt-2").to_wire()), None)
    assert len(wired.sqs.messages) == 2  # within its age the loaded key holds

    clock.now = T0 + 60 * SEC
    h.handler(_event(_outbound(signer, event_id="evt-3").to_wire()), None)
    assert len(wired.sqs.messages) == 2
    record = _records(wired)[-1]
    assert record["reason"] == "chain_signer_unknown"
    assert record["inputs_as_of"]["verify_keys"] == (T0 + 60 * SEC).isoformat()
    assert record["horizon"] == (T0 + 120 * SEC).isoformat()


def test_failed_a_key_refetch_past_the_age_is_transient_never_the_old_key(
    verifying, clock, monkeypatch, tmp_path
) -> None:
    wired, signer = verifying
    _declare(monkeypatch, tmp_path, {"verify_keys": 60})
    h.handler(_event(_outbound(signer, event_id="evt-1").to_wire()), None)

    def _down(arn: str) -> str:
        raise ConnectionError("secrets manager unreachable")

    monkeypatch.setattr(keys_mod, "_fetch_secret", _down)
    clock.now = T0 + 60 * SEC
    resp = h.handler(_event(_outbound(signer, event_id="evt-2").to_wire()), None)
    assert resp["body"] == _TRANSIENT
    assert len(wired.sqs.messages) == 1
    record = _records(wired)[-1]
    assert (record["reason"], record["detail"]) == ("not_evaluated", "key_source")
    assert "verify_keys" not in record["inputs_as_of"]  # no key in use


# ---------------------------------------------------------------------------
# The knob: closed vocabulary, positive and bounded, empty by default
# ---------------------------------------------------------------------------


def test_knob_defaults_to_no_declared_age() -> None:
    assert ChannelsManifest(zone=_ZONE).input_max_age_seconds == {}


@pytest.mark.parametrize(
    "bad",
    [
        {"webhook_token": 0},
        {"verify_keys": -1},
        {"manifest": MAX_DECLARABLE_AGE_SECONDS + 1},
        {"manifest": True},
        {"trust_map": 60},
    ],
)
def test_knob_refuses_a_bad_declaration(bad) -> None:
    with pytest.raises(pydantic.ValidationError):
        ChannelsManifest(zone=_ZONE, input_max_age_seconds=bad)


def test_record_refuses_a_naive_instant() -> None:
    from safe_agents.channels.trust_map import make_drop_record

    record = make_drop_record("webhook", "peer:example", "unmapped", T0.isoformat())
    with pytest.raises(pydantic.ValidationError):
        type(record).model_validate(
            {**record.model_dump(), "inputs_as_of": {"manifest": "2026-10-01T12:00:00"}}
        )

