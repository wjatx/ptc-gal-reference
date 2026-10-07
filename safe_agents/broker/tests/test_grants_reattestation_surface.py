"""Re-attestation appends a record: nothing else rewrites a grant.

#164; GAL §6.6, GAL-15.

R8 (no other same-level write exists, on the state machine, in the stores, or
anywhere in shipped code) and R9 (`re-seed`'s refusals hold and write
nothing).

The clause table and the shared harness are in reattestation_scaffold.py.
"""

from __future__ import annotations

import ast
from pathlib import Path

from safe_agents.broker.grants.rung import RungStateMachine
from safe_agents.broker.tests import reattestation_scaffold as harness
from safe_agents.broker.tests.reattestation_scaffold import (
    ACTION_CLASS,
    OLD_HASH,
    PRINCIPAL,
    _ledger,
    _reattestations,
    _refused,
    _reseed,
    _seed,
)

#: The three-backend fixture, re-bound so pytest resolves it by name here too.
backend = harness.backend


# ===========================================================================
# R8 — no other same-level write
# ===========================================================================


# The store primitives that write a grant with no record beside it. Only
# put_grant exists: the conditional record-less update is gone from every
# store. Its name stays on the list so a path reaching for it by any spelling
# is seen before the store that would have to grow it back.
_RECORD_LESS_WRITES = ("put_grant", "update_grant")

# Every place shipped code names one, by path under safe_agents/. The first
# is a create: the memory store's create_grant delegating after its
# not-exists check. The second is NOT sanctioned by GAL §6.6 and is listed so
# that it stays the only one: the prototype server's seed mode is a blind
# upsert with no ledger counterpart, tracked as #27.
_KNOWN_RECORD_LESS_WRITES = [
    "broker/grants/store.py:put_grant",
    "broker/prototype/broker_server.py:put_grant",
]

# The state machine's whole write surface. Each of these appends the record
# that accounts for its grant write.
_STATE_MACHINE_WRITES = {"promote", "demote", "tighten_to_in_loop"}


def _record_less_write_references() -> list[str]:
    """Every reference to a record-less grant write in the shipped package.

    A reference is an attribute access (called or not, so a bound method
    passed around counts) or the bare name as a string constant (so
    ``getattr(store, "put_grant")`` counts). Tests are excluded: they plant
    grants out of band on purpose.
    """
    import safe_agents

    package_dir = Path(safe_agents.__file__).parent
    found = []
    for path in sorted(package_dir.rglob("*.py")):
        relative = path.relative_to(package_dir)
        if "tests" in relative.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr in _RECORD_LESS_WRITES:
                found.append(f"{relative.as_posix()}:{node.attr}")
            elif isinstance(node, ast.Constant) and node.value in _RECORD_LESS_WRITES:
                found.append(f"{relative.as_posix()}:{node.value}")
    return found


class TestR8NoOtherSameLevelWrite:
    def test_the_state_machine_has_no_same_level_path(self):
        assert not hasattr(RungStateMachine, "re_ratify")

    def test_the_state_machine_s_write_surface_is_closed(self):
        """An allowlist, so a same-level rewrite added under ANY name fails
        here until someone shows it appends a record and lists it."""
        public = {
            name
            for name, member in vars(RungStateMachine).items()
            if callable(member) and not name.startswith("_")
        }
        assert public == _STATE_MACHINE_WRITES, (
            "I8 NO OTHER SAME-LEVEL WRITE: the state machine's public surface changed "
            f"({sorted(public ^ _STATE_MACHINE_WRITES)}). A new path must append the "
            "record that accounts for its grant write, and nothing may rewrite a grant "
            "at an unchanged level outside re-attestation (GAL §6.6)"
        )

    def test_no_store_carries_a_record_less_update(self):
        from safe_agents.broker.grants.sqlite_store import SqliteGrantStore
        from safe_agents.broker.grants.store import (
            DynamoDBGrantStore,
            GrantStore,
            InMemoryGrantStore,
        )

        for store_type in (GrantStore, InMemoryGrantStore, SqliteGrantStore, DynamoDBGrantStore):
            assert not hasattr(store_type, "update_grant"), (
                f"I8 NO OTHER SAME-LEVEL WRITE: {store_type.__name__} carries a "
                "record-less conditional grant update again"
            )

    def test_nothing_shipped_reaches_for_a_record_less_grant_write(self):
        assert _record_less_write_references() == _KNOWN_RECORD_LESS_WRITES, (
            "I8 NO OTHER SAME-LEVEL WRITE: shipped code names a record-less grant "
            "write outside the two known sites. A write to an existing grant goes "
            "through write_record_and_grant, with its record"
        )


# ===========================================================================
# R9 — re-seed's refusals write nothing
# ===========================================================================


class TestR9RefusalsPreserved:
    def test_a_store_layer_quarantine_is_refused_and_nothing_is_written(
        self, backend, monkeypatch, capsys
    ):
        _seed(backend, monkeypatch)
        backend.tamper_grant_data()
        tampered = backend.raw_grant_data()

        said = _refused(
            backend, monkeypatch, "I9 REFUSALS PRESERVED (a store-layer quarantine is a failure)"
        )

        assert "NEVER re-attestable" in said
        assert backend.raw_grant_data() == tampered  # the evidence survives
        assert backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).quarantined
        assert _reattestations(backend) == []

    def test_a_missing_grant_fails_and_nothing_is_written(self, backend, monkeypatch, capsys):
        said = _refused(
            backend, monkeypatch, "I9 REFUSALS PRESERVED (a missing grant is a failure)"
        )

        assert "bootstrap it with `seed`" in said
        assert backend.raw_grant_data() is None
        assert _ledger(backend) == []

    def test_a_grant_already_under_the_in_force_hash_is_skipped_with_no_record(
        self, backend, monkeypatch, capsys
    ):
        current = _seed(backend, monkeypatch)

        rc, _ = _reseed(backend, monkeypatch, envelope_hash=OLD_HASH)

        assert rc == 0, "I9 REFUSALS PRESERVED: a grant already in force is a skip, not a failure"
        assert "nothing to re-attest" in capsys.readouterr().out
        assert backend.raw_grant_data() == current.raw_data
        assert [r.recordType for r in _ledger(backend)] == ["bootstrap"]
