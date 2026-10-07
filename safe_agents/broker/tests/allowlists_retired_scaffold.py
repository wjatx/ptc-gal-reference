"""Shared helpers for the tests of the retired `Envelope.allowlists` block (#135).

Not a test module. `test_envelope_allowlists_retired.py` pins the schema, the
stores and the hash; `test_envelope_allowlists_retired_paths.py` pins the
operator-facing paths (broker boot, the ceremony, the seed CLI, the audit).
Both name their invariant in every failure through these helpers.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator

import pytest
from pydantic import ValidationError

from safe_agents.broker.envelope import InMemoryEnvelopeStore
from safe_agents.broker.envelope.sqlite_store import SqliteEnvelopeStore
from safe_agents.broker.schemas import Envelope
from safe_agents.broker.tests.scaffold import PRINCIPAL

A1 = "A1 (the allowlists field is gone and refused by name)"
A2 = "A2 (retiring the field changes every envelope hash)"

PRINCIPAL_KEY = "#".join(PRINCIPAL.model_dump().values())

# What the refusal has to tell the operator. Each fragment is one clause of the
# invariant, so a message that loses one fails on that clause.
MESSAGE_CLAUSES = {
    "retired": "says the field was retired",
    "comes from its grants": "says what an agent may call comes from its grants",
    "#135": "names the issue",
}

# Every shape the key was ever written in. `None` is the one that matters most:
# it is what the old serializer stored for an envelope that never set the block.
RETIRED_VALUES = [
    pytest.param(None, id="null-as-the-old-serializer-wrote-it"),
    pytest.param({}, id="empty-block"),
    pytest.param({"tools": []}, id="empty-tools"),
    pytest.param({"tools": ["snapshot.read"]}, id="narrowed-tools"),
    pytest.param({"destinations": ["example.org"]}, id="extra-key-only"),
    pytest.param([], id="wrong-type"),
]


def assert_names_the_retirement(message: str, where: str) -> None:
    for fragment, clause in MESSAGE_CLAUSES.items():
        assert fragment in message, f"{A1}: the refusal at {where} no longer {clause}: {message!r}"


@contextmanager
def refusing_the_retired_key(
    where: str, *, raises: type[Exception] = ValidationError
) -> Iterator[SimpleNamespace]:
    """Assert the block refuses an input carrying the retired key, by name.

    `pytest.raises` reports a path that silently DROPS the key as a bare
    "DID NOT RAISE", which is the one outcome the ruling forbids and the one a
    reader most needs named. This reports it, and a refusal of the wrong kind,
    under the invariant. The yielded namespace carries the message afterwards.
    """
    caught = SimpleNamespace(message="")
    try:
        yield caught
    except raises as exc:
        caught.message = str(exc)
        assert_names_the_retirement(caught.message, where)
    except Exception as exc:  # noqa: BLE001 - any other failure is the wrong refusal
        pytest.fail(
            f"{A1}: {where} failed with {type(exc).__name__} and not the named "
            f"refusal of the retired key: {exc}"
        )
    else:
        pytest.fail(
            f"{A1}: {where} accepted an input that carries the retired allowlists "
            "key. The key must be refused loudly, never dropped or ignored."
        )


def stored_dump_before_retirement(envelope: Envelope, value: object = None) -> str:
    """The bytes the old serializer stored for `envelope`: today's dump plus
    the key the old model always wrote, null when the block was never set."""
    return json.dumps({**envelope.model_dump(mode="json"), "allowlists": value})


def in_memory_store_holding(stored: str) -> InMemoryEnvelopeStore:
    store = InMemoryEnvelopeStore()
    store._store[PRINCIPAL_KEY] = json.loads(stored)
    return store


def sqlite_store_holding(stored: str, tmp_path: Path) -> SqliteEnvelopeStore:
    store = SqliteEnvelopeStore(tmp_path / "floor.db")
    store.put_envelope(PRINCIPAL, Envelope(polarity="abstain"))
    conn = store._connection()
    pk, sk = store._item_key(PRINCIPAL)
    conn.execute(
        "UPDATE items SET item = ? WHERE pk = ? AND sk = ?",
        (json.dumps({"data": stored}), pk, sk),
    )
    conn.commit()
    return store


def envelope_row(stored: str) -> dict:
    """A raw grants-table item for the principal's envelope, as the audit reads it."""
    return {"pk": f"ENVELOPE#{PRINCIPAL_KEY}", "sk": "V0", "data": stored}
