"""Envelope store client — Phase 3 Slice A of the broker-destub epic (sa#136).

Protocol + InMemoryEnvelopeStore (for tests) + DynamoDBEnvelopeStore
(production). Mirrors broker/grants/store.py's shape, with one deliberate
difference: no HMAC.

Design notes:
- No HMAC on the envelope record. Unlike a Grant, an Envelope's integrity is
  enforced downstream by grant hash-binding: every Grant carries the
  envelopeHash it was minted against (schemas/envelope.py::compute_envelope_hash).
  A tampered stored envelope changes that hash, which then fails to match any
  existing Grant — the tampered envelope can shift what the PDP evaluates
  against, but it can never itself mint new authority; a mismatch is a deny,
  not a bypass. See schemas/envelope.py's module docstring.
- Co-located in the SAME DynamoDB table as grants, as a distinct item type —
  matching the single-table item-type-prefix convention already documented in
  infra/lib/state-stack.ts (GRANT#/COUNTER#/IDEM#/LEDGER#/INTENT#). This adds
  "ENVELOPE#" to that list. brokerRole already holds read-only
  dynamodb:GetItem/Query on the grants table (infra/lib/identity-stack.ts);
  promotionRole/demotionRole already hold PutItem/UpdateItem there — so this
  item type needs NO new CDK stack, table, or IAM policy.
- Table name resolution mirrors DynamoDBGrantStore: an explicit table_name
  wins; otherwise GRANTS_TABLE_NAME from the environment. In practice callers
  (build_runtime, the seed script) should pass the SAME table_name they
  resolve for DynamoDBGrantStore, since the two stores share one physical
  table.
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from safe_agents.broker.schemas import Envelope
from safe_agents.broker.schemas.common import Principal


def _principal_key(principal: Principal) -> str:
    """Stable string key for a principal; used as part of the DynamoDB PK.

    Identical construction to grants/store.py's _principal_key — the two
    stores share a table, so the "ENVELOPE#" vs "GRANT#" prefix (not this
    suffix) is what keeps the item types from colliding.
    """
    return f"{principal.agentId}#{principal.skill}#{principal.user}#{principal.tier}"


# ---------------------------------------------------------------------------
# Store interface
# ---------------------------------------------------------------------------

@runtime_checkable
class EnvelopeStore(Protocol):
    """Injectable store interface. Tests supply InMemoryEnvelopeStore; prod uses
    DynamoDBEnvelopeStore."""

    def get_envelope(self, principal: Principal) -> Envelope | None:
        ...

    def put_envelope(self, principal: Principal, envelope: Envelope, session: object = None) -> None:
        """Persist envelope under the supplied boto3 Session (or None for in-memory)."""
        ...


# ---------------------------------------------------------------------------
# In-memory fake — for unit tests
# ---------------------------------------------------------------------------

class InMemoryEnvelopeStore:
    """Fake store backed by a plain dict. Thread-unsafe; suitable for unit tests only."""

    def __init__(self) -> None:
        # principal_key -> raw dict from model_dump(mode="json")
        self._store: dict[str, dict] = {}

    def get_envelope(self, principal: Principal) -> Envelope | None:
        raw = self._store.get(_principal_key(principal))
        if raw is None:
            return None
        return Envelope.model_validate(raw)

    def put_envelope(self, principal: Principal, envelope: Envelope, session: object = None) -> None:
        """Persist envelope. The session arg is accepted but unused (in-memory)."""
        self._store[_principal_key(principal)] = envelope.model_dump(mode="json")


# ---------------------------------------------------------------------------
# DynamoDB implementation — production
# ---------------------------------------------------------------------------

class DynamoDBEnvelopeStore:
    """DynamoDB-backed envelope store, co-located in the grants table.

    Table name: read from GRANTS_TABLE_NAME env var when table_name is not
    supplied explicitly (see module docstring re: sharing the grants table).
    Callers may supply a boto3 Session for writes — this client never assumes
    roles, same as DynamoDBGrantStore.

    Item layout:
        pk = "ENVELOPE#<agentId>#<skill>#<user>#<tier>"
        sk = "V0"
        data = entire Envelope as a JSON string (handles all Pydantic types cleanly)
    """

    def __init__(self, table_name: str | None = None) -> None:
        self._table_name = table_name or os.environ["GRANTS_TABLE_NAME"]

    def _item_key(self, principal: Principal) -> dict:
        return {
            "pk": f"ENVELOPE#{_principal_key(principal)}",
            "sk": "V0",
        }

    def _get_table(self, session=None):
        import boto3  # lazy — avoid import-time hard dependency

        resource = session.resource("dynamodb") if session is not None else boto3.resource("dynamodb")
        return resource.Table(self._table_name)

    def get_envelope(self, principal: Principal) -> Envelope | None:
        table = self._get_table()
        response = table.get_item(Key=self._item_key(principal))
        item = response.get("Item")
        if item is None:
            return None
        return Envelope.model_validate_json(item["data"])

    def put_envelope(self, principal: Principal, envelope: Envelope, session: object = None) -> None:
        """Write an envelope using the supplied boto3 Session.

        The session must carry a role with PutItem permission on the grants
        table (promotion role, or an equivalent out-of-band seed identity —
        see prototype/seed_envelope.py). AccessDenied is NOT caught here — a
        failed write must be visible to the caller.
        """
        table = self._get_table(session)
        item = {
            **self._item_key(principal),
            "data": envelope.model_dump_json(),
        }
        table.put_item(Item=item)
