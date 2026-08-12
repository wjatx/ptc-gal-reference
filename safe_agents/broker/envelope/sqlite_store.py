"""SQLite implementation of the EnvelopeStore Protocol (product-wrapper Phase 1, grants-sqlite slice).

The local durable backend for the in-force envelope, built on
``sqlite_substrate`` (one db file, WAL, item-shaped rows keyed exactly like
the DynamoDB single-table items). Fills ``EnvelopeStore`` exactly as
``InMemoryEnvelopeStore`` and ``DynamoDBEnvelopeStore`` do, with the identical
item layout so ``example-wrapper migrate`` stays a row pump.

As in the Dynamo twin, there is deliberately NO HMAC on the envelope item:
an Envelope's integrity is enforced downstream by grant hash-binding — every
Grant carries the envelopeHash it was minted against, so a tampered stored
envelope fails to match any existing Grant and is a deny, never a bypass (see
``envelope/store.py``'s module docstring).

The ``session`` parameter exists for Protocol parity and is ignored — there is
no boto3 here; identity on the local arm is the ceremony resolver's concern,
not the store's.
"""

from __future__ import annotations


from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.envelope.store import _principal_key
from safe_agents.broker.schemas import Envelope
from safe_agents.broker.schemas.common import Principal


class SqliteEnvelopeStore(substrate.SqliteStoreBase):
    """SQLite-backed ``EnvelopeStore``.

    Item layout mirrors ``DynamoDBEnvelopeStore`` key-for-key:
        pk = "ENVELOPE#<agentId>#<skill>#<user>#<tier>"  sk = "V0"
        attrs {"data": <entire Envelope as a JSON string>}
    """

    @staticmethod
    def _item_key(principal: Principal) -> tuple[str, str]:
        return f"ENVELOPE#{_principal_key(principal)}", "V0"

    def get_envelope(self, principal: Principal) -> Envelope | None:
        attrs = substrate.get_item(self._connection(), *self._item_key(principal))
        if attrs is None:
            return None
        return Envelope.model_validate_json(attrs["data"])

    def put_envelope(
        self, principal: Principal, envelope: Envelope, session: object = None
    ) -> None:
        """Persist the envelope. A blind upsert matching Dynamo's put_item —
        spelled as read-check then insert-or-update inside one transaction,
        never REPLACE. The session arg is accepted but unused (no boto3 here).
        """
        pk, sk = self._item_key(principal)
        attrs = {"data": envelope.model_dump_json()}
        conn = self._connection()
        with substrate.transaction(conn):
            if substrate.get_item(conn, pk, sk) is None:
                substrate.put_new_item(conn, pk, sk, attrs)
            else:
                substrate.update_existing_item(conn, pk, sk, attrs)
