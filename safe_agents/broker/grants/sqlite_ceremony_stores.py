"""sqlite_ceremony_stores.py — the grant ceremony's auxiliary stores, locally (#247).

The grant ceremony needs four durable stores, and after the v0.47.0 slice two of
them (grants, promotion records) had sqlite arms while these two did not, so the
ceremony CLI could not run on a machine with no AWS at all. This module is the
missing pair:

* :class:`SqliteProposalStore` — PROPOSAL# items, the DynamoDBProposalStore
  mirror. A proposal persists between the maker's `propose` and the checker's
  `ratify` (separate invocations by separate identities), so it is the ceremony's
  only cross-process state.
* :class:`SqliteAcknowledgmentStore` — ACK# items, the DynamoDBAcknowledgmentStore
  mirror. Append-only signed waivers (#196).

Both are deliberately thin: every integrity decision — the proposal HMAC basis,
the acknowledgment's canonical payload — lives in the domain modules
(``proposals.py`` / ``acknowledgments.py``) and is imported, never re-derived.
A second implementation of an integrity rule is a second chance to get it
wrong, and the #246 lesson is fresh: the MCP sqlite arm silently serialized
ledger records differently from its Dynamo twin, and every signature it wrote
was unverifiable until a drill caught it. So the rule here is that the two arms
call the SAME serializer and the differential suite proves they store
byte-identical bytes.

Conditional-write semantics come from ``BEGIN IMMEDIATE`` (see
``sqlite_substrate``): the read-check inside the transaction IS the #190
condition, so `put`'s append-only guarantee and `consume`'s single-shot status
flip hold against a concurrent writer exactly as their ConditionExpression
counterparts do.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.grants.acknowledgments import (
    AcknowledgmentAlreadyExistsError,
    AcknowledgmentRecord,
    canonical_ack_payload,
)
from safe_agents.broker.grants.proposals import (
    ProposalAlreadyExistsError,
    ProposalConsumedError,
    _check_new_status,
    _proposal_pk,
    _verify_proposal_item,
    compute_proposal_hash,
    proposal_from_json,
    proposal_to_json,
)
from safe_agents.broker.schemas.common import Principal

if TYPE_CHECKING:
    from safe_agents.broker.grants.ceremony import PromotionProposal


class SqliteProposalStore(substrate.SqliteStoreBase):
    """Local promotion-proposal store — the DynamoDBProposalStore mirror.

    Item layout (identical keys to the Dynamo arm, so ``example-wrapper migrate`` stays a
    row pump)::

        pk   = "PROPOSAL#<agentId>#<skill>#<user>#<tier>#<actionClass>"
        sk   = <proposal_id>
        attrs {"data": <proposal_to_json>, "proposalHash": <HMAC>,
               "status": "pending"|"ratified"|"rejected",
               "expires_at": <ISO-8601 UTC>}

    ``expires_at`` is duplicated into the indexed column as well as the
    attribute map: the column is what a future sweep queries, the attribute is
    what the Dynamo item carries, and the migrate pump copies the latter.
    Nothing here deletes — expiry is a predicate at use (sa#213).
    """

    def __init__(self, hmac_key: bytes, db_path: str | Path) -> None:
        super().__init__(db_path)
        self._hmac_key = hmac_key

    @staticmethod
    def _key(principal: Principal, action_class: str, proposal_id: str) -> tuple[str, str]:
        return _proposal_pk(principal, action_class), proposal_id

    def put_proposal(self, proposal: "PromotionProposal", session: object = None) -> None:
        pk, sk = self._key(proposal.principal, proposal.action_class, proposal.proposal_id)
        data = proposal_to_json(proposal)
        attrs = {
            "data": data,
            "proposalHash": compute_proposal_hash(data, self._hmac_key),
            "status": "pending",
            "expires_at": proposal.expires_at,
        }
        conn = self._connection()
        with substrate.transaction(conn):
            if substrate.get_item(conn, pk, sk) is not None:
                raise ProposalAlreadyExistsError(
                    f"proposal {pk}/{sk} already exists; proposals are never "
                    "overwritten — mint a fresh proposal_id"
                )
            substrate.put_new_item(conn, pk, sk, attrs, expires_at=proposal.expires_at)

    def get_proposal(
        self, principal: Principal, action_class: str, proposal_id: str, session: object = None
    ) -> tuple["PromotionProposal", str] | None:
        pk, sk = self._key(principal, action_class, proposal_id)
        attrs = substrate.get_item(self._connection(), pk, sk)
        if attrs is None:
            return None
        _verify_proposal_item(
            attrs["data"],
            attrs.get("proposalHash"),
            self._hmac_key,
            proposal_id=proposal_id,
            where=f"{principal.agentId}/{action_class}",
        )
        return proposal_from_json(attrs["data"]), attrs["status"]

    def consume_proposal(
        self,
        principal: Principal,
        action_class: str,
        proposal_id: str,
        new_status: str,
        session: object = None,
    ) -> None:
        _check_new_status(new_status)
        pk, sk = self._key(principal, action_class, proposal_id)
        conn = self._connection()
        with substrate.transaction(conn):
            # The read and the flip share one BEGIN IMMEDIATE, so the
            # double-ratify race is killed by the writer lock rather than by
            # caller courtesy — the ConditionExpression's exact guarantee.
            attrs = substrate.get_item(conn, pk, sk)
            if attrs is None or attrs.get("status") != "pending":
                found = "absent" if attrs is None else f"status={attrs.get('status')!r}"
                raise ProposalConsumedError(
                    f"proposal {proposal_id} for {principal.agentId}/{action_class} is not "
                    f"pending ({found}); it was already consumed or never existed"
                )
            substrate.update_existing_item(
                conn,
                pk,
                sk,
                {**attrs, "status": new_status},
                expires_at=attrs.get("expires_at"),
            )

    def list_pending(
        self, principal: Principal, action_class: str, session: object = None
    ) -> list["PromotionProposal"]:
        pk = _proposal_pk(principal, action_class)
        proposals: list["PromotionProposal"] = []
        for sk, attrs in substrate.get_partition(self._connection(), pk):
            if attrs.get("status") != "pending":
                continue
            # Verify EVERY pending proposal, not just the one asked for by id:
            # a tampered proposal must refuse loudly here too, never be quietly
            # skipped out of the listing (silence would read as "no proposal").
            _verify_proposal_item(
                attrs["data"],
                attrs.get("proposalHash"),
                self._hmac_key,
                proposal_id=sk,
                where=f"{principal.agentId}/{action_class}",
            )
            proposals.append(proposal_from_json(attrs["data"]))
        return proposals


class SqliteAcknowledgmentStore(substrate.SqliteStoreBase):
    """Local acknowledgment store — the DynamoDBAcknowledgmentStore mirror.

    Item layout::

        pk   = "ACK#<coordinate>"
        sk   = "<ts>#<rule>"
        attrs {"data": <canonical_ack_payload>, "signature": <DSSE JSON>}

    No HMAC seam, exactly as on the Dynamo arm: an acknowledgment's integrity
    IS its required issuer DSSE signature, and the audit applies nothing that
    does not verify.
    """

    def append_acknowledgment(
        self, ack: AcknowledgmentRecord, envelope: dict, session: object = None
    ) -> None:
        pk, sk = f"ACK#{ack.coordinate}", f"{ack.ts}#{ack.rule}"
        attrs = {
            "data": canonical_ack_payload(ack),
            "signature": json.dumps(envelope, sort_keys=True),
        }
        conn = self._connection()
        with substrate.transaction(conn):
            if substrate.get_item(conn, pk, sk) is not None:
                raise AcknowledgmentAlreadyExistsError(
                    f"acknowledgment {{'pk': {pk!r}, 'sk': {sk!r}}} already exists"
                )
            substrate.put_new_item(conn, pk, sk, attrs)

    def items(self) -> list[dict]:
        """Every stored acknowledgment in DYNAMO ITEM SHAPE (pk/sk merged back in).

        The substrate keeps pk/sk in columns rather than the attribute map, but
        the auditor consumes whole items — so this re-merges them. Returning
        the attribute map alone would hand the auditor coordinate-less
        acknowledgments, which it would silently match against nothing.
        """
        conn = self._connection()
        rows = conn.execute(
            "SELECT pk, sk, item FROM items WHERE pk LIKE 'ACK#%' ORDER BY pk, sk"
        ).fetchall()
        return [{"pk": pk, "sk": sk, **json.loads(item)} for pk, sk, item in rows]
