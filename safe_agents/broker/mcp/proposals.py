"""Durable admission-proposal store (#174).

admit-propose and admit-ratify are separate CLI invocations by different
identities — maker != checker is structural (MCP-HOST.md M7) — so an admission
proposal must persist between them. This module is that persistence, mirroring
``grants.proposals`` one-for-one: Protocol + MemoryAdmissionProposalStore (tests)
+ DynamoAdmissionProposalStore (production), co-located as ``TOOLPROP#`` items.

Design notes (same posture as grants/proposals.py):
- Callers supply the boto3 Session; this module never assumes IAM roles.
- The stored item carries the immutable proposal content plus a mutable
  ``status`` attribute: "pending" | "ratified" | "rejected".
- The content is HMAC'd with the same injected-key discipline as the grant/row
  stores (``compute_proposal_hmac``): a tampered proposal would launder a
  swapped tool definition into a signed admission at ratify time. put computes
  the hash; get verifies and raises ProposalIntegrityError on mismatch.
- consume_proposal is a conditional status flip (only from "pending") — the
  double-ratify race is killed by the store condition, not caller courtesy.
- Table name: MCP_REGISTRY_TABLE_NAME env var, like the row store. Never hardcoded.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from safe_agents.broker.schemas.mcp_registry import McpToolDef

# Ceremony kinds carried by a proposal/record: a first admission vs. a re-vet of
# a drifted definition (the SAME ceremony run against the NEW advertised def).
KIND_ADMISSION = "admission"
KIND_REVET = "re-vet"
CEREMONY_KINDS = (KIND_ADMISSION, KIND_REVET)


# ---------------------------------------------------------------------------
# Error types (mirror grants/proposals.py)
# ---------------------------------------------------------------------------


class ProposalAlreadyExistsError(Exception):
    """An admission proposal with this (server_id, tool_name, proposal_id) exists.

    Proposals are append-only content: an existing item is never overwritten —
    mint a fresh proposal_id.
    """


class ProposalConsumedError(Exception):
    """Conditional status flip failed: the admission proposal is not pending.

    The proposal was already ratified/rejected (the double-ratify race) or does
    not exist. Never retry the flip blind.
    """


class ProposalIntegrityError(Exception):
    """Read refused: the stored admission proposal failed HMAC verification.

    A tampered proposal would launder a swapped tool definition into a signed
    admission at ratify time. Refuse loudly, never serve it.
    """


# ---------------------------------------------------------------------------
# Proposal model + integrity HMAC
# ---------------------------------------------------------------------------


class McpAdmissionProposal(BaseModel):
    """A maker's proposal to admit ONE (server_id, tool_name) at a def_hash.

    Binds the FULL advertised ``McpToolDef`` and its ``def_hash`` so the checker
    ratifies exactly what the maker saw — a swapped definition between propose
    and ratify breaks the HMAC (ProposalIntegrityError). ``kind`` distinguishes
    a first admission from a re-vet of drifted bytes.
    """

    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    expires_at: str  # ISO-8601 UTC
    tool_def: McpToolDef
    def_hash: str
    kind: str
    proposed_by: str  # maker credential ARN


def canonical_proposal_payload(proposal: McpAdmissionProposal) -> str:
    """The ONE serialization of a proposal — what gets stored AND what gets HMAC'd.

    Storage and the integrity basis must be the same bytes. When they diverge,
    verification has to re-serialize the parsed model, which silently re-derives
    the basis from whatever the model class looks like *today* — so any additive
    schema change (a new optional field emitted by ``model_dump``) invalidates
    every historical row and reports it as a tamper. That happened for real:
    #221's field-carry widened ``McpToolDef`` from 4 fields to 10, and every
    proposal written before it began failing verification although none had been
    touched. A ceremony that cries tamper when a schema grows teaches operators
    to dismiss the alarm that matters.

    So: serialize once, store that exact string, HMAC that exact string, and on
    read HMAC the stored bytes verbatim without ever re-serializing. The basis is
    then immune to schema evolution and to construction-path differences (a
    code-built model and a JSON-parsed one can disagree about which fields are
    "set"). The mutable item-level ``status`` is deliberately outside the payload
    — consume flips it without a content rewrite.
    """
    return json.dumps(proposal.model_dump(mode="json"), sort_keys=True, ensure_ascii=True)


def compute_proposal_hmac(proposal: McpAdmissionProposal, hmac_key: bytes) -> str:
    """HMAC-SHA-256 over the canonical proposal payload (write path)."""
    return _hmac_payload(canonical_proposal_payload(proposal), hmac_key)


def _hmac_payload(payload: str, hmac_key: bytes) -> str:
    return _hmac.new(hmac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_proposal_payload(
    stored_hash: object, payload: str, hmac_key: bytes, *, coordinate: str
) -> None:
    """Verify the STORED bytes, before they are parsed into a model.

    Verify-then-parse, never parse-then-re-serialize: the bytes on disk are the
    thing under integrity protection, and they are also untrusted input.
    """
    expected = _hmac_payload(payload, hmac_key)
    if stored_hash != expected:
        raise ProposalIntegrityError(
            f"admission proposal {coordinate} failed integrity verification "
            f"(stored={stored_hash!r} expected={expected!r}); it must not be "
            "used until the tamper is resolved"
        )


def _proposal_pk(server_id: str, tool_name: str) -> str:
    return f"TOOLPROP#{server_id}#{tool_name}"


def _check_new_status(new_status: str) -> None:
    if new_status not in ("ratified", "rejected"):
        raise ValueError(
            f"consume_proposal only flips pending -> ratified|rejected, got {new_status!r}"
        )


# ---------------------------------------------------------------------------
# Store interface
# ---------------------------------------------------------------------------


@runtime_checkable
class AdmissionProposalStore(Protocol):
    """Injectable proposal store. Tests use the Memory arm; prod the Dynamo arm."""

    def put_proposal(self, proposal: McpAdmissionProposal, session: object = None) -> None: ...

    def get_proposal(
        self, server_id: str, tool_name: str, proposal_id: str, session: object = None
    ) -> tuple[McpAdmissionProposal, str] | None: ...

    def list_pending(
        self, server_id: str, tool_name: str, session: object = None
    ) -> list[tuple[McpAdmissionProposal, str]]: ...

    def consume_proposal(
        self, server_id: str, tool_name: str, proposal_id: str, new_status: str,
        session: object = None,
    ) -> None: ...


# ---------------------------------------------------------------------------
# In-memory fake — for unit tests
# ---------------------------------------------------------------------------


class MemoryAdmissionProposalStore:
    """Fake proposal store mirroring the DynamoDB item semantics (incl. HMAC
    verify-on-read). Thread-unsafe; unit tests only."""

    def __init__(self, hmac_key: bytes = b"test-hmac-key") -> None:
        self._hmac_key = hmac_key
        # (server_id, tool_name, proposal_id) -> {"data", "proposalHash", "status"}
        self._items: dict[tuple[str, str, str], dict] = {}

    def put_proposal(self, proposal: McpAdmissionProposal, session: object = None) -> None:
        key = (proposal.tool_def.server_id, proposal.tool_def.tool_name, proposal.proposal_id)
        if key in self._items:
            raise ProposalAlreadyExistsError(
                f"admission proposal {key} already exists; proposals are never "
                "overwritten — mint a fresh proposal_id"
            )
        payload = canonical_proposal_payload(proposal)
        self._items[key] = {
            "data": payload,
            "proposalHash": _hmac_payload(payload, self._hmac_key),
            "status": "pending",
        }

    def get_proposal(
        self, server_id: str, tool_name: str, proposal_id: str, session: object = None
    ) -> tuple[McpAdmissionProposal, str] | None:
        item = self._items.get((server_id, tool_name, proposal_id))
        if item is None:
            return None
        _verify_proposal_payload(
            item.get("proposalHash"), item["data"], self._hmac_key,
            coordinate=f"{server_id}/{tool_name}/{proposal_id}",
        )
        proposal = McpAdmissionProposal.model_validate_json(item["data"])
        return proposal, item["status"]

    def list_pending(
        self, server_id: str, tool_name: str, session: object = None
    ) -> list[tuple[McpAdmissionProposal, str]]:
        pending: list[tuple[McpAdmissionProposal, str]] = []
        for (item_server, item_tool, _), item in sorted(self._items.items()):
            if (item_server, item_tool) != (server_id, tool_name):
                continue
            # Verify EVERY row on the partition, not just the pending ones: the
            # integrity check is what makes a read refusal loud, and skipping
            # consumed rows first would let a tamper hide behind a status flip.
            _verify_proposal_payload(
                item.get("proposalHash"), item["data"], self._hmac_key,
                coordinate=f"{item_server}/{item_tool}",
            )
            if item["status"] == "pending":
                pending.append((McpAdmissionProposal.model_validate_json(item["data"]), item["status"]))
        return pending

    def consume_proposal(
        self, server_id: str, tool_name: str, proposal_id: str, new_status: str,
        session: object = None,
    ) -> None:
        _check_new_status(new_status)
        item = self._items.get((server_id, tool_name, proposal_id))
        if item is None or item["status"] != "pending":
            found = "absent" if item is None else f"status={item['status']!r}"
            raise ProposalConsumedError(
                f"admission proposal {proposal_id} for {server_id}/{tool_name} is not "
                f"pending ({found}); it was already consumed or never existed"
            )
        item["status"] = new_status


# ---------------------------------------------------------------------------
# DynamoDB implementation — production (MCP_REGISTRY_TABLE_NAME, TOOLPROP# items)
# ---------------------------------------------------------------------------


class DynamoAdmissionProposalStore:
    """DynamoDB-backed proposal store.

    Item layout (in the registry table):
        pk = "TOOLPROP#<server_id>#<tool_name>"   sk = <proposal_id>
        data = the proposal serialized as JSON
        proposalHash = HMAC-SHA-256 over data (verified on every read)
        status = "pending" | "ratified" | "rejected"
        expires_at = ISO-8601 UTC (duplicated at item level)

    Writes use update_item (not put_item), like the grant proposal store, so they
    run under an UpdateItem-only IAM role. put's attribute_not_exists(pk) makes
    content append-only; consume's status condition makes ratification single-shot.
    """

    def __init__(self, hmac_key: bytes, table_name: str | None = None) -> None:
        self._hmac_key = hmac_key
        self._table_name = table_name or os.environ["MCP_REGISTRY_TABLE_NAME"]

    def _get_table(self, session=None):
        import boto3  # lazy — avoid import-time hard dependency

        resource = session.resource("dynamodb") if session is not None else boto3.resource("dynamodb")
        return resource.Table(self._table_name)

    @staticmethod
    def _item_key(server_id: str, tool_name: str, proposal_id: str) -> dict:
        return {"pk": _proposal_pk(server_id, tool_name), "sk": proposal_id}

    def put_proposal(self, proposal: McpAdmissionProposal, session: object = None) -> None:
        from botocore.exceptions import ClientError  # lazy, like boto3

        table = self._get_table(session)
        key = self._item_key(
            proposal.tool_def.server_id, proposal.tool_def.tool_name, proposal.proposal_id
        )
        data = canonical_proposal_payload(proposal)
        try:
            table.update_item(
                Key=key,
                UpdateExpression="SET #data = :data, proposalHash = :h, #status = :s, expires_at = :e",
                ConditionExpression="attribute_not_exists(pk)",
                ExpressionAttributeNames={"#data": "data", "#status": "status"},
                ExpressionAttributeValues={
                    ":data": data,
                    ":h": _hmac_payload(data, self._hmac_key),
                    ":s": "pending",
                    ":e": proposal.expires_at,
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ProposalAlreadyExistsError(
                    f"admission proposal {key['pk']}/{key['sk']} already exists; "
                    "proposals are never overwritten — mint a fresh proposal_id"
                ) from exc
            raise

    def get_proposal(
        self, server_id: str, tool_name: str, proposal_id: str, session: object = None
    ) -> tuple[McpAdmissionProposal, str] | None:
        table = self._get_table(session)
        item = table.get_item(Key=self._item_key(server_id, tool_name, proposal_id)).get("Item")
        if item is None:
            return None
        _verify_proposal_payload(
            item.get("proposalHash"), item["data"], self._hmac_key,
            coordinate=f"{server_id}/{tool_name}/{proposal_id}",
        )
        proposal = McpAdmissionProposal.model_validate_json(item["data"])
        return proposal, item["status"]

    def list_pending(
        self, server_id: str, tool_name: str, session: object = None
    ) -> list[tuple[McpAdmissionProposal, str]]:
        """Every PENDING proposal on ONE known coordinate, HMAC-verified on read.

        A plain `Query` on the coordinate's partition key — the proposal pk
        already embeds (server_id, tool_name), so no GSI and no `dynamodb:Scan`
        is involved (no ceremony role is granted Scan; a scan would pass every
        in-memory test and be IAM-denied on the real floor). The caller supplies
        the coordinate from the image-baked manifest's declared namespace, so
        this never enumerates a universe the store chose.
        """
        table = self._get_table(session)
        kwargs: dict = {
            "KeyConditionExpression": "pk = :pk",
            "ExpressionAttributeValues": {":pk": _proposal_pk(server_id, tool_name)},
            "ScanIndexForward": True,
        }
        pending: list[tuple[McpAdmissionProposal, str]] = []
        while True:
            response = table.query(**kwargs)
            for item in response.get("Items", []):
                # Verify EVERY row on the partition, not just the pending ones:
                # a tamper must not be able to hide behind a status flip.
                _verify_proposal_payload(
                    item.get("proposalHash"), item["data"], self._hmac_key,
                    coordinate=f"{server_id}/{tool_name}/{item.get('sk')}",
                )
                if item["status"] == "pending":
                    pending.append(
                        (McpAdmissionProposal.model_validate_json(item["data"]), item["status"])
                    )
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                return pending
            kwargs["ExclusiveStartKey"] = last_key

    def consume_proposal(
        self, server_id: str, tool_name: str, proposal_id: str, new_status: str,
        session: object = None,
    ) -> None:
        from botocore.exceptions import ClientError  # lazy, like boto3

        _check_new_status(new_status)
        table = self._get_table(session)
        try:
            table.update_item(
                Key=self._item_key(server_id, tool_name, proposal_id),
                UpdateExpression="SET #status = :new",
                ConditionExpression="attribute_exists(pk) AND #status = :pending",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":new": new_status, ":pending": "pending"},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ProposalConsumedError(
                    f"admission proposal {proposal_id} for {server_id}/{tool_name} is not "
                    "pending; it was already consumed or never existed"
                ) from exc
            raise
