"""Durable promotion-proposal store (#123).

propose and ratify are separate CLI invocations by different identities —
maker ≠ checker is structural (broker/grant-lifecycle.md) — so a
PromotionProposal must persist between them. This module is that persistence:
Protocol + InMemoryProposalStore (tests) + DynamoDBProposalStore (production),
co-located in the grants table as PROPOSAL# items.

Design notes (same posture as store.py):
- Callers supply the boto3 Session; this module never assumes IAM roles.
- The stored item carries the proposal content (immutable, serialized JSON)
  plus a mutable `status` attribute: "pending" | "ratified" | "rejected".
  Status lives on the ITEM, not the dataclass — the proposal content is fixed
  at propose time.
- The proposal content is HMAC'd with the same injected key discipline as the
  grant store (compute_proposal_hash over the canonical JSON): proposals live
  in the same table the grant HMAC defends, and an unsigned proposal is a
  tamper target that launders into a signed grant at ratify time. put computes
  the hash; get/list verify and raise ProposalIntegrityError on mismatch —
  a tampered proposal is refused loudly, never silently served or skipped.
- consume_proposal is a conditional status flip (only from "pending"): the
  double-ratify race is killed by the store condition, not by caller courtesy.
  UpdateItem-only also fits the promotion IAM role.
- Expiry is deterministic: callers pass `now` to proposal_expired; an
  unparseable expires_at is treated as expired (fail closed — a proposal whose
  expiry cannot be read can never license a ratification).
- Table name: GRANTS_TABLE_NAME env var, like the grant store. Never hardcoded.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac as _hmac
import json
import os
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from safe_agents.broker.grants.predicate import ActionClassMetrics
from safe_agents.broker.grants.store import _principal_key
from safe_agents.broker.schemas.budgets import ErrorBudget
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import ConfidenceArtifact

if TYPE_CHECKING:
    # Runtime import would be circular: ceremony.py imports this module for
    # ProposalStore + proposal_expired. from_json imports it lazily instead.
    from safe_agents.broker.grants.ceremony import PromotionProposal


ProposalStatus = Literal["pending", "ratified", "rejected"]


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------

class ProposalAlreadyExistsError(Exception):
    """A proposal with this (principal, actionClass, proposal_id) already exists.

    Proposals are append-only content: an existing item is never overwritten.
    Mint a fresh proposal_id instead of re-putting.
    """


class ProposalConsumedError(Exception):
    """Conditional status flip failed: the proposal is not pending.

    Raised when consume_proposal's condition (stored status == "pending")
    fails — the proposal was already ratified or rejected (the double-ratify
    race), or it does not exist. Never retry the flip blind.
    """


class ProposalIntegrityError(Exception):
    """Read refused: the stored proposal failed HMAC verification.

    A tampered (or unsigned) proposal's contents are untrusted; serving it
    would let a table edit launder into a signed grant at ratify time. The
    proposal must not be used until the tamper is root-caused and the
    proposal re-submitted through the sanctioned path.
    """


# ---------------------------------------------------------------------------
# Deterministic expiry — shared by the ceremony and the future CLI
# ---------------------------------------------------------------------------

def proposal_expired(expires_at: str, now: datetime.datetime) -> bool:
    """True iff the proposal's expiry has passed at `now`. Pure; no I/O.

    Fail closed: an unparseable expires_at is expired — a proposal whose
    expiry cannot be read can never license a ratification. Naive timestamps
    (either side) are interpreted as UTC.
    """
    try:
        parsed = datetime.datetime.fromisoformat(expires_at)
    except (TypeError, ValueError):
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    effective_now = now if now.tzinfo is not None else now.replace(tzinfo=datetime.timezone.utc)
    return effective_now >= parsed


# ---------------------------------------------------------------------------
# Integrity — HMAC over the canonical proposal JSON (same key discipline as
# compute_grant_hash in store.py)
# ---------------------------------------------------------------------------

def compute_proposal_hash(data_json: str, hmac_key: bytes) -> str:
    """HMAC-SHA-256 over the canonical proposal serialization (proposal_to_json).

    The mutable item-level `status` attribute is deliberately NOT covered: it
    is flipped by consume_proposal without a content rewrite. The hash defends
    the immutable proposal content only.
    """
    return _hmac.new(hmac_key, data_json.encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_proposal_item(
    data_json: str,
    stored_hash: object,
    hmac_key: bytes,
    *,
    proposal_id: str,
    where: str,
) -> None:
    """Raise ProposalIntegrityError unless stored_hash matches the recomputed HMAC."""
    expected = compute_proposal_hash(data_json, hmac_key)
    if stored_hash != expected:
        raise ProposalIntegrityError(
            f"proposal {proposal_id} for {where} failed integrity verification "
            f"(hash mismatch: stored={stored_hash!r} expected={expected!r}); "
            "it must not be used until the tamper is resolved"
        )


# ---------------------------------------------------------------------------
# Serialization — the proposal is a dataclass over mixed pydantic/enum fields,
# so the codec is explicit rather than model_dump on the whole
# ---------------------------------------------------------------------------

def proposal_to_json(proposal: "PromotionProposal") -> str:
    """Serialize a PromotionProposal to the stored 'data' JSON string.

    Canonical form, identical to ``canonical_grant_payload`` and
    ``canonical_record_payload``: JSON with sorted keys, NO whitespace
    (compact ``separators=(",", ":")``), ASCII. This string is the HMAC basis
    (``compute_proposal_hash``) and the stored bytes, verified verbatim on
    read — so the canonical rule has to be the ONE rule the whole ceremony
    states, not a per-callsite accident.
    """
    payload = {
        "proposal_id": proposal.proposal_id,
        "expires_at": proposal.expires_at,
        "principal": proposal.principal.model_dump(mode="json"),
        "action_class": proposal.action_class,
        "from_level": proposal.from_level.value if proposal.from_level is not None else None,
        "target_level": proposal.target_level.value,
        "evidence_bundle": proposal.evidence_bundle,
        "proposer_id": proposal.proposer_id,
        "owner_id": proposal.owner_id,
        "envelope_hash": proposal.envelope_hash,
        "label_latency": proposal.label_latency,
        "demotion_triggers": [t.value for t in proposal.demotion_triggers],
        "last_safe_level": proposal.last_safe_level.value,
        "metrics": {
            "false_action_count": proposal.metrics.false_action_count,
            "human_override_count": proposal.metrics.human_override_count,
            "observation_count": proposal.metrics.observation_count,
        },
        "window_n": proposal.window_n,
        "window_periods": proposal.window_periods,
        "period": proposal.period,
        "min_observations": proposal.min_observations,
        "threshold": proposal.threshold,
        "artifact": (
            proposal.artifact.model_dump(mode="json") if proposal.artifact is not None else None
        ),
        "covered": proposal.covered,
        "provenance_maturity": proposal.provenance_maturity,
        "blast_class": proposal.blast_class,
        "error_budget": (
            proposal.error_budget.model_dump(mode="json")
            if proposal.error_budget is not None
            else None
        ),
    }
    # #255: the term is part of the ratified content, so it is inside the
    # HMAC'd payload when set — and OMITTED when None, so a no-term proposal
    # serializes to exactly the pre-#255 bytes.
    if proposal.certified_until is not None:
        payload["certified_until"] = proposal.certified_until
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def proposal_from_json(data: str) -> "PromotionProposal":
    """Rebuild a PromotionProposal from the stored 'data' JSON string."""
    from safe_agents.broker.grants.ceremony import PromotionProposal  # lazy — see module note

    payload = json.loads(data)
    return PromotionProposal(
        proposal_id=payload["proposal_id"],
        expires_at=payload["expires_at"],
        principal=Principal.model_validate(payload["principal"]),
        action_class=payload["action_class"],
        from_level=(
            AutonomyLevel(payload["from_level"]) if payload["from_level"] is not None else None
        ),
        target_level=AutonomyLevel(payload["target_level"]),
        evidence_bundle=payload["evidence_bundle"],
        proposer_id=payload["proposer_id"],
        owner_id=payload["owner_id"],
        envelope_hash=payload["envelope_hash"],
        label_latency=payload["label_latency"],
        demotion_triggers=[DemotionTrigger(t) for t in payload["demotion_triggers"]],
        last_safe_level=AutonomyLevel(payload["last_safe_level"]),
        metrics=ActionClassMetrics(**payload["metrics"]),
        window_n=payload["window_n"],
        # Defaults when absent: a proposal stored before #193 has no window key
        # and must still load and ratify (its metrics were today-only anyway); a
        # pre-#212 proposal spelled the span "window_days" (always day-period).
        window_periods=payload.get("window_periods", payload.get("window_days", 1)),
        period=payload.get("period", "utc-day"),
        min_observations=payload["min_observations"],
        threshold=payload["threshold"],
        artifact=(
            ConfidenceArtifact.model_validate(payload["artifact"])
            if payload["artifact"] is not None
            else None
        ),
        covered=payload["covered"],
        provenance_maturity=payload["provenance_maturity"],
        blast_class=payload["blast_class"],
        error_budget=(
            ErrorBudget.model_validate(payload["error_budget"])
            if payload["error_budget"] is not None
            else None
        ),
        # Absent on every proposal stored before #255 (and on no-term ones).
        certified_until=payload.get("certified_until"),
    )


# ---------------------------------------------------------------------------
# Store interface
# ---------------------------------------------------------------------------

def _proposal_pk(principal: Principal, action_class: str) -> str:
    return f"PROPOSAL#{_principal_key(principal)}#{action_class}"


@runtime_checkable
class ProposalStore(Protocol):
    """Injectable proposal store. Tests use InMemoryProposalStore; prod uses DynamoDB."""

    def put_proposal(self, proposal: "PromotionProposal", session: object = None) -> None:
        """Persist a fresh proposal with status='pending'.

        Raises ProposalAlreadyExistsError if the (principal, actionClass,
        proposal_id) item already exists — proposals are never overwritten.
        """
        ...

    def get_proposal(
        self, principal: Principal, action_class: str, proposal_id: str, session: object = None
    ) -> tuple["PromotionProposal", str] | None:
        """Return (proposal, status) or None if absent."""
        ...

    def consume_proposal(
        self,
        principal: Principal,
        action_class: str,
        proposal_id: str,
        new_status: str,
        session: object = None,
    ) -> None:
        """Conditionally flip status pending -> new_status ("ratified"/"rejected").

        Raises ProposalConsumedError if the stored status is not "pending"
        (already consumed — the double-ratify race) or the item is absent.
        """
        ...

    def list_pending(
        self, principal: Principal, action_class: str, session: object = None
    ) -> list["PromotionProposal"]:
        """All pending proposals for (principal, action_class)."""
        ...


def _check_new_status(new_status: str) -> None:
    if new_status not in ("ratified", "rejected"):
        raise ValueError(
            f"consume_proposal only flips pending -> ratified|rejected, got {new_status!r}"
        )


# ---------------------------------------------------------------------------
# In-memory fake — for unit tests
# ---------------------------------------------------------------------------

class InMemoryProposalStore:
    """Fake proposal store mirroring the DynamoDB item semantics (including the
    HMAC verify-on-read contract). Not thread-safe."""

    def __init__(self, hmac_key: bytes = b"test-hmac-key") -> None:
        self._hmac_key = hmac_key
        # (pk, proposal_id) -> {"data": str, "proposalHash": str, "status": str,
        #                       "expires_at": str}
        self._items: dict[tuple[str, str], dict] = {}

    def put_proposal(self, proposal: "PromotionProposal", session: object = None) -> None:
        key = (_proposal_pk(proposal.principal, proposal.action_class), proposal.proposal_id)
        if key in self._items:
            raise ProposalAlreadyExistsError(
                f"proposal {key[0]}/{key[1]} already exists; "
                "proposals are never overwritten — mint a fresh proposal_id"
            )
        data = proposal_to_json(proposal)
        self._items[key] = {
            "data": data,
            "proposalHash": compute_proposal_hash(data, self._hmac_key),
            "status": "pending",
            "expires_at": proposal.expires_at,
        }

    def get_proposal(
        self, principal: Principal, action_class: str, proposal_id: str, session: object = None
    ) -> tuple["PromotionProposal", str] | None:
        item = self._items.get((_proposal_pk(principal, action_class), proposal_id))
        if item is None:
            return None
        _verify_proposal_item(
            item["data"],
            item.get("proposalHash"),
            self._hmac_key,
            proposal_id=proposal_id,
            where=f"{principal.agentId}/{action_class}",
        )
        return proposal_from_json(item["data"]), item["status"]

    def consume_proposal(
        self,
        principal: Principal,
        action_class: str,
        proposal_id: str,
        new_status: str,
        session: object = None,
    ) -> None:
        _check_new_status(new_status)
        item = self._items.get((_proposal_pk(principal, action_class), proposal_id))
        if item is None or item["status"] != "pending":
            found = "absent" if item is None else f"status={item['status']!r}"
            raise ProposalConsumedError(
                f"proposal {proposal_id} for {principal.agentId}/{action_class} is not "
                f"pending ({found}); it was already consumed or never existed"
            )
        item["status"] = new_status

    def list_pending(
        self, principal: Principal, action_class: str, session: object = None
    ) -> list["PromotionProposal"]:
        pk = _proposal_pk(principal, action_class)
        proposals: list["PromotionProposal"] = []
        for (item_pk, item_id), item in self._items.items():
            if item_pk != pk or item["status"] != "pending":
                continue
            _verify_proposal_item(
                item["data"],
                item.get("proposalHash"),
                self._hmac_key,
                proposal_id=item_id,
                where=f"{principal.agentId}/{action_class}",
            )
            proposals.append(proposal_from_json(item["data"]))
        return proposals


# ---------------------------------------------------------------------------
# DynamoDB implementation — production (same grants table, PROPOSAL# items)
# ---------------------------------------------------------------------------

class DynamoDBProposalStore:
    """DynamoDB-backed proposal store.

    Item layout (in the grants table, GRANTS_TABLE_NAME env var):
        pk = "PROPOSAL#<agentId>#<skill>#<user>#<tier>#<actionClass>"
        sk = <proposal_id>
        data = the proposal serialized via proposal_to_json
        proposalHash = HMAC-SHA-256 over data (compute_proposal_hash); the
            HMAC key is injected at construction, same discipline as
            DynamoDBGrantStore. Verified on every read; a mismatch (or a
            missing hash) raises ProposalIntegrityError.
        status = "pending" | "ratified" | "rejected"
        expires_at = ISO-8601 UTC (duplicated at item level for queries)

    Writes use update_item (NOT put_item), like the PromotionRecord ledger, so
    they run under an UpdateItem-only IAM role. put's attribute_not_exists(pk)
    condition makes the content append-only; consume's status condition makes
    ratification single-shot.
    """

    def __init__(self, hmac_key: bytes, table_name: str | None = None) -> None:
        self._hmac_key = hmac_key
        self._table_name = table_name or os.environ["GRANTS_TABLE_NAME"]

    def _get_table(self, session=None):
        import boto3  # lazy — avoid import-time hard dependency

        resource = session.resource("dynamodb") if session is not None else boto3.resource("dynamodb")
        return resource.Table(self._table_name)

    @staticmethod
    def _item_key(principal: Principal, action_class: str, proposal_id: str) -> dict:
        return {"pk": _proposal_pk(principal, action_class), "sk": proposal_id}

    def put_proposal(self, proposal: "PromotionProposal", session: object = None) -> None:
        from botocore.exceptions import ClientError  # lazy, like boto3

        table = self._get_table(session)
        key = self._item_key(proposal.principal, proposal.action_class, proposal.proposal_id)
        data = proposal_to_json(proposal)
        try:
            table.update_item(
                Key=key,
                UpdateExpression=(
                    "SET #data = :data, proposalHash = :proposal_hash, "
                    "#status = :status, expires_at = :expires_at"
                ),
                ConditionExpression="attribute_not_exists(pk)",
                # 'data' and 'status' are DynamoDB-reserved words
                ExpressionAttributeNames={"#data": "data", "#status": "status"},
                ExpressionAttributeValues={
                    ":data": data,
                    ":proposal_hash": compute_proposal_hash(data, self._hmac_key),
                    ":status": "pending",
                    ":expires_at": proposal.expires_at,
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ProposalAlreadyExistsError(
                    f"proposal {key['pk']}/{key['sk']} already exists; "
                    "proposals are never overwritten — mint a fresh proposal_id"
                ) from exc
            raise

    def get_proposal(
        self, principal: Principal, action_class: str, proposal_id: str, session: object = None
    ) -> tuple["PromotionProposal", str] | None:
        table = self._get_table(session)
        response = table.get_item(Key=self._item_key(principal, action_class, proposal_id))
        item = response.get("Item")
        if item is None:
            return None
        _verify_proposal_item(
            item["data"],
            item.get("proposalHash"),
            self._hmac_key,
            proposal_id=proposal_id,
            where=f"{principal.agentId}/{action_class}",
        )
        return proposal_from_json(item["data"]), item["status"]

    def consume_proposal(
        self,
        principal: Principal,
        action_class: str,
        proposal_id: str,
        new_status: str,
        session: object = None,
    ) -> None:
        from botocore.exceptions import ClientError  # lazy, like boto3

        _check_new_status(new_status)
        table = self._get_table(session)
        try:
            table.update_item(
                Key=self._item_key(principal, action_class, proposal_id),
                UpdateExpression="SET #status = :new_status",
                ConditionExpression="attribute_exists(pk) AND #status = :pending",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":new_status": new_status, ":pending": "pending"},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ProposalConsumedError(
                    f"proposal {proposal_id} for {principal.agentId}/{action_class} is not "
                    "pending; it was already consumed or never existed"
                ) from exc
            raise

    def list_pending(
        self, principal: Principal, action_class: str, session: object = None
    ) -> list["PromotionProposal"]:
        table = self._get_table(session)
        pk = _proposal_pk(principal, action_class)
        proposals: list["PromotionProposal"] = []
        kwargs: dict = {
            "KeyConditionExpression": "pk = :pk",
            "FilterExpression": "#status = :pending",
            "ExpressionAttributeNames": {"#status": "status"},
            "ExpressionAttributeValues": {":pk": pk, ":pending": "pending"},
        }
        while True:
            response = table.query(**kwargs)
            for item in response.get("Items", []):
                _verify_proposal_item(
                    item["data"],
                    item.get("proposalHash"),
                    self._hmac_key,
                    proposal_id=item.get("sk", "<unknown>"),
                    where=f"{principal.agentId}/{action_class}",
                )
                proposals.append(proposal_from_json(item["data"]))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                return proposals
            kwargs["ExclusiveStartKey"] = last_key


# ---------------------------------------------------------------------------
# Checker-decline path
# ---------------------------------------------------------------------------

def reject_proposal(
    proposal_store: ProposalStore,
    principal: Principal,
    action_class: str,
    proposal_id: str,
    *,
    session: object = None,
) -> None:
    """A checker that declines flips the pending proposal to 'rejected'.

    The same conditional flip as ratification: an already-consumed proposal
    raises ProposalConsumedError (the flip is single-shot in either direction).
    """
    proposal_store.consume_proposal(
        principal, action_class, proposal_id, "rejected", session=session
    )
