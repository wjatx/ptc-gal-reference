"""The admission proposal's integrity basis is the STORED BYTES.

Regression suite for a defect found on the dev floor (2026-07-20). #221's
field-carry (`3b55e93`) widened `McpToolDef` from four fields to ten. That
commit was careful: it pinned `compute_tool_def_hash` byte-identical with a
golden fixture and a conformance row. But `compute_proposal_hmac` embeds the
same model under a *different* canonicalization, and verification re-serialized
the parsed proposal — so `model_dump` began emitting six fields that were never
in the basis, and every proposal written before that commit started failing
verification as a TAMPER although none had been touched.

The guarded hash held; the unguarded hash next door moved. A golden pin protects
the thing it pins, not the thing that embeds it.

Why it matters beyond tidiness: a ceremony that cries tamper when a schema grows
teaches operators to dismiss the alarm that matters. The fix is to serialize
once, store that exact string, HMAC that exact string, and on read HMAC the
stored bytes verbatim — never re-serializing. That makes the basis immune both
to additive schema change and to construction-path differences (a code-built
model and a JSON-parsed one can disagree about which fields are "set", so
`exclude_unset` would have been a fragile fix even though it reproduces the old
hash).
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from safe_agents.broker.mcp.proposals import (
    KIND_ADMISSION,
    McpAdmissionProposal,
    MemoryAdmissionProposalStore,
    ProposalIntegrityError,
    _hmac_payload,
    canonical_proposal_payload,
)
from safe_agents.broker.schemas.mcp_registry import McpToolDef, compute_tool_def_hash

SERVER_ID = "ledger"
TOOL = "get_entry"
PROPOSAL_ID = "p1"
MAKER_ARN = "arn:aws:sts::111111111111:assumed-role/MakerRole/maker-session"

ORIGINAL_TOOL_DEF_FIELDS = ("server_id", "tool_name", "input_schema", "description")


def _tool_def() -> McpToolDef:
    return McpToolDef(
        server_id=SERVER_ID,
        tool_name=TOOL,
        input_schema={"type": "object", "properties": {"entry_id": {"type": "string"}}},
        description="Return one ledger entry by id.",
    )


def _proposal() -> McpAdmissionProposal:
    definition = _tool_def()
    return McpAdmissionProposal(
        proposal_id=PROPOSAL_ID,
        expires_at="2026-07-20T13:00:00+00:00",
        tool_def=definition,
        def_hash=compute_tool_def_hash(definition),
        kind=KIND_ADMISSION,
        proposed_by=MAKER_ARN,
    )


@pytest.fixture
def store() -> MemoryAdmissionProposalStore:
    return MemoryAdmissionProposalStore()


def _item(store: MemoryAdmissionProposalStore) -> dict:
    return store._items[(SERVER_ID, TOOL, PROPOSAL_ID)]


class TestStoredBytesAreTheBasis:
    def test_the_stored_payload_hmacs_to_the_stored_hash(self, store) -> None:
        """The invariant the whole fix rests on: no re-serialization step exists
        for a schema change to perturb."""
        store.put_proposal(_proposal())
        item = _item(store)
        assert _hmac_payload(item["data"], store._hmac_key) == item["proposalHash"]

    def test_storage_and_basis_are_the_same_serialization(self, store) -> None:
        """Storing one serialization while hashing another is the defect itself.
        `model_dump_json()` (field order) and the canonical form (sorted keys)
        are not the same bytes — pinned so a future edit cannot reintroduce the
        divergence silently."""
        proposal = _proposal()
        store.put_proposal(proposal)
        assert _item(store)["data"] == canonical_proposal_payload(proposal)
        assert proposal.model_dump_json() != canonical_proposal_payload(proposal)


class TestSchemaEvolutionDoesNotInvalidateHistory:
    def _store_raw(self, store: MemoryAdmissionProposalStore, payload: str) -> None:
        store._items[(SERVER_ID, TOOL, PROPOSAL_ID)] = {
            "data": payload,
            "proposalHash": _hmac_payload(payload, store._hmac_key),
            "status": "pending",
        }

    def test_a_payload_predating_todays_optional_fields_still_verifies(self, store) -> None:
        """A row carrying only the four original `tool_def` fields stands in for
        any pre-widening proposal. It must verify: the read path hashes the bytes
        as found and never asks what the model class looks like today."""
        store.put_proposal(_proposal())
        as_dict = json.loads(_item(store)["data"])
        as_dict["tool_def"] = {
            k: v for k, v in as_dict["tool_def"].items() if k in ORIGINAL_TOOL_DEF_FIELDS
        }
        assert len(as_dict["tool_def"]) < len(McpToolDef.model_fields)
        self._store_raw(store, json.dumps(as_dict, sort_keys=True, ensure_ascii=True))

        loaded, status = store.get_proposal(SERVER_ID, TOOL, PROPOSAL_ID)
        assert (loaded.proposal_id, status) == (PROPOSAL_ID, "pending")

    def test_an_unknown_future_field_passes_integrity_but_fails_parsing(self, store) -> None:
        """The asymmetry is deliberate, and worth pinning so it is not "fixed".

        Backward compatibility is a property of the INTEGRITY basis: an older
        payload verifies, because the bytes are hashed as found. Forward
        compatibility is deliberately NOT offered by the MODEL: `McpToolDef` is
        `extra="forbid"`, so bytes from a newer writer are refused at parse.

        That is the safe polarity for an admission ceremony — an older reader
        that cannot fully understand a proposal must refuse it, never ratify the
        part it recognizes. So the integrity check passes (nothing was tampered)
        and the parse rejects (this reader is too old to judge it).
        """
        store.put_proposal(_proposal())
        as_dict = json.loads(_item(store)["data"])
        as_dict["tool_def"]["some_field_added_later"] = {"nested": True}
        payload = json.dumps(as_dict, sort_keys=True, ensure_ascii=True)
        self._store_raw(store, payload)

        # Integrity: intact — the bytes hash to their stored hash.
        assert _hmac_payload(payload, store._hmac_key) == _item(store)["proposalHash"]
        # Parsing: refused, and NOT as an integrity failure.
        with pytest.raises(ValidationError):
            store.get_proposal(SERVER_ID, TOOL, PROPOSAL_ID)


class TestDetectionIsNotWeakened:
    """The fix must not buy compatibility with leniency."""

    def test_editing_the_payload_without_rehmac_is_refused(self, store) -> None:
        store.put_proposal(_proposal())
        item = _item(store)
        item["data"] = item["data"].replace(MAKER_ARN, "arn:evil")
        with pytest.raises(ProposalIntegrityError):
            store.get_proposal(SERVER_ID, TOOL, PROPOSAL_ID)

    def test_a_swapped_hash_slot_is_refused(self, store) -> None:
        store.put_proposal(_proposal())
        _item(store)["proposalHash"] = "0" * 64
        with pytest.raises(ProposalIntegrityError):
            store.get_proposal(SERVER_ID, TOOL, PROPOSAL_ID)

    def test_verification_precedes_parsing(self, store) -> None:
        """Verify-then-parse: the stored bytes are untrusted input, so a payload
        that is not even valid JSON must raise the INTEGRITY error, not a
        validation error from the model."""
        store.put_proposal(_proposal())
        _item(store)["data"] = "{not json at all"
        with pytest.raises(ProposalIntegrityError):
            store.get_proposal(SERVER_ID, TOOL, PROPOSAL_ID)
