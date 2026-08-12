"""Tests for the durable promotion-proposal store (#123).

Coverage:
- Round-trip: put_proposal → get_proposal preserves every field, status starts
  'pending' (InMemoryProposalStore + the JSON codec directly).
- Append-only: a second put under the same key raises ProposalAlreadyExistsError.
- Single-shot consumption: consume flips pending → ratified/rejected once;
  a second consume raises ProposalConsumedError (the double-ratify race).
- reject_proposal is the checker-decline flip.
- list_pending returns pending proposals only.
- Integrity: the stored content is HMAC'd (compute_proposal_hash, same injected
  key discipline as the grant store); get/list verify and raise
  ProposalIntegrityError on a tampered or unsigned item — refused loudly,
  never silently skipped.
- proposal_expired: deterministic, fail-closed on unparseable expires_at,
  naive timestamps read as UTC.
- DynamoDBProposalStore: item layout + ConditionExpressions via mock boto3
  (no live AWS), ConditionalCheckFailedException mapping for put and consume,
  round-trip through a captured item — the same mock style as
  test_grants_store.py; real-DynamoDB (moto) coverage belongs in
  test_dynamo_stores.py.
"""

import datetime

import pytest
from unittest.mock import MagicMock

from safe_agents.broker.schemas.budgets import ErrorBudget
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import ConfidenceArtifact, SelfConsistencyEvidence
from safe_agents.broker.grants.ceremony import PromotionCeremony, PromotionProposal
from safe_agents.broker.grants.predicate import ActionClassMetrics
from safe_agents.broker.grants.proposals import (
    DynamoDBProposalStore,
    InMemoryProposalStore,
    ProposalAlreadyExistsError,
    ProposalConsumedError,
    ProposalIntegrityError,
    compute_proposal_hash,
    proposal_expired,
    proposal_from_json,
    proposal_to_json,
    reject_proposal,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-prop", skill="email", user="alice", tier="B")
ACTION_CLASS = "email.send"
TEST_HMAC_KEY = b"test-hmac-key"

_ARTIFACT = ConfidenceArtifact(
    confidence=0.9,
    error_prob=0.1,
    evidence=SelfConsistencyEvidence(samples=5, agreement=0.9),
    computed_at="2026-07-12T00:00:00+00:00",
)

_NOW = datetime.datetime(2026, 7, 12, tzinfo=datetime.timezone.utc)


def make_proposal(**overrides) -> PromotionProposal:
    """A valid proposal via propose_promotion (the sanctioned constructor)."""
    kwargs = dict(
        principal=PRINCIPAL,
        action_class=ACTION_CLASS,
        target_level=AutonomyLevel.on_loop,
        evidence_bundle="evidence-ref-001",
        proposer_id="human-proposer",
        proposal_id="prop-001",
        expires_at="2026-08-01T00:00:00+00:00",
        owner_id="alice",
        from_level=AutonomyLevel.in_loop,
        envelope_hash="sha256:abc",
        label_latency="P1D",
        demotion_triggers=[DemotionTrigger.stale_confidence, DemotionTrigger.budget_breach],
        last_safe_level=AutonomyLevel.in_loop,
        metrics=ActionClassMetrics(
            false_action_count=1, human_override_count=0, observation_count=100
        ),
        window_n=100,
        min_observations=10,
        threshold=0.05,
        artifact=_ARTIFACT,
        covered=True,
        provenance_maturity="signed-lineage",
        blast_class="low",
        error_budget=ErrorBudget(tolerance=0.5, spent=0.1),
    )
    kwargs.update(overrides)
    return PromotionCeremony.propose_promotion(
        kwargs.pop("principal"),
        kwargs.pop("action_class"),
        kwargs.pop("target_level"),
        kwargs.pop("evidence_bundle"),
        kwargs.pop("proposer_id"),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# JSON codec — the serialization the DynamoDB 'data' attribute stores
# ---------------------------------------------------------------------------


def test_json_round_trip_preserves_all_fields():
    original = make_proposal()
    restored = proposal_from_json(proposal_to_json(original))
    assert restored == original  # frozen dataclass equality covers every field


def test_json_round_trip_with_optional_fields_none():
    """Recommend-origin (from_level=None) + unset artifact/budget survive the codec."""
    original = make_proposal(
        from_level=None,
        target_level=AutonomyLevel.in_loop,
        artifact=None,
        error_budget=None,
    )
    restored = proposal_from_json(proposal_to_json(original))
    assert restored == original
    assert restored.from_level is None
    assert restored.artifact is None
    assert restored.error_budget is None


# ---------------------------------------------------------------------------
# proposal_expired — deterministic, fail-closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expires_at, expected",
    [
        ("2026-08-01T00:00:00+00:00", False),  # future
        ("2026-07-01T00:00:00+00:00", True),   # past
        ("2026-07-12T00:00:00+00:00", True),   # exactly now → expired (>= semantics)
        ("2026-08-01T00:00:00", False),        # naive future → read as UTC
        ("not-a-timestamp", True),             # unparseable → expired (fail closed)
        ("", True),
    ],
)
def test_proposal_expired(expires_at, expected):
    assert proposal_expired(expires_at, _NOW) is expected


def test_proposal_expired_naive_now_read_as_utc():
    naive_now = datetime.datetime(2026, 7, 12)
    assert proposal_expired("2026-08-01T00:00:00+00:00", naive_now) is False
    assert proposal_expired("2026-07-01T00:00:00+00:00", naive_now) is True


# ---------------------------------------------------------------------------
# InMemoryProposalStore
# ---------------------------------------------------------------------------


def test_put_then_get_round_trip():
    store = InMemoryProposalStore()
    proposal = make_proposal()
    store.put_proposal(proposal)

    result = store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001")
    assert result is not None
    restored, status = result
    assert restored == proposal
    assert status == "pending"


def test_get_missing_returns_none():
    store = InMemoryProposalStore()
    assert store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-absent") is None


def test_put_collision_raises():
    store = InMemoryProposalStore()
    store.put_proposal(make_proposal())
    with pytest.raises(ProposalAlreadyExistsError, match="never overwritten"):
        store.put_proposal(make_proposal())


def test_same_id_different_action_class_is_a_distinct_item():
    store = InMemoryProposalStore()
    store.put_proposal(make_proposal())
    store.put_proposal(make_proposal(action_class="email.draft"))  # no collision
    assert store.get_proposal(PRINCIPAL, "email.draft", "prop-001") is not None


def test_consume_flips_status_once():
    store = InMemoryProposalStore()
    store.put_proposal(make_proposal())

    store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", "ratified")
    _, status = store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001")
    assert status == "ratified"

    # The double-ratify race: the second consume hits the pending-only condition.
    with pytest.raises(ProposalConsumedError):
        store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", "ratified")


def test_consume_missing_proposal_raises():
    store = InMemoryProposalStore()
    with pytest.raises(ProposalConsumedError):
        store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-absent", "ratified")


def test_consume_rejects_invalid_status():
    store = InMemoryProposalStore()
    store.put_proposal(make_proposal())
    with pytest.raises(ValueError, match="ratified|rejected"):
        store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", "pending")


def test_reject_proposal_flips_to_rejected():
    store = InMemoryProposalStore()
    store.put_proposal(make_proposal())

    reject_proposal(store, PRINCIPAL, ACTION_CLASS, "prop-001")

    _, status = store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001")
    assert status == "rejected"
    # rejected is terminal too — ratifying afterwards is refused
    with pytest.raises(ProposalConsumedError):
        store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", "ratified")


def test_list_pending_filters_consumed():
    store = InMemoryProposalStore()
    store.put_proposal(make_proposal(proposal_id="prop-a"))
    store.put_proposal(make_proposal(proposal_id="prop-b"))
    store.put_proposal(make_proposal(proposal_id="prop-c"))
    store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-b", "ratified")
    store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-c", "rejected")

    pending = store.list_pending(PRINCIPAL, ACTION_CLASS)
    assert [p.proposal_id for p in pending] == ["prop-a"]


# ---------------------------------------------------------------------------
# Integrity — the stored proposal is HMAC'd; a tamper is refused loudly
# (proposals share the table the grant HMAC defends; an unsigned proposal
# would launder a table edit into a signed grant at ratify time)
# ---------------------------------------------------------------------------


def test_inmemory_get_refuses_tampered_data():
    store = InMemoryProposalStore()
    store.put_proposal(make_proposal())
    (key,) = store._items.keys()
    store._items[key]["data"] = store._items[key]["data"].replace(
        '"on-loop"', '"out-of-loop"'
    )

    with pytest.raises(ProposalIntegrityError, match="hash mismatch"):
        store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001")


def test_inmemory_list_pending_refuses_tampered_data():
    store = InMemoryProposalStore()
    store.put_proposal(make_proposal())
    (key,) = store._items.keys()
    store._items[key]["data"] = store._items[key]["data"].replace(
        '"on-loop"', '"out-of-loop"'
    )

    with pytest.raises(ProposalIntegrityError, match="hash mismatch"):
        store.list_pending(PRINCIPAL, ACTION_CLASS)


def test_inmemory_untampered_round_trip_verifies():
    """The verify-on-read contract passes cleanly for untampered content."""
    store = InMemoryProposalStore()
    store.put_proposal(make_proposal())
    restored, status = store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001")
    assert restored == make_proposal()
    assert status == "pending"


def test_compute_proposal_hash_is_keyed_and_content_sensitive():
    data = proposal_to_json(make_proposal())
    assert compute_proposal_hash(data, TEST_HMAC_KEY) == compute_proposal_hash(
        data, TEST_HMAC_KEY
    )
    assert compute_proposal_hash(data, TEST_HMAC_KEY) != compute_proposal_hash(
        data, b"other-key"
    )
    other = proposal_to_json(make_proposal(owner_id="mallory"))
    assert compute_proposal_hash(data, TEST_HMAC_KEY) != compute_proposal_hash(
        other, TEST_HMAC_KEY
    )


# ---------------------------------------------------------------------------
# DynamoDBProposalStore — expression shape + error mapping (mock boto3)
# ---------------------------------------------------------------------------


def _mock_table() -> tuple[MagicMock, MagicMock]:
    session = MagicMock()
    table = MagicMock()
    session.resource.return_value.Table.return_value = table
    return session, table


def _conditional_failure(op: str):
    from botocore.exceptions import ClientError

    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "The conditional request failed"}},
        op,
    )


def test_dynamo_put_item_layout():
    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    session, table = _mock_table()

    store.put_proposal(make_proposal(), session=session)

    kwargs = table.update_item.call_args.kwargs
    assert kwargs["Key"] == {
        "pk": "PROPOSAL#agent-prop#email#alice#B#email.send",
        "sk": "prop-001",
    }
    assert kwargs["ConditionExpression"] == "attribute_not_exists(pk)"
    # 'data' and 'status' are DynamoDB-reserved words
    assert kwargs["ExpressionAttributeNames"] == {"#data": "data", "#status": "status"}
    values = kwargs["ExpressionAttributeValues"]
    assert values[":status"] == "pending"
    assert values[":expires_at"] == "2026-08-01T00:00:00+00:00"
    assert proposal_from_json(values[":data"]) == make_proposal()
    # The stored content is HMAC'd with the injected key (verified on read)
    assert values[":proposal_hash"] == compute_proposal_hash(values[":data"], TEST_HMAC_KEY)
    assert "proposalHash = :proposal_hash" in kwargs["UpdateExpression"]


def test_dynamo_put_collision_maps_to_already_exists():
    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    session, table = _mock_table()
    table.update_item.side_effect = _conditional_failure("UpdateItem")

    with pytest.raises(ProposalAlreadyExistsError):
        store.put_proposal(make_proposal(), session=session)


def test_dynamo_consume_expression_shape():
    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    session, table = _mock_table()

    store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", "ratified", session=session)

    kwargs = table.update_item.call_args.kwargs
    assert kwargs["UpdateExpression"] == "SET #status = :new_status"
    assert kwargs["ConditionExpression"] == "attribute_exists(pk) AND #status = :pending"
    assert kwargs["ExpressionAttributeValues"] == {
        ":new_status": "ratified",
        ":pending": "pending",
    }


def test_dynamo_consume_conditional_failure_maps_to_consumed():
    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    session, table = _mock_table()
    table.update_item.side_effect = _conditional_failure("UpdateItem")

    with pytest.raises(ProposalConsumedError):
        store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", "ratified", session=session)


def test_dynamo_access_denied_propagates():
    """AccessDenied is NOT mapped to a domain error — the caller must see it."""
    from botocore.exceptions import ClientError

    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    session, table = _mock_table()
    table.update_item.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "User is not authorized"}},
        "UpdateItem",
    )

    with pytest.raises(ClientError):
        store.put_proposal(make_proposal(), session=session)
    with pytest.raises(ClientError):
        store.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", "ratified", session=session)


def _captured_item(store: DynamoDBProposalStore) -> dict:
    """Put a proposal against a mock table and return the item it would store."""
    put_session, put_table = _mock_table()
    store.put_proposal(make_proposal(), session=put_session)
    put_kwargs = put_table.update_item.call_args.kwargs
    return {
        **put_kwargs["Key"],
        "data": put_kwargs["ExpressionAttributeValues"][":data"],
        "proposalHash": put_kwargs["ExpressionAttributeValues"][":proposal_hash"],
        "status": put_kwargs["ExpressionAttributeValues"][":status"],
        "expires_at": put_kwargs["ExpressionAttributeValues"][":expires_at"],
    }


def test_dynamo_get_round_trips_captured_item():
    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    item = _captured_item(store)

    get_session, get_table = _mock_table()
    get_table.get_item.return_value = {"Item": item}
    result = store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", session=get_session)

    assert result is not None
    restored, status = result
    assert restored == make_proposal()
    assert status == "pending"


def test_dynamo_get_refuses_tampered_data():
    """A PROPOSAL# item whose data was edited in the table (hash attribute
    untouched) is refused loudly — never served into a ratification."""
    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    item = _captured_item(store)
    item["data"] = item["data"].replace('"on-loop"', '"out-of-loop"')

    get_session, get_table = _mock_table()
    get_table.get_item.return_value = {"Item": item}
    with pytest.raises(ProposalIntegrityError, match="hash mismatch"):
        store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", session=get_session)


def test_dynamo_get_refuses_missing_hash():
    """An item with NO proposalHash (stripped, or written outside the store)
    is equally refused — unsigned proposals are a laundering path."""
    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    item = _captured_item(store)
    del item["proposalHash"]

    get_session, get_table = _mock_table()
    get_table.get_item.return_value = {"Item": item}
    with pytest.raises(ProposalIntegrityError):
        store.get_proposal(PRINCIPAL, ACTION_CLASS, "prop-001", session=get_session)


def test_dynamo_list_pending_refuses_tampered_data():
    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    item = _captured_item(store)
    item["data"] = item["data"].replace('"on-loop"', '"out-of-loop"')

    session, table = _mock_table()
    table.query.return_value = {"Items": [item]}
    with pytest.raises(ProposalIntegrityError, match="hash mismatch"):
        store.list_pending(PRINCIPAL, ACTION_CLASS, session=session)


def test_dynamo_list_pending_query_shape():
    store = DynamoDBProposalStore(hmac_key=TEST_HMAC_KEY, table_name="grants-test")
    session, table = _mock_table()
    data = proposal_to_json(make_proposal())
    table.query.return_value = {
        "Items": [
            {
                "sk": "prop-001",
                "data": data,
                "proposalHash": compute_proposal_hash(data, TEST_HMAC_KEY),
            }
        ]
    }

    pending = store.list_pending(PRINCIPAL, ACTION_CLASS, session=session)

    assert [p.proposal_id for p in pending] == ["prop-001"]
    kwargs = table.query.call_args.kwargs
    assert kwargs["KeyConditionExpression"] == "pk = :pk"
    assert kwargs["FilterExpression"] == "#status = :pending"
    assert kwargs["ExpressionAttributeValues"] == {
        ":pk": "PROPOSAL#agent-prop#email#alice#B#email.send",
        ":pending": "pending",
    }
