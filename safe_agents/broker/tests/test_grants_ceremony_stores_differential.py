"""Differential suite for the grant ceremony's auxiliary stores (#247).

ONE contract, THREE backends, for the two stores that had no sqlite arm until
this slice: the promotion-proposal store (PROPOSAL# items — the ceremony's only
cross-process state, since propose and ratify are separate invocations by
separate identities) and the acknowledgment store (ACK# items, #196).

The clause worth naming is :class:`TestStoredBytesAgreeAcrossArms`. Today's
#226 drill found that the MCP sqlite arm serialized ledger records differently
from its Dynamo twin — declaration order vs the canonical sorted-key form the
signature binds — so every signed record that arm wrote was unverifiable from
birth, and four suites missed it because they all verified a RE-SERIALIZATION
of the parsed object rather than the bytes the store actually held. These
stores carry the same hazard on two axes (the proposal HMAC basis and the
acknowledgment's signed payload), so the pin goes in with the implementation
rather than after the next drill.

Each backend harness exposes out-of-band tamper/raw-read helpers: tamper must
bypass the store API by definition, and "the store holds exactly these bytes"
cannot be asked of the API under test. The moto backend importorskips per-param
so the memory/sqlite rows run AWS-free.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from safe_agents.broker.grants.acknowledgments import (
    AcknowledgmentAlreadyExistsError,
    AcknowledgmentRecord,
    InMemoryAcknowledgmentStore,
    canonical_ack_payload,
    violation_detail_digest,
)
from safe_agents.broker.grants.ceremony import PromotionCeremony
from safe_agents.broker.grants.predicate import ActionClassMetrics
from safe_agents.broker.grants.proposals import (
    InMemoryProposalStore,
    ProposalAlreadyExistsError,
    ProposalConsumedError,
    ProposalIntegrityError,
    _proposal_pk,
    proposal_to_json,
)
from safe_agents.broker.grants.sqlite_ceremony_stores import (
    SqliteAcknowledgmentStore,
    SqliteProposalStore,
)
from safe_agents.broker.schemas.budgets import ErrorBudget
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal
from safe_agents.broker.schemas.evidence import ConfidenceArtifact, SelfConsistencyEvidence

HMAC_KEY = b"test-hmac-key"
PRINCIPAL = Principal(agentId="agent-prop", skill="email", user="alice", tier="B")
ACTION_CLASS = "email.send"
PROPOSAL_ID = "prop-001"
TS = "2026-07-25T12:00:00+00:00"

_ARTIFACT = ConfidenceArtifact(
    confidence=0.9,
    error_prob=0.1,
    evidence=SelfConsistencyEvidence(samples=5, agreement=0.9),
    computed_at="2026-07-25T00:00:00+00:00",
)


def make_proposal(proposal_id: str = PROPOSAL_ID):
    return PromotionCeremony.propose_promotion(
        PRINCIPAL,
        ACTION_CLASS,
        AutonomyLevel.on_loop,
        "evidence-ref-001",
        "human-proposer",
        proposal_id=proposal_id,
        expires_at="2026-08-01T00:00:00+00:00",
        owner_id="alice",
        from_level=AutonomyLevel.in_loop,
        envelope_hash="sha256:abc",
        label_latency="P1D",
        demotion_triggers=[DemotionTrigger.stale_confidence],
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


def make_ack(rule: str = "LEDGER_COUNTERPART", ts: str = TS) -> AcknowledgmentRecord:
    return AcknowledgmentRecord(
        rule=rule,
        coordinate="agent-prop#email#alice#B#email.send",
        detailDigest=violation_detail_digest("the exact finding detail"),
        rationale="accepted as-is",
        acknowledgedBy="arn:aws:sts::1:assumed-role/CheckerRole/maintainer",
        ts=ts,
    )


# ===========================================================================
# Backend harnesses
# ===========================================================================


class MemoryBackend:
    name = "memory"

    def __init__(self) -> None:
        self.proposals = InMemoryProposalStore(hmac_key=HMAC_KEY)
        self.acks = InMemoryAcknowledgmentStore()

    def tamper_proposal(self, proposal_id: str = PROPOSAL_ID) -> None:
        item = self.proposals._items[(_proposal_pk(PRINCIPAL, ACTION_CLASS), proposal_id)]
        item["data"] = item["data"].replace("evidence-ref-001", "evidence-ref-666")

    def raw_proposal_data(self, proposal_id: str = PROPOSAL_ID) -> str:
        return self.proposals._items[
            (_proposal_pk(PRINCIPAL, ACTION_CLASS), proposal_id)
        ]["data"]

    def raw_ack_data(self) -> str:
        return self.acks.items()[0]["data"]

    def raw_ack_signature(self) -> str:
        return self.acks.items()[0]["signature"]

    def raw_ack_key(self) -> tuple[str, str]:
        item = self.acks.items()[0]
        return item["pk"], item["sk"]


class SqliteBackend:
    name = "sqlite"

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.proposals = SqliteProposalStore(HMAC_KEY, db_path)
        self.acks = SqliteAcknowledgmentStore(db_path)

    def _raw_conn(self):
        # A REAL second connection: out-of-band access must not ride the
        # store's own handle, or a single-connection bug could hide.
        import sqlite3

        return sqlite3.connect(str(self.db_path))

    def _read(self, pk: str, sk: str) -> dict:
        with self._raw_conn() as conn:
            (item,) = conn.execute(
                "SELECT item FROM items WHERE pk = ? AND sk = ?", (pk, sk)
            ).fetchone()
        return json.loads(item)

    def tamper_proposal(self, proposal_id: str = PROPOSAL_ID) -> None:
        pk = _proposal_pk(PRINCIPAL, ACTION_CLASS)
        attrs = self._read(pk, proposal_id)
        attrs["data"] = attrs["data"].replace("evidence-ref-001", "evidence-ref-666")
        with self._raw_conn() as conn:
            conn.execute(
                "UPDATE items SET item = ? WHERE pk = ? AND sk = ?",
                (json.dumps(attrs, sort_keys=True, ensure_ascii=True), pk, proposal_id),
            )

    def raw_proposal_data(self, proposal_id: str = PROPOSAL_ID) -> str:
        return self._read(_proposal_pk(PRINCIPAL, ACTION_CLASS), proposal_id)["data"]

    def raw_ack_data(self) -> str:
        return self.acks.items()[0]["data"]

    def raw_ack_signature(self) -> str:
        return self.acks.items()[0]["signature"]

    def raw_ack_key(self) -> tuple[str, str]:
        item = self.acks.items()[0]
        return item["pk"], item["sk"]


class DynamoBackend:
    name = "dynamo"
    REGION = "us-east-1"
    TABLE = "safe-agents-grants-ceremony-differential"

    def __init__(self, boto3_module, proposals, acks) -> None:
        self._boto3 = boto3_module
        self.proposals = proposals
        self.acks = acks

    def _table(self):
        return self._boto3.resource("dynamodb", region_name=self.REGION).Table(self.TABLE)

    def _get(self, pk: str, sk: str) -> dict:
        return self._table().get_item(Key={"pk": pk, "sk": sk})["Item"]

    def tamper_proposal(self, proposal_id: str = PROPOSAL_ID) -> None:
        pk = _proposal_pk(PRINCIPAL, ACTION_CLASS)
        item = self._get(pk, proposal_id)
        self._table().update_item(
            Key={"pk": pk, "sk": proposal_id},
            UpdateExpression="SET #d = :d",
            ExpressionAttributeNames={"#d": "data"},
            ExpressionAttributeValues={
                ":d": item["data"].replace("evidence-ref-001", "evidence-ref-666")
            },
        )

    def raw_proposal_data(self, proposal_id: str = PROPOSAL_ID) -> str:
        return self._get(_proposal_pk(PRINCIPAL, ACTION_CLASS), proposal_id)["data"]

    def raw_ack_data(self) -> str:
        ack = make_ack()
        return self._get(f"ACK#{ack.coordinate}", f"{ack.ts}#{ack.rule}")["data"]

    def raw_ack_signature(self) -> str:
        ack = make_ack()
        return self._get(f"ACK#{ack.coordinate}", f"{ack.ts}#{ack.rule}")["signature"]

    def raw_ack_key(self) -> tuple[str, str]:
        ack = make_ack()
        item = self._get(f"ACK#{ack.coordinate}", f"{ack.ts}#{ack.rule}")
        return item["pk"], item["sk"]


@pytest.fixture(params=["memory", "sqlite", "dynamo"])
def backend(request, tmp_path):
    if request.param == "memory":
        yield MemoryBackend()
        return
    if request.param == "sqlite":
        yield SqliteBackend(tmp_path / "broker.db")
        return
    pytest.importorskip("moto", reason="moto is required for the dynamo differential row")
    boto3 = pytest.importorskip("boto3", reason="boto3 is required for the dynamo row")
    for var in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SECURITY_TOKEN",
        "AWS_SESSION_TOKEN",
    ):
        os.environ.setdefault(var, "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    from moto import mock_aws

    from safe_agents.broker.grants.acknowledgments import DynamoDBAcknowledgmentStore
    from safe_agents.broker.grants.proposals import DynamoDBProposalStore

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name=DynamoBackend.REGION)
        ddb.create_table(
            TableName=DynamoBackend.TABLE,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        ).wait_until_exists()
        yield DynamoBackend(
            boto3,
            DynamoDBProposalStore(hmac_key=HMAC_KEY, table_name=DynamoBackend.TABLE),
            DynamoDBAcknowledgmentStore(table_name=DynamoBackend.TABLE),
        )


# ===========================================================================
# Proposal store — one contract, three backends
# ===========================================================================


class TestProposalStoreContract:
    def test_put_then_get_round_trips_and_starts_pending(self, backend):
        proposal = make_proposal()
        backend.proposals.put_proposal(proposal)
        loaded, status = backend.proposals.get_proposal(PRINCIPAL, ACTION_CLASS, PROPOSAL_ID)
        assert loaded == proposal  # frozen dataclass equality — every field
        assert status == "pending"

    def test_get_absent_is_none_not_an_error(self, backend):
        assert backend.proposals.get_proposal(PRINCIPAL, ACTION_CLASS, "nope") is None

    def test_proposals_are_append_only(self, backend):
        backend.proposals.put_proposal(make_proposal())
        with pytest.raises(ProposalAlreadyExistsError):
            backend.proposals.put_proposal(make_proposal())

    @pytest.mark.parametrize("new_status", ["ratified", "rejected"])
    def test_consume_is_single_shot(self, backend, new_status):
        backend.proposals.put_proposal(make_proposal())
        backend.proposals.consume_proposal(PRINCIPAL, ACTION_CLASS, PROPOSAL_ID, new_status)
        _, status = backend.proposals.get_proposal(PRINCIPAL, ACTION_CLASS, PROPOSAL_ID)
        assert status == new_status
        # The double-ratify race is killed by the store, not caller courtesy.
        with pytest.raises(ProposalConsumedError):
            backend.proposals.consume_proposal(
                PRINCIPAL, ACTION_CLASS, PROPOSAL_ID, new_status
            )

    def test_consuming_an_absent_proposal_refuses(self, backend):
        with pytest.raises(ProposalConsumedError):
            backend.proposals.consume_proposal(PRINCIPAL, ACTION_CLASS, "nope", "ratified")

    def test_consume_rejects_an_unknown_status(self, backend):
        backend.proposals.put_proposal(make_proposal())
        with pytest.raises(ValueError):
            backend.proposals.consume_proposal(
                PRINCIPAL, ACTION_CLASS, PROPOSAL_ID, "quietly-approved"
            )

    def test_list_pending_returns_only_pending(self, backend):
        backend.proposals.put_proposal(make_proposal("prop-a"))
        backend.proposals.put_proposal(make_proposal("prop-b"))
        backend.proposals.consume_proposal(PRINCIPAL, ACTION_CLASS, "prop-a", "ratified")
        pending = backend.proposals.list_pending(PRINCIPAL, ACTION_CLASS)
        assert [p.proposal_id for p in pending] == ["prop-b"]

    def test_a_tampered_proposal_refuses_loudly_on_read(self, backend):
        backend.proposals.put_proposal(make_proposal())
        backend.tamper_proposal()
        with pytest.raises(ProposalIntegrityError):
            backend.proposals.get_proposal(PRINCIPAL, ACTION_CLASS, PROPOSAL_ID)

    def test_a_tampered_proposal_refuses_in_the_listing_too(self, backend):
        """Never SKIPPED out of the listing: silence would read as "no pending
        proposal", which is the tamper achieving exactly what it wanted."""
        backend.proposals.put_proposal(make_proposal())
        backend.tamper_proposal()
        with pytest.raises(ProposalIntegrityError):
            backend.proposals.list_pending(PRINCIPAL, ACTION_CLASS)

    def test_consume_does_not_disturb_the_content_or_its_hash(self, backend):
        """The status flip is item-level; the HMAC covers the immutable content
        only, so a consumed proposal must still read back intact."""
        proposal = make_proposal()
        backend.proposals.put_proposal(proposal)
        before = backend.raw_proposal_data()
        backend.proposals.consume_proposal(PRINCIPAL, ACTION_CLASS, PROPOSAL_ID, "ratified")
        assert backend.raw_proposal_data() == before
        loaded, status = backend.proposals.get_proposal(PRINCIPAL, ACTION_CLASS, PROPOSAL_ID)
        assert loaded == proposal and status == "ratified"


# ===========================================================================
# Acknowledgment store — one contract, three backends
# ===========================================================================


class TestAcknowledgmentStoreContract:
    def test_append_then_read_back(self, backend):
        """Runs on EVERY backend — deliberately keyed off the harness's raw
        reader rather than an `items()` only some stores implement, since a
        clause that silently skips a row is worse than no clause at all."""
        ack = make_ack()
        envelope = {"payloadType": "application/vnd.test+json", "payload": "e30=", "signatures": []}
        backend.acks.append_acknowledgment(ack, envelope)
        assert backend.raw_ack_key() == (f"ACK#{ack.coordinate}", f"{ack.ts}#{ack.rule}")
        assert json.loads(backend.raw_ack_signature()) == envelope

    def test_acknowledgments_are_append_only(self, backend):
        ack = make_ack()
        envelope = {"payloadType": "t", "payload": "e30=", "signatures": []}
        backend.acks.append_acknowledgment(ack, envelope)
        with pytest.raises(AcknowledgmentAlreadyExistsError):
            backend.acks.append_acknowledgment(ack, envelope)

    def test_a_different_rule_at_the_same_coordinate_is_a_distinct_slot(self, backend):
        envelope = {"payloadType": "t", "payload": "e30=", "signatures": []}
        backend.acks.append_acknowledgment(make_ack("LEDGER_COUNTERPART"), envelope)
        backend.acks.append_acknowledgment(make_ack("GRANT_ENVELOPE_IN_FORCE"), envelope)


# ===========================================================================
# The bytes each arm actually stores — the #246 pin, applied preemptively
#
# The hazard this closes: an arm that persists a DIFFERENT serialization from
# its sibling passes every round-trip test (a parser does not care about key
# order) while silently breaking the integrity basis computed over those bytes.
# That is exactly how the MCP sqlite arm shipped unverifiable signed records.
# ===========================================================================


class TestStoredBytesAgreeAcrossArms:
    def test_stored_proposal_bytes_are_the_canonical_serialization(self, backend):
        proposal = make_proposal()
        backend.proposals.put_proposal(proposal)
        assert backend.raw_proposal_data() == proposal_to_json(proposal), (
            f"{backend.name} stored a non-canonical proposal serialization; the "
            "HMAC basis is these bytes, so a divergent arm silently breaks "
            "integrity verification rather than failing loudly"
        )

    def test_stored_ack_bytes_are_the_canonical_payload(self, backend):
        ack = make_ack()
        backend.acks.append_acknowledgment(
            ack, {"payloadType": "t", "payload": "e30=", "signatures": []}
        )
        assert backend.raw_ack_data() == canonical_ack_payload(ack), (
            f"{backend.name} stored a non-canonical acknowledgment payload; the "
            "issuer DSSE signature binds these bytes verbatim (#246)"
        )


# ===========================================================================
# sqlite-specific: cross-process visibility, the property WAL is here for
# ===========================================================================


class TestSqliteCrossConnection:
    def test_a_proposal_written_by_the_cli_is_visible_to_another_process(self, tmp_path):
        """propose and ratify are separate invocations — if this did not hold,
        the ceremony could not run locally at all."""
        db = tmp_path / "broker.db"
        maker = SqliteProposalStore(HMAC_KEY, db)
        checker = SqliteProposalStore(HMAC_KEY, db)
        maker.put_proposal(make_proposal())
        loaded, status = checker.get_proposal(PRINCIPAL, ACTION_CLASS, PROPOSAL_ID)
        assert loaded is not None and status == "pending"
        checker.consume_proposal(PRINCIPAL, ACTION_CLASS, PROPOSAL_ID, "ratified")
        # ...and the maker's connection sees the burn, so a re-ratify refuses.
        with pytest.raises(ProposalConsumedError):
            maker.consume_proposal(PRINCIPAL, ACTION_CLASS, PROPOSAL_ID, "ratified")

    def test_a_wrong_hmac_key_refuses_rather_than_serving(self, tmp_path):
        db = tmp_path / "broker.db"
        SqliteProposalStore(HMAC_KEY, db).put_proposal(make_proposal())
        with pytest.raises(ProposalIntegrityError):
            SqliteProposalStore(b"a-different-key", db).get_proposal(
                PRINCIPAL, ACTION_CLASS, PROPOSAL_ID
            )
