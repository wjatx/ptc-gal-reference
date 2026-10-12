"""Shared fixtures for the issuer-standing tests (GAL-41, #179).

One world: a standing authority, two issuer keys and an evaluator key; an issuer
standing document served from a mutable slot; and a grant at ``on-loop`` whose
level rests on a promotion signed by ``issuer-a``. Tests change the world by
publishing a new document version and moving the clock.
"""

from __future__ import annotations

import datetime
import json

from safe_agents.broker.grants import key_standing as ks
from safe_agents.broker.grants import standing_source as ss
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore
from safe_agents.broker.grants.grant_standing import GrantStandingCheck
from safe_agents.broker.grants.record_signing import (
    EVALUATOR_ROLE,
    ISSUER_ROLE,
    RoleKeyResolvers,
)
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER
from safe_agents.broker.tests.test_grant_term_lapse import ACTION_CLASS, ENV_HASH, PRINCIPAL
from safe_agents.broker.tests.test_key_standing import keypair
from safe_agents.channels.keys import key_resolver_from_map

IN, ON, OUT = AutonomyLevel.in_loop, AutonomyLevel.on_loop, AutonomyLevel.out_of_loop
UTC = datetime.UTC
HOUR = datetime.timedelta(hours=1)
MAX_AGE = 4 * HOUR
T0 = datetime.datetime(2026, 10, 1, tzinfo=UTC)  # the first document's issuedAt
BOOTSTRAP_TS = "2026-09-01T00:00:00+00:00"
PROMOTION_TS = "2026-09-02T00:00:00+00:00"
HMAC_KEY = b"standing-test-hmac-key"


class Clock:
    def __init__(self, now: datetime.datetime) -> None:
        self.now = now

    def __call__(self) -> datetime.datetime:
        return self.now


def grant(**overrides) -> Grant:
    base = dict(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level=ON,
        envelopeHash=ENV_HASH,
        promotedBy="checker-bob",
        evidence="evidence-ref",
        ts=PROMOTION_TS,
        lastSafeLevel=IN,
        demotionTriggers=[],
        demotionReason=None,
        labelLatency="PT1H",
        ownerId="owner:ops",
    )
    base.update(overrides)
    return Grant(**base)


def record(record_type: str, ts: str, **overrides) -> PromotionRecord:
    shapes = {
        "bootstrap": dict(fromLevel=None, toLevel=IN, proposedBy="seeder", ratifiedBy="seeder"),
        "promotion": dict(
            fromLevel=IN, toLevel=ON, predicate="predicate passed",
            proposedBy="maker-alice", ratifiedBy="checker-bob",
        ),
        "reattestation": dict(fromLevel=ON, toLevel=ON, proposedBy="op", ratifiedBy="op"),
        "demotion": dict(
            fromLevel=ON, toLevel=IN, proposedBy=DEMOTION_RATIFIER, ratifiedBy=DEMOTION_RATIFIER,
            triggeredBy=["budget_breach"], demotionReason="failing",
        ),
        "withdrawal": dict(
            fromLevel=ON, toLevel=IN, proposedBy=DEMOTION_RATIFIER, ratifiedBy=DEMOTION_RATIFIER,
            demotionReason="pending-evidence",
        ),
    }
    fields = dict(
        recordType=record_type,
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        evidence="evidence-ref",
        envelopeHash=ENV_HASH,
        ts=ts,
        **shapes[record_type],
    )
    fields.update(overrides)
    return PromotionRecord(**fields)


class World:
    """Keys, a served issuer document, a ledger and a grant, all mutable."""

    def __init__(self) -> None:
        self.authority, self.authority_pem = keypair("authority-1")
        self.keys = {name: keypair(name) for name in ("issuer-a", "issuer-b", "issuer-c")}
        self.evaluator, self.evaluator_pem = keypair("evaluator-e")
        entries = ks.add_key({}, "issuer-a", self.keys["issuer-a"][1])
        entries = ks.add_key(entries, "issuer-b", self.keys["issuer-b"][1])
        self.document = ks.next_document(
            None, role=ISSUER_ROLE, keys=entries, issued_at=T0, signer=self.authority
        )
        self.served = {"text": ks.sign_standing_document(self.document, self.authority)}
        self.clock = Clock(T0 + datetime.timedelta(minutes=5))
        self.source = self._source(ISSUER_ROLE, self.served)
        self.grants = InMemoryGrantStore(hmac_key=HMAC_KEY)
        self.records = InMemoryPromotionRecordStore()

    def _source(self, role, served) -> ss.StandingSource:
        return ss.StandingSource(
            role=role,
            fetch=lambda: served["text"],
            source_label=f"test-{role}",
            authority=key_resolver_from_map({"authority-1": self.authority_pem}),
            authority_key_ids=frozenset({"authority-1"}),
            authority_public_keys=frozenset({ks.public_key_raw(self.authority_pem)}),
            max_age=MAX_AGE,
            clock=self.clock,
        )

    # -- the ledger ------------------------------------------------------------

    def write(self, rec: PromotionRecord, new_grant: Grant, *, signer="issuer-a") -> None:
        """Append ``rec`` beside ``new_grant`` through the paired write seam."""
        current = self.grants.get_grant(PRINCIPAL, ACTION_CLASS)
        signature = None
        if signer == "evaluator":
            signature = self.evaluator.sign_record(rec)
        elif signer is not None:
            signature = self.keys[signer][0].sign_record(rec)
        self.grants.write_record_and_grant(
            rec, new_grant, self.records, signature=signature,
            expected=current if current.grant is not None else None,
        )

    def promoted(self, *, signer="issuer-a", bootstrap_signer="issuer-a") -> Grant:
        """Bootstrap at in-loop, then a promotion to on-loop; returns the stored grant."""
        self.write(record("bootstrap", BOOTSTRAP_TS), grant(level=IN, ts=BOOTSTRAP_TS),
                   signer=bootstrap_signer)
        self.write(record("promotion", PROMOTION_TS), grant(), signer=signer)
        return self.stored_grant()

    def stored_grant(self) -> Grant:
        return self.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant

    def items(self) -> list[dict]:
        """The grant and its ledger as table items, the shape the audit loads."""
        items = [
            {"pk": f"GRANT#{principal_key}", "sk": f"CLASS#{action_class}", **item}
            for (principal_key, action_class), item in self.grants._store.items()
        ]
        for (pk, sk), (data, signature) in self.records._records.items():
            item = {"pk": f"RECORD#{pk}", "sk": sk, "data": data}
            if signature is not None:
                item["signature"] = json.dumps(signature, sort_keys=True)
            items.append(item)
        return items

    # -- the document ----------------------------------------------------------

    def publish(self, entries, *, at: datetime.datetime) -> None:
        self.document = ks.next_document(
            self.document, role=ISSUER_ROLE, keys=entries, issued_at=at, signer=self.authority
        )
        self.served["text"] = ks.sign_standing_document(self.document, self.authority)

    def withdraw(self, key_id="issuer-a", *, reason="keyCompromise", at=None) -> None:
        at = at or self.clock.now
        self.publish(ks.withdraw_key(self.document.keys, key_id, reason, at), at=at)

    def retire(self, key_id="issuer-a", *, at=None) -> None:
        at = at or self.clock.now
        self.publish(ks.retire_key(self.document.keys, key_id, "superseded", at), at=at)

    def check(self, **kwargs) -> GrantStandingCheck:
        return GrantStandingCheck(source=self.source, records=self.records, **kwargs)

    def evaluator_source(self, *, withdrawn: bool) -> ss.StandingSource:
        entries = ks.add_key({}, "evaluator-e", self.evaluator_pem)
        doc = ks.next_document(
            None, role=EVALUATOR_ROLE, keys=entries, issued_at=T0, signer=self.authority
        )
        if withdrawn:
            doc = ks.next_document(
                doc, role=EVALUATOR_ROLE,
                keys=ks.withdraw_key(doc.keys, "evaluator-e", "keyCompromise", T0),
                issued_at=T0, signer=self.authority,
            )
        source = self._source(EVALUATOR_ROLE, {"text": ks.sign_standing_document(doc, self.authority)})
        assert source.refresh().accepted
        return source

    def resolvers(self, *, evaluator_withdrawn: bool | None = None) -> RoleKeyResolvers:
        """Both roles' verify keys as an audit holds them, with standing where given."""
        self.source.refresh()
        standing = {ISSUER_ROLE: self.source}
        evaluator = key_resolver_from_map({"evaluator-e": self.evaluator_pem})
        if evaluator_withdrawn is not None:
            evaluator_source = self.evaluator_source(withdrawn=evaluator_withdrawn)
            standing[EVALUATOR_ROLE] = evaluator_source
            evaluator = evaluator_source.key_resolver()
        return RoleKeyResolvers(
            issuer=self.source.key_resolver(), evaluator=evaluator, standing=standing
        )
