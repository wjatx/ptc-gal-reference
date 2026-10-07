"""The retired `Envelope.allowlists` block (#135) on the operator-facing paths.

`test_envelope_allowlists_retired.py` pins the schema and the stores. This file
pins what an operator meets on a floor that still holds an envelope row stored
before the retirement, or a manifest that still carries the block:

  - the broker does not boot in store mode, and does not fall back to the
    manifest's envelope to get there;
  - a ceremony command says the seeded row is refused and why, and never that
    no envelope is seeded;
  - the seed CLI fails in its own voice and writes nothing;
  - the ledger audit reports the row as an UNPARSEABLE_ITEM, which no
    acknowledgment can waive, and never takes it as the envelope in force.
"""

from __future__ import annotations

import json

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from safe_agents.broker.envelope import InMemoryEnvelopeStore
from safe_agents.broker.envelope import store as envelope_store_module
from safe_agents.broker.grants._commands_common import _resolve_envelope_hash
from safe_agents.broker.grants.acknowledgments import (
    WAIVABLE_RULES,
    AcknowledgmentRecord,
    canonical_ack_payload,
    sign_acknowledgment,
    violation_detail_digest,
)
from safe_agents.broker.grants.audit import (
    ACKNOWLEDGMENT_NOT_WAIVABLE,
    UNPARSEABLE_ITEM,
    dataset_from_items,
    run_audit,
)
from safe_agents.broker.grants.record_signing import signer_from_pem
from safe_agents.broker.grants.runner import RunnerConfigError
from safe_agents.broker.prototype import seed_envelope as seed_cli
from safe_agents.broker.prototype.broker_server import build_runtime
from safe_agents.broker.schemas import AgentManifest, Envelope
from safe_agents.broker.tests.allowlists_retired_scaffold import (
    A1,
    RETIRED_VALUES,
    assert_names_the_retirement,
    envelope_row,
    in_memory_store_holding,
    refusing_the_retired_key,
    stored_dump_before_retirement,
)
from safe_agents.broker.tests.scaffold import PRINCIPAL, PRINCIPAL_DATA
from safe_agents.channels.keys import key_resolver_from_map

A1_AUDIT = (
    "A1 (the allowlists field is gone and refused by name): a stored envelope row "
    "carrying the retired key is an unparseable item, never waivable, never the "
    "envelope in force"
)

_STORED = stored_dump_before_retirement(Envelope(polarity="abstain"))


# ---------------------------------------------------------------------------
# A1: broker boot in store mode
# ---------------------------------------------------------------------------


def _manifest() -> AgentManifest:
    """A manifest whose own envelope is valid, so a boot that falls back to it
    after the stored row is refused would succeed and be caught here."""
    return AgentManifest.model_validate(
        {
            "envelope": {"polarity": "abstain", "caps": {"actions_per_run": 7}},
            "principal": PRINCIPAL_DATA,
            "grant_classes": ["search.query", "notify.send"],
            "connectors": ["github", "search"],
        }
    )


def test_the_broker_does_not_boot_on_a_row_stored_before_the_retirement(monkeypatch):
    """In store mode the stored row is the envelope in force. A row the schema
    refuses must stop the boot. Starting under the manifest's envelope instead
    would enforce an envelope nobody seeded."""
    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")

    with refusing_the_retired_key("build_runtime in store mode"):
        build_runtime(_manifest(), envelope_store=in_memory_store_holding(_STORED))


# ---------------------------------------------------------------------------
# A1: the ceremony's store-mode envelope read
# ---------------------------------------------------------------------------


def test_a_ceremony_names_the_refused_row_and_not_a_missing_seed(monkeypatch):
    """`propose`, `ratify`, `seed` and `re-seed` stamp the hash of the in-force
    envelope. Against a pre-retirement row they must refuse cleanly, say the
    row is refused and why, and not tell the operator that nothing is seeded:
    a row IS seeded, and "run seed_envelope FIRST" hides the reason."""
    monkeypatch.setenv("BROKER_ENVELOPE_LOAD", "store")
    monkeypatch.setenv("BROKER_STORE", "dynamo")
    monkeypatch.setattr(
        envelope_store_module,
        "DynamoDBEnvelopeStore",
        lambda table_name: in_memory_store_holding(_STORED),
    )

    with refusing_the_retired_key(
        "the ceremony's store-mode envelope read", raises=RunnerConfigError
    ) as refusal:
        _resolve_envelope_hash(PRINCIPAL, "grants")

    assert "no envelope is seeded" not in refusal.message, (
        f"{A1}: the ceremony reports a refused pre-retirement row as a missing seed: "
        f"{refusal.message!r}"
    )
    assert "refused by the envelope schema" in refusal.message, (
        f"{A1}: the ceremony does not say the seeded row was refused: {refusal.message!r}"
    )


# ---------------------------------------------------------------------------
# A1: the seed CLI
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, {"tools": []}], ids=["null", "empty-tools"])
def test_the_seed_cli_fails_in_its_own_voice_and_writes_nothing(
    value, monkeypatch, tmp_path, capsys
):
    manifest = tmp_path / "agent.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {"envelope": {"polarity": "abstain", "allowlists": value}, "principal": PRINCIPAL_DATA}
        ),
        encoding="utf-8",
    )
    store = InMemoryEnvelopeStore()
    monkeypatch.setenv("BROKER_GRANTS_TABLE", "grants")
    monkeypatch.setenv("BROKER_ENVELOPE_MANIFEST", str(manifest))
    monkeypatch.delenv("BROKER_MANIFEST", raising=False)
    monkeypatch.setattr(seed_cli, "DynamoDBEnvelopeStore", lambda table_name: store)

    try:
        code = seed_cli.main()
    except ValidationError as exc:
        pytest.fail(f"{A1}: the seed CLI ended in a traceback and not a '[seed] FAIL' line: {exc}")

    err = capsys.readouterr().err
    assert code == 1, (
        f"{A1}: the seed CLI exited {code} on a manifest carrying the retired allowlists "
        "key. The key must be refused loudly, never dropped or ignored."
    )
    assert "[seed] FAIL" in err, f"{A1}: the seed CLI refusal is not in the seed voice: {err!r}"
    assert_names_the_retirement(err, "the seed CLI")
    assert store.get_envelope(PRINCIPAL) is None, (
        f"{A1}: the seed CLI wrote an envelope from a manifest carrying the retired block"
    )


# ---------------------------------------------------------------------------
# A1: the ledger audit
# ---------------------------------------------------------------------------


def _findings(report, rule):
    return [v for v in report.violations if v.rule == rule]


def _issuer_signer_and_resolver():
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    signer = signer_from_pem("issuer:retirement-test", "zone-test", private_pem)
    return signer, key_resolver_from_map({"issuer:retirement-test": public_pem})


def _ack_item(violation, signer) -> dict:
    ack = AcknowledgmentRecord(
        rule=violation.rule,
        coordinate=violation.coordinate,
        detailDigest=violation_detail_digest(violation.detail),
        rationale="stored before the retirement, envelope seed scheduled",
        acknowledgedBy="arn:aws:sts::123:assumed-role/PromotionRole/maintainer",
        ts="2026-10-07T15:00:00+00:00",
    )
    return {
        "pk": f"ACK#{ack.coordinate}",
        "sk": f"{ack.ts}#{ack.rule}",
        "data": canonical_ack_payload(ack),
        "signature": json.dumps(sign_acknowledgment(ack, signer), sort_keys=True),
    }


@pytest.mark.parametrize("value", RETIRED_VALUES)
def test_the_audit_reports_a_pre_retirement_row_as_unparseable_and_unwaivable(value):
    """The ledger audit parses envelope rows with the same model the broker
    loads them with. A row carrying the retired key is a parse failure that
    says why, is never read as the envelope in force, and cannot be waived:
    the remedy is to seed the envelope again, and a waiver would report green
    over a row the broker refuses to start with."""
    signer, resolver = _issuer_signer_and_resolver()
    row = envelope_row(stored_dump_before_retirement(Envelope(polarity="abstain"), value))

    dataset = dataset_from_items([row])
    report = run_audit(dataset, record_key_resolver=resolver)

    assert dataset.envelopes == () and report.envelopes_examined == 0, (
        f"{A1_AUDIT}: the audit took a row the broker refuses as the envelope in force: "
        f"{dataset.envelopes}"
    )
    assert [v.rule for v in report.violations] == [UNPARSEABLE_ITEM], (
        f"{A1_AUDIT}: the audit did not report the row as exactly one {UNPARSEABLE_ITEM}: "
        f"{report.violations}"
    )
    (finding,) = report.violations
    assert_names_the_retirement(finding.detail, "the ledger audit")
    assert finding.rule not in WAIVABLE_RULES, (
        f"{A1_AUDIT}: {finding.rule} joined the waivable vocabulary"
    )

    waived = run_audit(
        dataset_from_items([row, _ack_item(finding, signer)]), record_key_resolver=resolver
    )

    assert finding in waived.violations and waived.acknowledged == (), (
        f"{A1_AUDIT}: a signed acknowledgment waived the finding: {waived.acknowledged}"
    )
    assert _findings(waived, ACKNOWLEDGMENT_NOT_WAIVABLE), (
        f"{A1_AUDIT}: an acknowledgment naming {UNPARSEABLE_ITEM} was not itself reported: "
        f"{waived.violations}"
    )
