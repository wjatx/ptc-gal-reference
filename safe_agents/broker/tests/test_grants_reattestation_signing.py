"""Re-attestation appends a record: who signs it (#164; GAL §6.6, §6.10).

R4: the issuer signs a reattestation record, the evaluator's key on one is
refused, and `re-seed` refuses to run at all with no issuer signing key.

The clause table and the shared harness are in reattestation_scaffold.py.
"""

from __future__ import annotations

import pytest

from safe_agents.broker.grants import commands, issuer_keys
from safe_agents.broker.grants.audit import (
    RECORD_SIGNATURE_VERIFIES,
    AuditDataset,
    AuditedRecord,
    run_audit,
)
from safe_agents.broker.grants.record_signing import (
    RECORD_SIGNER_WRONG_ROLE,
    verify_record_by_type,
)
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.tests import reattestation_scaffold as harness
from safe_agents.broker.tests import test_grant_store_differential as differential
from safe_agents.broker.tests.reattestation_scaffold import (
    ACTION_CLASS,
    NEW_HASH,
    ON,
    OPERATOR,
    OTHER_CLASS,
    PRINCIPAL,
    _as,
    _ledger,
    _reattest,
    _reattestations,
    _refused,
    _seed,
)

#: The three-backend and two-key fixtures, re-bound so pytest resolves them by
#: name here too.
backend = harness.backend
roles = harness.roles


# ===========================================================================
# R4 — the issuer signs it
# ===========================================================================


def _stored_record_and_signature(backend, record: PromotionRecord):
    """The record's stored bytes and envelope, read from the store itself."""
    if backend.name == "dynamo":  # no read seam on the Dynamo record store (#99)
        import json

        item = backend._table().get_item(
            Key={"pk": differential.RECORD_PK, "sk": f"{record.ts}#{record.recordType}"}
        )["Item"]
        return item["data"], json.loads(item["signature"]) if "signature" in item else None
    return backend.records.stored_data_for(record), backend.records.signature_for(record)


class TestR4SigningRole:
    def test_reseed_signs_under_the_issuer_role(self, backend, monkeypatch, roles, capsys):
        issuer_signer, _evaluator_signer, resolvers = roles
        _seed(backend, monkeypatch)

        _reattest(backend, monkeypatch, signer=issuer_signer)

        (record,) = _reattestations(backend)
        data, signature = _stored_record_and_signature(backend, record)
        result = verify_record_by_type(
            data, signature, record_type=record.recordType, resolvers=resolvers
        )
        assert result.ok, result.reason
        assert "signed (issuer DSSE)" in capsys.readouterr().out

    def test_the_evaluator_s_key_on_one_is_refused(self, backend, monkeypatch, roles):
        """A deployment that handed re-seed the evaluator's key writes a record
        no audit accepts: the no-human side must not re-license a grant."""
        _issuer_signer, evaluator_signer, resolvers = roles
        _seed(backend, monkeypatch)
        _reattest(backend, monkeypatch, signer=evaluator_signer)

        (record,) = _reattestations(backend)
        data, signature = _stored_record_and_signature(backend, record)
        result = verify_record_by_type(
            data, signature, record_type=record.recordType, resolvers=resolvers
        )
        assert not result.ok and result.reason == RECORD_SIGNER_WRONG_ROLE

        report = run_audit(
            AuditDataset(records=(AuditedRecord(record, signature, data),)),
            record_key_resolver=resolvers,
        )
        findings = [v for v in report.violations if v.rule == RECORD_SIGNATURE_VERIFIES]
        assert len(findings) == 1, (
            "I4 SIGNING ROLE: with no signing epoch declared, a reattestation that "
            "carries a signature must still be verified under the issuer role; the "
            f"audit reported {len(findings)} signature finding(s) for one signed by the evaluator"
        )
        assert RECORD_SIGNER_WRONG_ROLE in findings[0].detail

    def test_the_cli_hands_re_seed_the_issuer_s_signer(self, backend, monkeypatch, roles):
        """`re-seed` through main(), with BOTH roles' keys resolvable: the
        record must come out signed, and under the issuer's key."""
        issuer_signer, evaluator_signer, resolvers = roles
        _seed(backend, monkeypatch)
        monkeypatch.setattr(
            issuer_keys,
            "resolve_signer_for_role",
            lambda role_env, zone=None: (
                issuer_signer if role_env is issuer_keys.ISSUER_ROLE_ENV else evaluator_signer
            ),
        )
        monkeypatch.setattr(commands, "_build_stores", lambda _t: (backend.grants, backend.records))
        monkeypatch.setattr(
            commands, "_manifest_context", lambda _t: (PRINCIPAL, [ACTION_CLASS], NEW_HASH, [])
        )
        _as(monkeypatch, OPERATOR)

        assert commands.main(["re-seed"]) == 0

        (record,) = _reattestations(backend)
        data, signature = _stored_record_and_signature(backend, record)
        assert signature is not None, (
            "I4 SIGNING ROLE: the re-seed command wrote an UNSIGNED reattestation "
            "record with an issuer signing key configured"
        )
        result = verify_record_by_type(
            data, signature, record_type=record.recordType, resolvers=resolvers
        )
        assert result.ok, (
            "I4 SIGNING ROLE: the re-seed command must sign under the ISSUER role, "
            f"and the stored signature was refused: {result.reason}"
        )

    def test_with_no_issuer_key_it_refuses_and_writes_nothing(self, backend, monkeypatch):
        """No issuer signer, no re-attestation: the grant stays quarantined
        under the old hash and the ledger gains nothing. There is no unsigned
        mode to fall back to."""
        current = _seed(backend, monkeypatch, level=ON)

        said = _refused(
            backend, monkeypatch, "I4 SIGNING ROLE (no issuer signing key)", signer=None
        )

        assert backend.raw_grant_data() == current.raw_data, (
            "I4 SIGNING ROLE: re-seed rewrote a grant with no issuer signing key. A "
            "re-attestation must be issuer-signed or not happen at all"
        )
        assert [r.recordType for r in _ledger(backend)] == ["bootstrap"], (
            "I4 SIGNING ROLE: re-seed appended a record with no issuer signing key, "
            f"which can only be an unsigned one: {[r.recordType for r in _ledger(backend)]}"
        )
        assert "issuer signing key not configured" in said, (
            "I4 SIGNING ROLE: the refusal must name the missing issuer signing key, "
            f"it said: {said.strip()!r}"
        )
        assert "Nothing was written" in said

    def test_the_refusal_comes_before_any_grant_is_read(self, backend, monkeypatch):
        """Up front, for the whole run: a keyless re-seed does not get as far
        as a per-class verdict, so it cannot refuse one class and write another."""
        _seed(backend, monkeypatch)
        real_get = backend.grants.get_grant
        reads = []

        def counted_get(principal, action_class):
            reads.append(action_class)
            return real_get(principal, action_class)

        monkeypatch.setattr(backend.grants, "get_grant", counted_get)

        _refused(
            backend,
            monkeypatch,
            "I4 SIGNING ROLE (no issuer signing key, two classes)",
            signer=None,
            classes=(ACTION_CLASS, OTHER_CLASS),
        )

        assert reads == [], (
            "I4 SIGNING ROLE: with no issuer signing key re-seed must refuse before it "
            f"reads a grant, and it read {reads}"
        )

    def test_the_cli_refuses_with_no_issuer_key_and_writes_nothing(
        self, backend, monkeypatch, roles, capsys
    ):
        """`re-seed` through main() with the ISSUER's key unresolvable and the
        evaluator's resolvable: it must refuse, never reach for the other
        role's key, and never write unsigned."""
        _issuer_signer, evaluator_signer, _resolvers = roles
        current = _seed(backend, monkeypatch, level=ON)
        monkeypatch.setattr(
            issuer_keys,
            "resolve_signer_for_role",
            lambda role_env, zone=None: (
                None if role_env is issuer_keys.ISSUER_ROLE_ENV else evaluator_signer
            ),
        )
        monkeypatch.setattr(commands, "_build_stores", lambda _t: (backend.grants, backend.records))
        monkeypatch.setattr(
            commands, "_manifest_context", lambda _t: (PRINCIPAL, [ACTION_CLASS], NEW_HASH, [])
        )
        _as(monkeypatch, OPERATOR)

        rc = commands.main(["re-seed"])

        assert rc == 1, (
            "I4 SIGNING ROLE: the re-seed command ran with no issuer signing key "
            f"resolvable and exited {rc}"
        )
        assert backend.raw_grant_data() == current.raw_data, (
            "I4 SIGNING ROLE: the re-seed command rewrote a grant with no issuer signing key"
        )
        assert [r.recordType for r in _ledger(backend)] == ["bootstrap"], (
            "I4 SIGNING ROLE: the re-seed command appended a record with no issuer "
            f"signing key: {[r.recordType for r in _ledger(backend)]}"
        )
        said = capsys.readouterr().err
        assert "issuer signing key not configured" in said, (
            "I4 SIGNING ROLE: the refusal must name the missing issuer signing key, "
            f"it said: {said.strip()!r}"
        )

    def test_re_seed_has_no_unsigned_override(self, capsys):
        """ratify takes --allow-unsigned for bootstrap. re-seed must not."""
        with pytest.raises(SystemExit) as refused:
            commands.main(["re-seed", "--allow-unsigned"])
        assert refused.value.code == 2, (
            "I4 SIGNING ROLE: re-seed accepted --allow-unsigned. A re-attestation has "
            "no unsigned mode (GAL §6.6)"
        )
        assert "--allow-unsigned" in capsys.readouterr().err
