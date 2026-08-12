"""mcp.signing — sign the admission-record ledger (#174, adopts #181).

The MCP mirror of ``grants.record_signing``: turns an admission record from
*asserted* into *non-repudiable* — who proposed, who ratified, which
``(server_id, tool_name)`` at which discovery-hash. It reuses the SAME DSSE PAE
over an in-toto-style statement the grant ledger uses (``channels.signing``), and
the SAME ISSUER Ed25519 identity (a ``RecordSigner`` resolved from
``ISSUER_SIGNING_KEY_SECRET_ARN`` / ``ISSUER_SIGNING_KEY_ID`` by
``grants.issuer_keys``). A parallel statement builder is unavoidable — the
admission record's fields differ from a PromotionRecord's — but the crypto floor
and the key material are shared, not reinvented.

This module is pure and key-injected: it never reads a secret, an env var, or the
wall clock. Cold-start key resolution belongs to the ceremony command-side
binding (``mcp/commands.py`` via ``grants.issuer_keys``), exactly as
``record_signing`` defers to it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict

from safe_agents.broker.grants.record_signing import (
    DsseVerifyReasons,
    RecordSigner,
    stored_record_digest_hex,
    verify_dsse_record,
)
from safe_agents.channels.signing import (
    DSSE_PAYLOAD_TYPE,
    STATEMENT_TYPE,
    KeyResolver,
    pae,
)

# The in-toto predicate type for a signed admission record — versioned and
# name-agnostic, the same convention as RECORD_PREDICATE_TYPE in
# grants/record_signing.py.
ADMISSION_PREDICATE_TYPE = "https://safe-agents.dev/mcp-admission/v1"

# Verification reasons — module-level constants so the ledger reader / auditor
# stay in lockstep with what verification returns (mirrors record_signing.py).
ADMISSION_SIGNATURE_MISSING = "admission_signature_missing"
ADMISSION_SIGNATURE_MALFORMED = "admission_signature_malformed"
ADMISSION_SIGNATURE_INVALID = "admission_signature_invalid"
ADMISSION_SIGNER_UNKNOWN = "admission_signer_unknown"

# The admission ledger's own reason strings, mapped onto the shared DSSE verifier
# (grants/record_signing.verify_dsse_record) — same verification LOGIC as the
# promotion ledger, distinct only in predicate type, subject-digest fn, and these.
_ADMISSION_VERIFY_REASONS = DsseVerifyReasons(
    missing=ADMISSION_SIGNATURE_MISSING,
    malformed=ADMISSION_SIGNATURE_MALFORMED,
    invalid=ADMISSION_SIGNATURE_INVALID,
    signer_unknown=ADMISSION_SIGNER_UNKNOWN,
)


class McpAdmissionRecord(BaseModel):
    """One append-only admission-ledger entry (M8; PromotionRecord idiom).

    Binds who (both ARNs), what (server_id, tool_name, def_hash), when, and the
    ceremony kind — DSSE-signed by the issuer so who-admitted-what is
    non-repudiable.
    """

    model_config = ConfigDict(extra="forbid")

    recordType: str  # KIND_ADMISSION | KIND_REVET
    serverId: str
    toolName: str
    defHash: str
    proposedBy: str  # maker credential ARN
    ratifiedBy: str  # checker credential ARN
    ts: str  # ISO-8601 UTC
    # How the two identities were established (#226) — None (and absent on
    # every pre-#226 record) = two IAM-backed STS ARNs; "solo-local" = ONE
    # operator holding both local roles. Derived from the identity strings by
    # ceremony_identity.attestation_for, never asserted separately. See the
    # PromotionRecord field of the same name for the full rationale.
    attestation: Literal["solo-local"] | None = None


@dataclass(frozen=True)
class AdmissionVerifyResult:
    ok: bool
    reason: str | None = None


def canonical_record_payload(record: McpAdmissionRecord) -> str:
    """The ONE serialization of an admission record — STORED and signed (#246).

    Canonical JSON: sorted keys, no whitespace, ASCII. The ledger stores
    exactly this string as the item's data, the signature binds its sha256,
    and verification digests the STORED bytes verbatim — never a
    re-serialization of the parsed record (the grants
    ``canonical_record_payload`` mirror; same rationale).
    """
    return json.dumps(
        record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def canonical_record_bytes(record: McpAdmissionRecord) -> bytes:
    """canonical_record_payload as UTF-8 bytes (the sign-side digest input)."""
    return canonical_record_payload(record).encode("utf-8")


def _record_digest_hex(record: McpAdmissionRecord) -> str:
    return hashlib.sha256(canonical_record_bytes(record)).hexdigest()


def _build_admission_statement(record: McpAdmissionRecord, *, key_id: str, zone: str) -> bytes:
    """The in-toto statement an admission signature commits to (record_signing mirror).

    ``subject`` binds the full record via its canonical-JSON sha256;
    ``predicate.signer`` binds this signature's key_id/zone (attribution is
    non-malleable); ``predicate.record`` carries the audit-index fields in the
    clear so an auditor indexes without parsing the payload.
    """
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": ADMISSION_PREDICATE_TYPE,
        "subject": [
            {"name": "mcp-admission-record", "digest": {"sha256": _record_digest_hex(record)}}
        ],
        "predicate": {
            "signer": {"key_id": key_id, "zone": zone},
            "record": {
                "recordType": record.recordType,
                "serverId": record.serverId,
                "toolName": record.toolName,
                "defHash": record.defHash,
                "proposedBy": record.proposedBy,
                "ratifiedBy": record.ratifiedBy,
                "ts": record.ts,
            },
        },
    }
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def sign_admission_record(record: McpAdmissionRecord, signer: RecordSigner) -> dict:
    """Sign the admission record; return a JSON-serializable DSSE envelope.

    Reuses the issuer ``RecordSigner``'s key material and the DSSE/in-toto
    primitives from ``channels.signing``. ``RecordSigner.sign_record`` is bound
    to a PromotionRecord's shape, so this builds its own admission statement and
    signs it through the ``sign_pae`` seam — borrowing the key material, never
    the key itself.
    """
    statement = _build_admission_statement(record, key_id=signer.key_id, zone=signer.zone)
    sig = signer.sign_pae(pae(DSSE_PAYLOAD_TYPE, statement))
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(statement).decode("ascii"),
        "signatures": [{"keyid": signer.key_id, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def verify_admission_record(
    stored: str | bytes, envelope: dict, key_resolver: KeyResolver
) -> AdmissionVerifyResult:
    """Verify the STORED admission-record bytes against their DSSE envelope.

    The verify_record mirror: since #246 the input is the stored serialization
    itself (the ledger item's data string), and the subject digest is the
    sha256 over exactly those bytes — additive McpAdmissionRecord growth can
    never flip a valid signature to INVALID. Fails closed with a distinct
    reason for each mode; every present signature must verify (at least one
    required). The verification LOGIC is the shared DSSE core
    (grants/record_signing.verify_dsse_record); only the predicate type, the
    subject-digest input, and the reason strings are admission-specific.
    """
    reason = verify_dsse_record(
        envelope,
        expected_predicate_type=ADMISSION_PREDICATE_TYPE,
        subject_digest_hex=stored_record_digest_hex(stored),
        key_resolver=key_resolver,
        reasons=_ADMISSION_VERIFY_REASONS,
    )
    return AdmissionVerifyResult(reason is None, reason)
