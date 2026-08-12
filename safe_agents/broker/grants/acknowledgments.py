"""grants.acknowledgments — sanctioned disposition of TRUE audit findings (#196).

A waiver is a CEREMONY ARTIFACT, not a config toggle: an acknowledgment RECORD
appended to the same append-only grants table — NEVER a mutation of the flagged
item, which is exactly the thing the audit exists to catch. The audit then
reports the matched finding as ``acknowledged`` (with the waiver ref) instead
of ``violation``: GREEN-with-annotations, never silently green.

Guard rails, each load-bearing:

  * **Closed waivable vocabulary.** Only the rules in ``WAIVABLE_RULES`` can be
    acknowledged (the closed-vocabulary discipline from the screening/reviewer
    surfaces). HMAC-tamper quarantines, unaccounted raises, lifecycle and parse
    violations are UN-waivable — a waiver for those is a laundering seam.
  * **Finding-fingerprint binding.** An acknowledgment names the rule, the
    coordinate, AND the sha256 digest of the exact violation detail string. A
    NEW violation at the same coordinate produces a different detail and is
    never auto-waived by an old acknowledgment.
  * **Signing is REQUIRED.** A waiver mints "green", which is authority — the
    acknowledge ceremony refuses without a fully-configured issuer signer
    (same DSSE PAE / in-toto shape as record_signing, its own predicate type).
    The audit applies a waiver only when the acknowledgment's signature
    verifies against the issuer verify keys; keyless/no-resolver runs skip
    acknowledgment verification LOUDLY and apply NO waivers (fail toward RED).
  * **Operator-run, never broker-run.** "The broker cannot write grants" holds;
    the ceremony command surface is the only sanctioned writer, identity
    STS-derived like every ceremony command.

Contract + reference (docs/contract-vs-reference.md): this module is the
reference implementation; the conformance surface is the audit's behavior
(test_grants_audit.py / test_grants_integrity.py rows).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json

from pydantic import BaseModel, ConfigDict

from cryptography.exceptions import InvalidSignature

from safe_agents.broker.grants.record_signing import (
    RecordSigner,
    RecordVerifyResult,
    RECORD_SIGNATURE_INVALID,
    RECORD_SIGNATURE_MALFORMED,
    RECORD_SIGNATURE_MISSING,
    RECORD_SIGNER_UNKNOWN,
)
from safe_agents.channels.signing import (
    DSSE_PAYLOAD_TYPE,
    STATEMENT_TYPE,
    KeyResolver,
    pae,
)

# The in-toto predicate type for a signed acknowledgment — distinct from the
# promotion-record type so a signature can never be replayed across artifact
# kinds (the subject digest already prevents it; the type makes it legible).
ACK_PREDICATE_TYPE = "https://safe-agents.dev/audit-acknowledgment/v1"

# ---------------------------------------------------------------------------
# The closed waivable vocabulary. Everything not named here is UN-waivable —
# additions are a reviewed code change, never config (the injection-power
# lattice: a store-writable waivable-set would let a waiver waive itself in).
# ---------------------------------------------------------------------------

WAIVABLE_RULES: frozenset[str] = frozenset(
    {
        # A pre-ceremony grant with no ledger counterpart (#195's orphans):
        # honest history whose remediation is a coordinated operator session.
        "LEDGER_COUNTERPART",
        # An unsigned/unverifiable promotion record superseded by a signed
        # re-climb (the Phase 6 drill's 03:31 record): honest history.
        "RECORD_SIGNATURE_VERIFIES",
        # A grant stamped under a no-longer-in-force envelope: the EXPECTED
        # window after a far-jump redeploy, pending re-seed (#201).
        "GRANT_ENVELOPE_IN_FORCE",
    }
)


def violation_detail_digest(detail: str) -> str:
    """The finding fingerprint an acknowledgment binds to."""
    return "sha256:" + hashlib.sha256(detail.encode("utf-8")).hexdigest()


class AcknowledgmentRecord(BaseModel):
    """One signed waiver for one specific audit finding.

    Append-only beside the lifecycle items (pk ``ACK#<coordinate>``); the DSSE
    envelope is stored as a storage-layer attribute BESIDE the record blob,
    same convention as the promotion-record ledger.
    """

    model_config = ConfigDict(extra="forbid")

    rule: str
    coordinate: str
    detailDigest: str
    rationale: str
    acknowledgedBy: str  # STS-derived Arn — never asserted
    ts: str


# ---------------------------------------------------------------------------
# Canonical bytes + DSSE sign/verify — same PAE/in-toto shape as
# record_signing, with the acknowledgment predicate type
# ---------------------------------------------------------------------------


def canonical_ack_payload(ack: AcknowledgmentRecord) -> str:
    """The ONE serialization of an acknowledgment — STORED and signed (#246
    instance 7, found post-inventory): the stores write exactly this string as
    the item's data, the signature binds its sha256, and verification digests
    the STORED bytes verbatim — never a re-serialization of the parsed record,
    so additive AcknowledgmentRecord growth can never flip a stored waiver's
    signature to INVALID (which would un-waive the finding it dispositioned)."""
    return json.dumps(
        ack.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def canonical_ack_bytes(ack: AcknowledgmentRecord) -> bytes:
    return canonical_ack_payload(ack).encode("utf-8")


def _ack_digest_hex(ack: AcknowledgmentRecord) -> str:
    return hashlib.sha256(canonical_ack_bytes(ack)).hexdigest()


def _stored_ack_digest_hex(stored: str | bytes) -> str:
    """sha256 over the stored acknowledgment bytes VERBATIM (verify side)."""
    data = stored.encode("utf-8") if isinstance(stored, str) else stored
    return hashlib.sha256(data).hexdigest()


def build_ack_statement(ack: AcknowledgmentRecord, *, key_id: str, zone: str) -> bytes:
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": ACK_PREDICATE_TYPE,
        "subject": [
            {"name": "audit-acknowledgment", "digest": {"sha256": _ack_digest_hex(ack)}}
        ],
        "predicate": {
            "signer": {"key_id": key_id, "zone": zone},
            "acknowledgment": {
                "rule": ack.rule,
                "coordinate": ack.coordinate,
                "detailDigest": ack.detailDigest,
                "acknowledgedBy": ack.acknowledgedBy,
                "ts": ack.ts,
            },
        },
    }
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def sign_acknowledgment(ack: AcknowledgmentRecord, signer: RecordSigner) -> dict:
    """Sign the acknowledgment with the ISSUER's identity; return the DSSE envelope."""
    statement = build_ack_statement(ack, key_id=signer.key_id, zone=signer.zone)
    sig = signer._private_key.sign(pae(DSSE_PAYLOAD_TYPE, statement))
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(statement).decode("ascii"),
        "signatures": [{"keyid": signer.key_id, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def verify_acknowledgment(
    stored: str | bytes, envelope: object, key_resolver: KeyResolver
) -> RecordVerifyResult:
    """Verify the STORED acknowledgment bytes against their DSSE envelope.

    Mirrors record_signing.verify_record mode-for-mode (missing / malformed /
    unknown-signer / invalid). Since #246 (instance 7) the input is the stored
    serialization itself — the subject digest is the sha256 over exactly those
    bytes, never a re-serialization of a parsed model.
    """
    if not isinstance(envelope, dict):
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_MALFORMED)
    signatures = envelope.get("signatures")
    if not signatures:
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_MISSING)
    if not isinstance(signatures, list):
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_MALFORMED)
    payload_type = envelope.get("payloadType")
    if payload_type != DSSE_PAYLOAD_TYPE:
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_INVALID)
    try:
        statement_bytes = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(statement_bytes)
    except (KeyError, TypeError, ValueError, binascii.Error):
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_MALFORMED)
    if not isinstance(statement, dict):
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_MALFORMED)
    if statement.get("_type") != STATEMENT_TYPE:
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_INVALID)
    if statement.get("predicateType") != ACK_PREDICATE_TYPE:
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_INVALID)
    try:
        subject_hex = statement["subject"][0]["digest"]["sha256"]
        signer_key_id = statement["predicate"]["signer"]["key_id"]
    except (KeyError, IndexError, TypeError):
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_MALFORMED)
    if subject_hex != _stored_ack_digest_hex(stored):
        return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_INVALID)
    signed_bytes = pae(payload_type, statement_bytes)
    for signature in signatures:
        if not isinstance(signature, dict) or "keyid" not in signature or "sig" not in signature:
            return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_MALFORMED)
        if signature["keyid"] != signer_key_id:
            return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_INVALID)
        public_key = key_resolver(signature["keyid"])
        if public_key is None:
            return RecordVerifyResult(ok=False, reason=RECORD_SIGNER_UNKNOWN)
        try:
            public_key.verify(base64.b64decode(signature["sig"], validate=True), signed_bytes)
        except (InvalidSignature, TypeError, ValueError, binascii.Error):
            return RecordVerifyResult(ok=False, reason=RECORD_SIGNATURE_INVALID)
    return RecordVerifyResult(ok=True)


# ---------------------------------------------------------------------------
# Stores — append-only; conditional write so a waiver can never be replaced
# ---------------------------------------------------------------------------


class AcknowledgmentAlreadyExistsError(RuntimeError):
    """The (coordinate, ts, rule) slot is already written — append-only holds."""


def _ack_item_key(ack: AcknowledgmentRecord) -> dict:
    return {"pk": f"ACK#{ack.coordinate}", "sk": f"{ack.ts}#{ack.rule}"}


class InMemoryAcknowledgmentStore:
    """Test fake mirroring the DynamoDB item layout."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], dict] = {}

    def append_acknowledgment(
        self, ack: AcknowledgmentRecord, envelope: dict, session: object = None
    ) -> None:
        key = _ack_item_key(ack)
        slot = (key["pk"], key["sk"])
        if slot in self._items:
            raise AcknowledgmentAlreadyExistsError(f"acknowledgment {slot} already exists")
        self._items[slot] = {
            **key,
            "data": canonical_ack_payload(ack),
            "signature": json.dumps(envelope, sort_keys=True),
        }

    def items(self) -> list[dict]:
        return list(self._items.values())


class DynamoDBAcknowledgmentStore:
    """Production store, co-located in the grants table (ACK# item type).

    Writes run under the CALLER's session (PromotionRole holds PutItem on the
    grants table) — never an assumed role, matching every ceremony writer.
    """

    def __init__(self, table_name: str) -> None:
        self._table_name = table_name

    def _get_table(self, session=None):
        import boto3  # noqa: PLC0415 — lazy, no import-time AWS dependency

        resource = (
            session.resource("dynamodb") if session is not None else boto3.resource("dynamodb")
        )
        return resource.Table(self._table_name)

    def append_acknowledgment(
        self, ack: AcknowledgmentRecord, envelope: dict, session: object = None
    ) -> None:
        from botocore.exceptions import ClientError  # noqa: PLC0415

        table = self._get_table(session)
        item = {
            **_ack_item_key(ack),
            "data": canonical_ack_payload(ack),
            "signature": json.dumps(envelope, sort_keys=True),
        }
        try:
            table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise AcknowledgmentAlreadyExistsError(
                    f"acknowledgment {_ack_item_key(ack)} already exists"
                ) from exc
            raise
