"""Phase 4 exit predicate — the chain-signing conformance suite (channels/SIGNING.md).

Each test proves one clause (S1..S7) from channels/SIGNING.md §"Conformance"; the
mapping table lives there. Three layers:

  - The pure `signing` module: sign → verify round-trips, and every forgery mode
    (tampered hop, tampered payload, unknown signer, unsigned, bad coverage)
    fails closed.
  - The cold-start `keys` seam: signing / verification keys resolve from Secrets
    Manager, ship OFF when unset, and fail closed when set-but-unresolvable.
  - The `dispatch` gate: verification runs at the right point in the fixed gate
    order, quarantines a forged chain before spending downstream budget, ships
    OFF, and records `sig:pass` evidence when it passes.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safe_agents.channels import keys as keys_mod
from safe_agents.channels.dispatch import dispatch
from safe_agents.channels.keys import (
    SigningConfigError,
    peer_key_resolver_from_map,
    resolve_signer,
    resolve_verification_keys,
)
from safe_agents.channels.manifest import WebhookAdapterConfig
from safe_agents.channels.publish import stamp_outbound
from safe_agents.channels.schemas import EventTrigger, ProvenanceEntry, SenderIdentity
from safe_agents.channels.schemas.event_trigger import (
    MAX_CHAIN_SIGNATURES,
    MAX_ENVELOPE_BYTES,
    MAX_FORWARD_BYTES,
    ChainSignature,
)
from safe_agents.channels.signing import (
    AGENT_SEPARATED_MIN_POSTURE,
    CUSTODY_ATTESTED,
    CUSTODY_DECLARED,
    CUSTODY_EVIDENCE_CLASSES,
    DSSE_PAYLOAD_TYPE,
    HOP_FIELDS,
    MATURITY_LINEAGE,
    MATURITY_SIGNED_LINEAGE,
    PREDICATE_TYPE,
    SIGNATURE_INVALID,
    SIGNATURE_MISSING,
    SIGNER_IDENTITY_OUT_OF_SCOPE,
    SIGNER_UNKNOWN,
    SIGNER_ZONE_MISMATCH,
    SUBJECT_FIELDS,
    UNSIGNED_FIELDS,
    ChainSigner,
    ChainVerifyResult,
    ProvenanceTier,
    bound_envelope,
    build_statement,
    canonical_identity,
    deployment_provenance_tier,
    envelope_provenance_tier,
    load_private_key,
    make_gate,
    pae,
    signer_from_pem,
    verify_chain,
)
from safe_agents.channels.tests.test_adapters import StubInboundAdapter
from safe_agents.channels.trust_map import ChannelTrustMap, TrustMapEntry
from safe_agents.channels.webhook import SignedWebhookAdapter, WebhookRequest

_TS = "2026-07-10T00:00:00+00:00"
_EXPIRY = "2026-07-10T01:00:00+00:00"
_EXPIRED = "2026-07-09T23:00:00+00:00"
_NOW = datetime.fromisoformat(_TS)
# The receiving airlock's zone: what every `dispatch` here runs as, and so the
# audience an envelope addressed to it carries.
_RECV = "recv"


# ---------------------------------------------------------------------------
# Key + signer fixtures
# ---------------------------------------------------------------------------


def _keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh Ed25519 key."""
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = (
        sk.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    return priv, pub


# The custody record most fixtures enrol a key with: a signer whose key its own
# agent cannot reach, on the operator's say-so. Tests about custody override it.
_CUSTODY = {"signer_posture": 2, "custody_evidence": CUSTODY_DECLARED}


def _peer_resolver(
    keys: dict[str, tuple[str, str, list[str]]], *, postures: dict[str, int] | None = None
):
    """``key_id -> (public_pem, zone, sender_identities)``, the scope each key is enrolled with.

    ``postures`` overrides the recorded signer posture for the key ids it names.
    """
    return peer_key_resolver_from_map(
        {
            key_id: {
                **_CUSTODY,
                "public_key": pem,
                "zone": zone,
                "sender_identities": identities,
                **({"signer_posture": postures[key_id]} if key_id in (postures or {}) else {}),
            }
            for key_id, (pem, zone, identities) in keys.items()
        }
    )


@pytest.fixture
def signer_and_resolver():
    priv, pub = _keypair()
    signer = signer_from_pem("broker:A", "zone-a", priv)
    resolver = _peer_resolver({"broker:A": (pub, "zone-a", ["peer:example"])})
    return signer, resolver


_ORIGINAL_PAYLOAD = {"signal": "buy", "ticker": "ACME"}
_SWAPPED_PAYLOAD = {"signal": "sell", "ticker": "ACME"}


def _payload_hash(payload: dict) -> str:
    """`sha256:<hex>` of the canonical inline payload, as the statement hashes it."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _signed_outbound(
    signer: ChainSigner,
    *,
    turn_tainted: bool = False,
    inbound=None,
    payload: dict | None = None,
    audience: str = _RECV,
    **raw_original,
):
    """A signed envelope; ``raw_original`` passes ``payload_ref``/``payload_digest`` through."""
    return stamp_outbound(
        zone="zone-a",
        agent_identity="example",
        channel_type="webhook",
        channel_identity="peer:example",
        turn_tainted=turn_tainted,
        event_id="evt-1",
        principal="example-agent",
        audience=audience,
        payload=copy.deepcopy(payload or _ORIGINAL_PAYLOAD),
        ts=_TS,
        expiry=_EXPIRY,
        inbound=inbound,
        signer=signer,
        **raw_original,
    )


# ---------------------------------------------------------------------------
# S1 / S4 — pure signing round-trip and the forgery modes
# ---------------------------------------------------------------------------


def test_valid_signed_chain_verifies(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    assert len(env.chain_signatures) == 1
    assert verify_chain(env, resolver).ok


def test_tampered_hop_fails_closed(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    forged = env.provenance[-1].model_copy(update={"label": "untrusted"})
    tampered = env.model_copy(update={"provenance": [*env.provenance[:-1], forged]})
    result = verify_chain(tampered, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_tampered_payload_fails_closed(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    tampered = env.model_copy(update={"payload": {"signal": "sell", "ticker": "ACME"}})
    result = verify_chain(tampered, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_unknown_signer_quarantines(signer_and_resolver):
    signer, _ = signer_and_resolver
    env = _signed_outbound(signer)
    result = verify_chain(env, lambda key_id: None)
    assert not result.ok and result.reason == SIGNER_UNKNOWN


def test_unsigned_chain_missing(signer_and_resolver):
    _, resolver = signer_and_resolver
    unsigned = EventTrigger(
        event_id="evt-1",
        principal="example-agent",
        audience=_RECV,
        sender=SenderIdentity(channel_type="webhook", channel_identity="peer:example"),
        payload={"x": 1},
        provenance=[ProvenanceEntry(zone="zone-a", source="peer:example", label="trusted", ts=_TS)],
        ts=_TS,
        expiry=_EXPIRY,
    )
    result = verify_chain(unsigned, resolver)
    assert not result.ok and result.reason == SIGNATURE_MISSING


def test_covers_out_of_range_invalid(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    # A signature claiming to cover more hops than the chain holds is invalid —
    # it cannot be a legitimate prefix commitment.
    overreaching = env.chain_signatures[0].model_copy(update={"covers": len(env.provenance) + 1})
    env2 = env.model_copy(update={"chain_signatures": [overreaching]})
    result = verify_chain(env2, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_a_signature_that_does_not_cover_the_whole_chain_is_invalid(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    assert verify_chain(env, resolver).ok
    # A hop appended after signing: the one signature now covers a prefix only.
    appended = env.model_copy(
        update={
            "provenance": [
                *env.provenance,
                ProvenanceEntry(zone="zone-a", source="peer:appended", label="trusted", ts=_TS),
            ]
        }
    )
    result = verify_chain(appended, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID
    # Relabelling the signature as full-cover does not help: the hops are signed.
    relabelled = appended.model_copy(
        update={"chain_signatures": [env.chain_signatures[0].model_copy(update={"covers": 2})]}
    )
    assert not verify_chain(relabelled, resolver).ok


def test_a_chain_cannot_be_cut_back_to_an_earlier_hop():
    """A relay's envelope carries an upstream hop and the relay's own. A party
    with no key removes the relay's `untrusted` hop and presents what is left.
    Nothing in a full-chain signature verifies for the shorter chain."""
    priv_a, pub_a = _keypair()
    priv_b, pub_b = _keypair()
    first = _signed_outbound(signer_from_pem("broker:A", "zone-a", priv_a))
    relayed = stamp_outbound(
        zone="zone-b",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:relay",
        turn_tainted=True,
        event_id="evt-2",
        principal="downstream",
        audience=_RECV,
        payload={"signal": "hold"},
        ts=_TS,
        expiry=_EXPIRY,
        inbound=first,
        signer=signer_from_pem("broker:B", "zone-b", priv_b),
    )
    resolver = _peer_resolver(
        {
            "broker:A": (pub_a, "zone-a", ["peer:example", "peer:relay"]),
            "broker:B": (pub_b, "zone-b", ["peer:relay"]),
        }
    )
    assert relayed.tainted and verify_chain(relayed, resolver).ok

    for covers in (1, 2):
        cut = relayed.model_copy(
            update={
                "provenance": relayed.provenance[:1],
                "chain_signatures": [
                    relayed.chain_signatures[0].model_copy(update={"covers": covers})
                ],
            }
        )
        assert not cut.tainted  # what the attacker is after
        assert not verify_chain(cut, resolver).ok
    # Nor with the upstream broker's own signature over its original envelope.
    spliced = relayed.model_copy(
        update={"provenance": relayed.provenance[:1], "chain_signatures": first.chain_signatures}
    )
    assert not verify_chain(spliced, resolver).ok


def test_payload_swap_with_pinned_digest_fails_closed(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    # An on-path attacker mutates the inline payload AND pins a well-formed
    # payload_digest, hoping the verifier trusts the field. Verification rebinds
    # the subject to a hash of the actual payload, so the swap breaks the sig.
    tampered = env.model_copy(
        update={"payload": _SWAPPED_PAYLOAD, "payload_digest": _payload_hash(_ORIGINAL_PAYLOAD)}
    )
    result = verify_chain(tampered, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_replay_with_fresh_event_id_or_extended_expiry_fails_closed(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    # event_id and expiry are bound into the signature — a replay that swaps a
    # fresh dedupe key or pushes the TTL out no longer verifies.
    assert not verify_chain(env.model_copy(update={"event_id": "replay-1"}), resolver).ok
    assert not verify_chain(
        env.model_copy(update={"expiry": "2099-01-01T00:00:00+00:00"}), resolver
    ).ok
    assert not verify_chain(env.model_copy(update={"principal": "someone-else"}), resolver).ok


def test_signature_attribution_is_not_malleable(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    sig = env.chain_signatures[0]
    # Rewriting the signature's own zone (its attribution) breaks it — key_id and
    # zone are bound into the signed statement, not free metadata.
    relabelled = sig.model_copy(update={"zone": "zone-impostor"})
    result = verify_chain(env.model_copy(update={"chain_signatures": [relabelled]}), resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


# ---------------------------------------------------------------------------
# S2 — per-envelope signing over the full (preserved-hop) chain under relay
# ---------------------------------------------------------------------------


def test_relay_signs_full_chain_over_preserved_hops():
    priv_a, pub_a = _keypair()
    priv_b, pub_b = _keypair()
    signer_a = signer_from_pem("broker:A", "zone-a", priv_a)
    signer_b = signer_from_pem("broker:B", "zone-b", priv_b)

    first = _signed_outbound(signer_a)
    # Broker B relays A's envelope onward, re-packaging into its own envelope
    # (fresh event_id/principal) and signing the full chain — A's preserved hops
    # included — as it leaves zone-b.
    relayed = stamp_outbound(
        zone="zone-b",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:relay",
        turn_tainted=False,
        event_id="evt-2",
        principal="downstream",
        audience=_RECV,
        payload={"signal": "hold", "ticker": "ACME"},
        ts=_TS,
        expiry=_EXPIRY,
        inbound=first,
        signer=signer_b,
    )
    # One signature, B's, full-cover over the relayed chain. A's inbound hop is
    # preserved as lineage; A's inbound signature is NOT carried (it could not
    # verify against B's re-packaged envelope).
    assert [s.key_id for s in relayed.chain_signatures] == ["broker:B"]
    assert relayed.chain_signatures[0].covers == len(relayed.provenance)
    assert len(relayed.provenance) == len(first.provenance) + 1  # A's hop preserved

    assert verify_chain(relayed, _peer_resolver({"broker:B": (pub_b, "zone-b", ["peer:relay"])})).ok


# ---------------------------------------------------------------------------
# S3 — broker-keyed; the agent has no signing path
# ---------------------------------------------------------------------------


def test_broker_signs_agent_has_no_key():
    import inspect

    params = inspect.signature(stamp_outbound).parameters
    # The only signing input is the broker-supplied `signer`; there is no
    # parameter by which the agent could hand in a key, a key_id, or a
    # ready-made signature.
    assert "signer" in params
    forbidden = {"private_key", "signing_key", "key", "key_id", "signature", "sig"}
    assert forbidden.isdisjoint(params)


def test_signing_key_resolved_at_cold_start_from_secret(monkeypatch):
    priv, pub = _keypair()

    fetched: list[str] = []

    def fake_fetch(secret_arn: str) -> str:
        fetched.append(secret_arn)
        return priv

    monkeypatch.setattr(keys_mod, "_fetch_secret", fake_fetch)

    # OFF: no ARN configured → no signer.
    monkeypatch.delenv(keys_mod.SIGNING_KEY_SECRET_ARN_ENV, raising=False)
    assert resolve_signer("zone-a") is None

    # ARN set but no key_id → misconfiguration fails closed.
    monkeypatch.setenv(keys_mod.SIGNING_KEY_SECRET_ARN_ENV, "arn:sign")
    monkeypatch.delenv(keys_mod.SIGNING_KEY_ID_ENV, raising=False)
    with pytest.raises(SigningConfigError):
        resolve_signer("zone-a")

    # ARN + key_id → a working signer built from the fetched secret.
    monkeypatch.setenv(keys_mod.SIGNING_KEY_ID_ENV, "broker:A")
    signer = resolve_signer("zone-a")
    assert isinstance(signer, ChainSigner) and signer.key_id == "broker:A"
    assert fetched == ["arn:sign"]
    # The signature it produces verifies against the paired public key.
    env = _signed_outbound(signer)
    assert verify_chain(env, _peer_resolver({"broker:A": (pub, "zone-a", ["peer:example"])})).ok


def test_verification_keys_resolve_and_fail_closed(monkeypatch):
    import json

    priv, pub = _keypair()

    # OFF: no ARN → resolver None → gate OFF.
    monkeypatch.delenv(keys_mod.VERIFY_KEYS_SECRET_ARN_ENV, raising=False)
    assert resolve_verification_keys() is None

    monkeypatch.setenv(keys_mod.VERIFY_KEYS_SECRET_ARN_ENV, "arn:verify")
    entry = {**_CUSTODY, "public_key": pub, "zone": "zone-a", "sender_identities": [" Peer:Example "]}
    monkeypatch.setattr(keys_mod, "_fetch_secret", lambda arn: json.dumps({"broker:A": entry}))
    resolver = resolve_verification_keys()
    assert resolver is not None and resolver("nope") is None
    key = resolver("broker:A")
    # The scope comes from the receiver's configuration, identities in canonical form.
    assert key.zone == "zone-a" and key.sender_identities == {"peer:example"}

    # A malformed secret fails closed rather than silently disabling verification.
    monkeypatch.setattr(keys_mod, "_fetch_secret", lambda arn: "not json")
    with pytest.raises(SigningConfigError):
        resolve_verification_keys()


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param("PEM", id="bare PEM string, the format before keys had a scope"),
        pytest.param({"public_key": "PEM", "zone": "zone-a"}, id="no sender identities"),
        pytest.param({"public_key": "PEM", "sender_identities": ["peer:example"]}, id="no zone"),
        pytest.param(
            {"public_key": "PEM", "zone": " ", "sender_identities": ["peer:example"]},
            id="blank zone",
        ),
        pytest.param(
            {"public_key": "PEM", "zone": "zone-a", "sender_identities": []},
            id="empty sender identities",
        ),
        pytest.param(
            {"public_key": "PEM", "zone": "zone-a", "sender_identities": "peer:example"},
            id="sender identities not a list",
        ),
        pytest.param(
            {"public_key": "PEM", "zone": "zone-a", "sender_identities": ["peer:example", ""]},
            id="blank sender identity",
        ),
        pytest.param(
            {"public_key": "PEM", "zone": "zone-a", "sender_identities": ["*"], "any": True},
            id="unrecognized field",
        ),
    ],
)
def test_a_verification_key_without_a_full_scope_is_refused(monkeypatch, entry):
    """A key with no scope would be trusted to sign for every zone and sender,
    so an entry that does not state both is a configuration error naming the key."""
    import json

    _, pub = _keypair()
    if isinstance(entry, dict):
        entry = {**_CUSTODY, **entry, "public_key": pub}
    monkeypatch.setenv(keys_mod.VERIFY_KEYS_SECRET_ARN_ENV, "arn:verify")
    monkeypatch.setattr(keys_mod, "_fetch_secret", lambda arn: json.dumps({"broker:A": entry}))
    with pytest.raises(SigningConfigError, match="broker:A"):
        resolve_verification_keys()


# ---------------------------------------------------------------------------
# S4 / S5 — the dispatch gate: ordering, quarantine, ships-OFF, evidence
# ---------------------------------------------------------------------------


class _RecordingAdapter:
    channel_type = "webhook"

    def __init__(self, envelope: EventTrigger) -> None:
        self.calls: list[str] = []
        self._envelope = envelope

    def verify_token(self, request: Any) -> bool:
        self.calls.append("verify_token")
        return True

    def extract_identity(self, request: Any) -> str:
        self.calls.append("extract_identity")
        return "peer:example"

    def normalize(self, request: Any) -> EventTrigger:
        self.calls.append("normalize")
        return self._envelope


class _RecordingTrustMap(ChannelTrustMap):
    """A trust map that records whether resolve() was consulted."""

    resolved: bool = False

    def resolve(self, channel_type: str, channel_identity: str):
        object.__setattr__(self, "resolved", True)
        return super().resolve(channel_type, channel_identity)


def _trust_map(cls=ChannelTrustMap) -> ChannelTrustMap:
    return cls(
        entries=[
            TrustMapEntry(
                channel_type="webhook",
                channel_identity="peer:example",
                principal="example-agent",
                sender_class="peer-agent",
            )
        ]
    )


def _run(envelope, *, gate, trust_map=None, now=_NOW):
    adapter = _RecordingAdapter(envelope)
    drops: list[Any] = []
    out = dispatch(
        None,
        adapter=adapter,
        trust_map=trust_map or _trust_map(),
        screen=None,
        verify_chain=gate,
        dedupe_store=set(),
        drops=drops,
        now=now,
        zone=_RECV,
    )
    return out, drops, adapter


def test_verify_gate_runs_after_normalize_before_expiry(signer_and_resolver):
    signer, resolver = signer_and_resolver
    gate = make_gate(resolver)
    # An EXPIRED envelope carrying a forged chain: if the signature gate (3.5)
    # runs before the expiry gate (4), the drop reason is the signature failure,
    # not "expired" — proving ordering. And the gate saw the normalized
    # envelope, so it necessarily ran after normalize.
    env = _signed_outbound(signer).model_copy(
        update={"expiry": _EXPIRED, "payload": {"tampered": True}}
    )
    out, drops, adapter = _run(env, gate=gate, now=datetime.fromisoformat(_TS))
    assert out is None
    assert [d.reason for d in drops] == [SIGNATURE_INVALID]
    assert adapter.calls == ["verify_token", "extract_identity", "normalize"]


def test_forged_chain_drops_before_trust_map(signer_and_resolver):
    signer, resolver = signer_and_resolver
    gate = make_gate(resolver)
    forged = _signed_outbound(signer).model_copy(update={"payload": {"tampered": True}})
    tm = _trust_map(_RecordingTrustMap)
    out, drops, _ = _run(forged, gate=gate, trust_map=tm)
    assert out is None
    assert [d.reason for d in drops] == [SIGNATURE_INVALID]
    assert tm.resolved is False  # quarantined before spending trust-map budget


def test_verification_ships_off_unsigned_passes():
    # Gate OFF (None) — an unsigned chain flows exactly as today.
    unsigned = EventTrigger(
        event_id="evt-1",
        principal="example-agent",
        audience=_RECV,
        sender=SenderIdentity(channel_type="webhook", channel_identity="peer:example"),
        payload={"x": 1},
        provenance=[ProvenanceEntry(zone="zone-a", source="peer:example", label="trusted", ts=_TS)],
        ts=_TS,
        expiry=_EXPIRY,
    )
    out, drops, _ = _run(unsigned, gate=None)
    assert out is not None and drops == []
    assert "sig:pass" not in out.provenance[-1].evidence


def test_sig_pass_evidence_recorded(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    out, drops, _ = _run(env, gate=make_gate(resolver))
    assert out is not None and drops == []
    assert out.provenance[-1].evidence == ["token:pass", "sig:pass", "custody:declared"]


# ---------------------------------------------------------------------------
# Evidence-of-check: verify_chain populates signer identity
# ---------------------------------------------------------------------------


def test_verify_chain_success_populates_signer_identity(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    result = verify_chain(env, resolver)
    assert result.ok
    assert result.signer_key_id == "broker:A"
    assert result.signer_zone == "zone-a"


def test_verify_chain_success_names_the_full_cover_signer_under_relay():
    priv_a, pub_a = _keypair()
    priv_b, pub_b = _keypair()
    signer_a = signer_from_pem("broker:A", "zone-a", priv_a)
    signer_b = signer_from_pem("broker:B", "zone-b", priv_b)

    first = _signed_outbound(signer_a)
    relayed = stamp_outbound(
        zone="zone-b",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:relay",
        turn_tainted=False,
        event_id="evt-2",
        principal="downstream",
        audience=_RECV,
        payload={"signal": "hold", "ticker": "ACME"},
        ts=_TS,
        expiry=_EXPIRY,
        inbound=first,
        signer=signer_b,
    )
    # Only B's full-cover signature rides the relayed envelope, so the
    # evidence names B — the broker that actually committed to this chain —
    # never A, whose inbound signature isn't carried across the relay.
    result = verify_chain(relayed, _peer_resolver({"broker:B": (pub_b, "zone-b", ["peer:relay"])}))
    assert result.ok
    assert result.signer_key_id == "broker:B"
    assert result.signer_zone == "zone-b"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda env: env.model_copy(update={"payload": {"tampered": True}}),
        lambda env: env.model_copy(update={"chain_signatures": []}),
    ],
)
def test_verify_chain_failure_leaves_signer_identity_none(signer_and_resolver, mutate):
    signer, resolver = signer_and_resolver
    env = mutate(_signed_outbound(signer))
    result = verify_chain(env, resolver)
    assert not result.ok
    assert result.signer_key_id is None
    assert result.signer_zone is None


def test_dispatch_names_signer_on_screen_refused_drop_and_verdict(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    adapter = _RecordingAdapter(env)
    drops: list[Any] = []
    verdicts: list[Any] = []
    out = dispatch(
        None,
        adapter=adapter,
        trust_map=_trust_map(),
        screen=lambda e: False,
        verify_chain=make_gate(resolver),
        verdicts=verdicts,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone=_RECV,
    )
    assert out is None
    assert len(drops) == 1 and drops[0].reason == "screen_refused"
    assert drops[0].chain_verified is True
    assert drops[0].signer_key_id == "broker:A"
    assert len(verdicts) == 1
    assert verdicts[0].chain_verified is True
    assert verdicts[0].signer_key_id == "broker:A"


def test_dispatch_unsigned_drop_has_unverified_evidence():
    unsigned = EventTrigger(
        event_id="evt-1",
        principal="example-agent",
        audience=_RECV,
        sender=SenderIdentity(channel_type="webhook", channel_identity="peer:example"),
        payload={"x": 1},
        provenance=[ProvenanceEntry(zone="zone-a", source="peer:example", label="trusted", ts=_TS)],
        ts=_TS,
        expiry=_EXPIRY,
    )
    gate = make_gate(_peer_resolver({}))
    out, drops, _ = _run(unsigned, gate=gate)
    assert out is None
    assert len(drops) == 1 and drops[0].reason == SIGNATURE_MISSING
    assert drops[0].chain_verified is False
    assert drops[0].signer_key_id is None


def test_dispatch_verification_off_leaves_defaults(signer_and_resolver):
    signer, _ = signer_and_resolver
    env = _signed_outbound(signer)
    out, drops, _ = _run(env, gate=None)
    assert out is not None and drops == []
    # No later drop to inspect on the happy path with verification off; prove
    # the default via a screen refusal instead, so the record is materialized.
    adapter = _RecordingAdapter(env)
    drops2: list[Any] = []
    dispatch(
        None,
        adapter=adapter,
        trust_map=_trust_map(),
        screen=lambda e: False,
        verify_chain=None,
        dedupe_store=set(),
        drops=drops2,
        now=_NOW,
        zone=_RECV,
    )
    assert len(drops2) == 1
    assert drops2[0].chain_verified is False
    assert drops2[0].signer_key_id is None


def test_mutated_sender_replay_fails_verification_no_second_attributed_record(signer_and_resolver):
    """The replay closure (channels/WATCHDOG.md §"Replay soundness"):
    `sender.channel_identity` is now bound into the signed statement
    (`bound_envelope`), so a captured signature no
    longer verifies once it's mutated — even an INTERNALLY CONSISTENT
    mutation (the same identity a conformant adapter's `extract_identity`
    would also report for this request, so the gate-3 sender-transport-
    binding check — channels/ADAPTERS.md — does not catch it, and dedupe
    never gets the chance to either). The replay is instead caught at gate
    3.5, before dedupe or the screen ever run, dropped as a forgery
    (`chain_signature_invalid`) with no attribution evidence.
    """
    signer, resolver = signer_and_resolver
    original = _signed_outbound(signer)  # sender.channel_identity == "peer:example"
    mutated = original.model_copy(
        update={"sender": original.sender.model_copy(update={"channel_identity": "peer:mutated"})}
    )
    # The premise this test proves: the mutation invalidates the signature.
    result = verify_chain(mutated, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID

    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=identity,
                principal="example-agent",
                sender_class="peer-agent",
            )
            for identity in ("peer:example", "peer:mutated")
        ]
    )
    drops: list[Any] = []
    verdicts: list[Any] = []
    dedupe_store: set = set()
    gate = make_gate(resolver)

    # First: the original signed envelope, screen-refused — one attributed
    # DropRecord + ScreenRecord, correctly bound to the real signer.
    first = dispatch(
        None,
        adapter=StubInboundAdapter(identity="peer:example", envelope=original),
        trust_map=trust_map,
        screen=lambda e: False,
        verify_chain=gate,
        verdicts=verdicts,
        dedupe_store=dedupe_store,
        drops=drops,
        now=_NOW,
        zone=_RECV,
    )
    assert first is None
    assert len(drops) == 1 and drops[0].reason == "screen_refused"
    assert drops[0].chain_verified is True and drops[0].signer_key_id == "broker:A"
    assert len(verdicts) == 1

    # Second: a replay of the SAME captured signature under a mutated but
    # internally-consistent sender claim (extract_identity agrees with it, so
    # gate 3's binding check passes cleanly — this adapter is conformant).
    # Gate 3.5 re-verifies and now fails, since sender.channel_identity is
    # signed. No second attributed record accrues, and dedupe/screen are
    # never consulted for this replay.
    second = dispatch(
        None,
        adapter=StubInboundAdapter(identity="peer:mutated", envelope=mutated),
        trust_map=trust_map,
        screen=lambda e: False,
        verify_chain=gate,
        verdicts=verdicts,
        dedupe_store=dedupe_store,
        drops=drops,
        now=_NOW,
        zone=_RECV,
    )
    assert second is None
    assert len(drops) == 2
    assert drops[1].reason == SIGNATURE_INVALID
    assert drops[1].chain_verified is False
    assert drops[1].signer_key_id is None
    # No second ScreenRecord: gate 3.5 precedes gate 7 entirely.
    assert len(verdicts) == 1


def test_mutated_sender_after_signing_fails_verify_chain(signer_and_resolver):
    """The narrow unit-level proof behind the dispatch-level test above:
    mutating ONLY `sender.channel_identity` post-signing breaks verification,
    with no other field touched."""
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    mutated = env.model_copy(
        update={"sender": env.sender.model_copy(update={"channel_identity": "peer:someone-else"})}
    )
    result = verify_chain(mutated, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_sign_verify_round_trip_with_non_canonical_sender_spelling(signer_and_resolver):
    """An honest signer's non-canonical wire spelling still verifies: signing
    canonicalizes `sender.channel_identity` when it signs (`stamp_outbound`),
    and `bound_envelope` canonicalizes again at verify time — idempotent, so
    they agree regardless of which side (if either) already canonicalized."""
    signer, resolver = signer_and_resolver
    env = stamp_outbound(
        zone="zone-a",
        agent_identity="example",
        channel_type="webhook",
        channel_identity="  Peer:Example  ",
        turn_tainted=False,
        event_id="evt-1",
        principal="example-agent",
        audience=_RECV,
        payload={"signal": "buy", "ticker": "ACME"},
        ts=_TS,
        expiry=_EXPIRY,
        signer=signer,
    )
    # The wire field itself is NOT canonicalized by stamp_outbound (that stays
    # the receiving adapter's normalize() job) — only what's bound to the
    # signature is.
    assert env.sender.channel_identity == "  Peer:Example  "
    assert verify_chain(env, resolver).ok
    # A receiver whose adapter canonicalized the wire spelling before gate 3.5
    # also still verifies (idempotent canonicalization on both sides).
    receiver_side = env.model_copy(
        update={
            "sender": env.sender.model_copy(
                update={"channel_identity": canonical_identity(env.sender.channel_identity)}
            )
        }
    )
    assert verify_chain(receiver_side, resolver).ok


def test_relay_resign_binds_the_relays_own_sender_not_the_inbounds():
    """S2's relay case is unaffected: a relay signs its OWN sender claim, not
    the inbound envelope's — proven directly for the new bound field too."""
    priv_a, pub_a = _keypair()
    priv_b, pub_b = _keypair()
    signer_a = signer_from_pem("broker:A", "zone-a", priv_a)
    signer_b = signer_from_pem("broker:B", "zone-b", priv_b)

    first = _signed_outbound(signer_a)  # sender.channel_identity == "peer:example"
    relayed = stamp_outbound(
        zone="zone-b",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:relay",
        turn_tainted=False,
        event_id="evt-2",
        principal="downstream",
        audience=_RECV,
        payload={"signal": "hold", "ticker": "ACME"},
        ts=_TS,
        expiry=_EXPIRY,
        inbound=first,
        signer=signer_b,
    )
    assert relayed.sender.channel_identity == "peer:relay"
    assert verify_chain(relayed, _peer_resolver({"broker:B": (pub_b, "zone-b", ["peer:relay"])})).ok
    # Confirms the bound field really is the relay's own claim: a copy whose
    # sender still says "peer:example" (the ORIGINAL sender, not the relay's)
    # does not verify.
    impersonating_original = relayed.model_copy(
        update={"sender": relayed.sender.model_copy(update={"channel_identity": "peer:example"})}
    )
    assert not verify_chain(impersonating_original, _peer_resolver({"broker:B": (pub_b, "zone-b", ["peer:relay"])})).ok


# ---------------------------------------------------------------------------
# S1c — the inline payload is always bound, and so is the raw-original reference
# ---------------------------------------------------------------------------

_RAW_REF = "airlock-raw:msg-1"
_RAW_DIGEST = "sha256:" + "a" * 64
_REFERENCED = {"payload_ref": _RAW_REF, "payload_digest": _RAW_DIGEST}
_DIGEST_ONLY = {"payload_digest": _RAW_DIGEST}
# Mixed case and longer than any plausible truncation, so a verifier that
# normalized or shortened the reference before binding it would be caught.
_LONG_REF = "airlock-raw:2026-10-01/Example-Vendor-9931.eml"
_LONG_REFERENCED = {"payload_ref": _LONG_REF, "payload_digest": _RAW_DIGEST}
# Unsorted keys, nesting, a list and a non-ASCII value: everything the canonical
# form has to settle.
_NESTED_PAYLOAD = {
    "order": {"legs": [{"qty": 1, "side": "buy"}, {"qty": 2, "side": "sell"}], "note": "café"},
    "b": 1,
    "a": 2,
}


def test_payload_swap_behind_an_added_payload_ref_fails_closed(signer_and_resolver):
    """GHSA-wfrf-hcqh-pw8x. A party with no key swaps the inline payload of a
    signed envelope, attaches a ``payload_ref``, and pins ``payload_digest`` to
    the hash of the ORIGINAL payload. The v1 statement bound the declared digest
    in place of the inline payload whenever a ``payload_ref`` was present, so the
    rebuilt statement was byte-identical to the signed one and this verified."""
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    forged = env.model_copy(
        update={
            "payload": _SWAPPED_PAYLOAD,
            "payload_ref": _RAW_REF,
            "payload_digest": _payload_hash(_ORIGINAL_PAYLOAD),
        }
    )
    result = verify_chain(forged, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


@pytest.mark.parametrize(
    "signed_with, mutation",
    [
        pytest.param({}, _REFERENCED, id="inline: reference attached"),
        pytest.param({}, _DIGEST_ONLY, id="inline: digest attached"),
        # Reachable only past the schema gate, which requires a digest beside a
        # reference. The verifier must still answer, not raise out of the gate.
        pytest.param({}, {"payload_ref": _RAW_REF}, id="inline: reference attached, no digest"),
        pytest.param(_REFERENCED, {"payload": _SWAPPED_PAYLOAD}, id="referenced: inline payload swapped"),
        pytest.param(_REFERENCED, {"payload_ref": "airlock-raw:msg-2"}, id="referenced: reference repointed"),
        pytest.param(_REFERENCED, {"payload_digest": "sha256:" + "b" * 64}, id="referenced: digest changed"),
        pytest.param(_REFERENCED, {"payload_ref": None}, id="referenced: reference removed"),
        pytest.param(
            _REFERENCED,
            {"payload_ref": None, "payload_digest": None},
            id="referenced: reference and digest removed",
        ),
        pytest.param(_DIGEST_ONLY, {"payload": _SWAPPED_PAYLOAD}, id="digest only: inline payload swapped"),
        pytest.param(_DIGEST_ONLY, {"payload_digest": None}, id="digest only: digest removed"),
        pytest.param(_DIGEST_ONLY, {"payload_ref": _RAW_REF}, id="digest only: reference attached"),
        pytest.param(_DIGEST_ONLY, {"payload_ref": ""}, id="digest only: empty reference attached"),
        pytest.param(
            _REFERENCED, {"payload_digest": "sha256:" + "A" * 64}, id="referenced: digest upper-cased"
        ),
        pytest.param(
            _LONG_REFERENCED, {"payload_ref": _LONG_REF.lower()}, id="long reference: case folded"
        ),
        pytest.param(
            _LONG_REFERENCED, {"payload_ref": f" {_LONG_REF} "}, id="long reference: padded"
        ),
        pytest.param(
            _LONG_REFERENCED, {"payload_ref": _LONG_REF[:-1] + "x"}, id="long reference: tail changed"
        ),
        pytest.param(
            _LONG_REFERENCED, {"payload_ref": _LONG_REF + "#other"}, id="long reference: fragment added"
        ),
    ],
)
def test_inline_payload_and_raw_original_reference_are_bound(
    signer_and_resolver, signed_with, mutation
):
    """Whatever form the envelope was signed in, the inline payload, the
    reference and the digest are each fixed by the signature: none can be
    added, changed or removed afterwards."""
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer, **signed_with)
    assert verify_chain(env, resolver).ok
    result = verify_chain(env.model_copy(update=mutation), resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def _nested(mutate) -> dict:
    payload = copy.deepcopy(_NESTED_PAYLOAD)
    mutate(payload)
    return payload


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda p: p["order"]["legs"][1].update(qty=3), id="leaf inside a list changed"),
        pytest.param(lambda p: p["order"]["legs"].reverse(), id="list reordered"),
        pytest.param(lambda p: p["order"]["legs"].pop(), id="list element removed"),
        pytest.param(lambda p: p["order"].update(extra=True), id="nested key added"),
        pytest.param(lambda p: p["order"].update(note="cafe"), id="non-ASCII value changed"),
    ],
)
def test_nested_payload_content_is_bound(signer_and_resolver, mutate):
    """The payload hash covers the whole structure, not its top level."""
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer, payload=_NESTED_PAYLOAD)
    assert verify_chain(env, resolver).ok
    result = verify_chain(env.model_copy(update={"payload": _nested(mutate)}), resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_forged_payload_ref_envelope_drops_at_the_webhook_gate(signer_and_resolver):
    """The same forgery through the shipped receive path with verification ON:
    wire JSON, the real webhook adapter's schema gate, then gate 3.5."""
    signer, resolver = signer_and_resolver
    token = "s3cr3t-token"
    adapter = SignedWebhookAdapter(WebhookAdapterConfig(), token)

    def receive(wire: dict):
        drops: list[Any] = []
        out = dispatch(
            WebhookRequest(headers={"x-airlock-token": token}, body=json.dumps(wire)),
            adapter=adapter,
            trust_map=_trust_map(),
            screen=None,
            verify_chain=make_gate(resolver),
            dedupe_store=set(),
            drops=drops,
            now=_NOW,
            zone=_RECV,
        )
        return out, [d.reason for d in drops]

    honest = json.loads(_signed_outbound(signer).model_dump_json())
    out, reasons = receive(honest)
    assert out is not None and reasons == []  # the path accepts what was signed

    forged = {
        **honest,
        "payload": _SWAPPED_PAYLOAD,
        "payload_ref": _RAW_REF,
        "payload_digest": _payload_hash(_ORIGINAL_PAYLOAD),
    }
    out, reasons = receive(forged)
    assert out is None
    assert reasons == [SIGNATURE_INVALID]


_HOP = ProvenanceEntry(zone="zone-a", source="peer:example", label="trusted", ts=_TS)


def _unsigned(**overrides) -> EventTrigger:
    """An unsigned one-hop envelope. Overrides are applied past the schema, so a
    test can hand the statement builder a combination the schema would refuse."""
    return EventTrigger(
        event_id="evt-1",
        principal="example-agent",
        audience=_RECV,
        sender=SenderIdentity(channel_type="webhook", channel_identity="peer:example"),
        payload=copy.deepcopy(_ORIGINAL_PAYLOAD),
        provenance=[_HOP],
        ts=_TS,
        expiry=_EXPIRY,
    ).model_copy(update=overrides)


def _statement(envelope: EventTrigger) -> bytes:
    return build_statement(envelope, key_id="broker:A", zone="zone-a")
_INLINE_SUBJECT = {
    "name": "payload",
    "digest": {"sha256": _payload_hash(_ORIGINAL_PAYLOAD).removeprefix("sha256:")},
}


@pytest.mark.parametrize(
    "raw_original, expected_subjects",
    [
        pytest.param({}, [_INLINE_SUBJECT], id="inline"),
        pytest.param(
            _DIGEST_ONLY,
            [_INLINE_SUBJECT, {"name": "raw_original", "digest": {"sha256": "a" * 64}}],
            id="digest only",
        ),
        pytest.param(
            _REFERENCED,
            [
                _INLINE_SUBJECT,
                {"name": "raw_original", "uri": _RAW_REF, "digest": {"sha256": "a" * 64}},
            ],
            id="referenced",
        ),
    ],
)
def test_statement_subjects(raw_original, expected_subjects):
    statement = json.loads(_statement(_unsigned(**raw_original)))
    assert statement["predicateType"] == PREDICATE_TYPE
    assert PREDICATE_TYPE == "https://safe-agents.dev/provenance-chain/v3"
    assert statement["subject"] == expected_subjects


def test_statement_and_payload_hash_are_canonical_json():
    """Sign and verify agree only because both sides produce one byte string:
    sorted keys, no whitespace, ASCII escapes. Key order on the wire is not content."""
    raw = _statement(_unsigned(payload=_NESTED_PAYLOAD))
    statement = json.loads(raw)
    canonical = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert raw == canonical.encode("utf-8")
    assert statement["subject"][0]["digest"]["sha256"] == _payload_hash(
        _NESTED_PAYLOAD
    ).removeprefix("sha256:")

    reordered = json.loads(json.dumps(_NESTED_PAYLOAD, sort_keys=True))
    assert list(reordered) != list(_NESTED_PAYLOAD)  # the fixture really is unsorted
    assert _statement(_unsigned(payload=reordered)) == raw


@pytest.mark.parametrize(
    "raw_original",
    [
        pytest.param({"payload_ref": _RAW_REF}, id="reference without a digest"),
        pytest.param({"payload_digest": "md5:" + "a" * 32}, id="digest of another algorithm"),
        pytest.param({"payload_digest": "sha256:"}, id="digest with no value"),
        pytest.param({"payload_digest": "sha256:not-hex"}, id="digest that is not hex"),
        pytest.param({"payload_digest": "sha256:" + "A" * 64}, id="digest in upper case"),
        pytest.param({"payload_digest": "sha256:" + "a" * 63}, id="digest too short"),
        pytest.param({"payload_digest": "sha256:" + "a" * 64 + "\n"}, id="digest with a newline"),
        pytest.param({"payload_digest": "sha256:" + "a" * 60 + ":b:c"}, id="digest with colons"),
    ],
)
def test_statement_refuses_a_raw_original_it_cannot_bind(raw_original):
    """A reference the statement cannot name is refused loudly at signing time,
    never signed with the reference silently left out of the bound set."""
    with pytest.raises(ValueError):
        _statement(_unsigned(**raw_original))


def _deep(depth: int) -> dict:
    payload: dict = {"leaf": 1}
    for _ in range(depth):
        payload = {"k": payload}
    return payload


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"x": float("nan")}, id="NaN"),
        pytest.param({"x": float("inf")}, id="Infinity"),
        pytest.param({"x": "\ud800"}, id="lone surrogate"),
        pytest.param(_deep(300), id="nested past what the wire form can carry"),
        pytest.param({1: "a"}, id="non-string key"),
        pytest.param({"x": (1, 2)}, id="tuple"),
    ],
)
def test_signing_refuses_a_payload_the_wire_cannot_carry(signer_and_resolver, payload):
    """Serializing such a payload rewrites it or fails, so a signature over the
    in-process value would cover content the receiver never sees. Signing
    refuses instead of returning an envelope that fails at the transport."""
    signer, _ = signer_and_resolver
    with pytest.raises(ValueError):
        _signed_outbound(signer, payload=payload)


# ---------------------------------------------------------------------------
# S1d — the whole envelope is signed by default
# ---------------------------------------------------------------------------


def test_every_envelope_field_is_signed_or_named_as_unsigned():
    """The statement signs every field it is not told to leave out. A field
    added to EventTrigger lands in ``predicate.envelope`` unless it is named in
    one of the three sets, and this fails if a name there stops being a field."""
    fields = set(EventTrigger.model_fields)
    elsewhere = SUBJECT_FIELDS | HOP_FIELDS | UNSIGNED_FIELDS
    in_view = set(bound_envelope(_unsigned()))
    assert elsewhere <= fields
    assert in_view == fields - elsewhere
    assert UNSIGNED_FIELDS == {"sender_class", "chain_signatures"}
    assert set(bound_envelope(_unsigned())["sender"]) == set(SenderIdentity.model_fields)
    # The hops are signed whole, so a field added to a hop is signed too.
    hops = json.loads(_statement(_unsigned()))["predicate"]["hops"]
    assert [set(hop) for hop in hops] == [set(ProvenanceEntry.model_fields)]


def _sender(**changes):
    return {"sender": SenderIdentity(channel_type="webhook", channel_identity="peer:example").model_copy(update=changes)}


# One post-signing change per signed top-level field, and per field of the nested
# sender claim. The completeness test below fails when the envelope gains a field
# this table does not exercise.
_SIGNED_FIELD_MUTATIONS = {
    "schema_version": {"schema_version": 2},
    "event_id": {"event_id": "evt-2"},
    "principal": {"principal": "someone-else"},
    "audience": {"audience": "another-receiver"},
    "payload": {"payload": _SWAPPED_PAYLOAD},
    "payload_digest": {"payload_digest": _RAW_DIGEST},
    "payload_ref": {"payload_ref": _RAW_REF, "payload_digest": _RAW_DIGEST},
    "provenance": {
        "provenance": [ProvenanceEntry(zone="zone-a", source="peer:example", label="trusted", ts=_EXPIRY)]
    },
    "ts": {"ts": "2020-01-01T00:00:00+00:00"},
    "expiry": {"expiry": "2099-01-01T00:00:00+00:00"},
    "sender.channel_type": _sender(channel_type="telegram"),
    "sender.channel_identity": _sender(channel_identity="peer:other"),
    "sender.evidence": _sender(evidence=["sig:pass"]),
}


def test_the_mutation_table_covers_every_signed_field():
    top_level = {name for name in _SIGNED_FIELD_MUTATIONS if "." not in name}
    nested = {name.split(".", 1)[1] for name in _SIGNED_FIELD_MUTATIONS if name.startswith("sender.")}
    assert top_level == set(EventTrigger.model_fields) - UNSIGNED_FIELDS - {"sender"}
    assert nested == set(SenderIdentity.model_fields)


@pytest.mark.parametrize("field", sorted(_SIGNED_FIELD_MUTATIONS))
def test_no_signed_field_can_change_after_signing(signer_and_resolver, field):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    assert verify_chain(env, resolver).ok
    result = verify_chain(env.model_copy(update=_SIGNED_FIELD_MUTATIONS[field]), resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_the_receiver_owned_class_is_outside_the_signature(signer_and_resolver):
    """``sender_class`` is the one content field left unsigned: the receiver sets
    it and discards whatever arrived, so a sender has nothing to bind there."""
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer).model_copy(update={"sender_class": "owner"})
    assert verify_chain(env, resolver).ok


# ---------------------------------------------------------------------------
# S8 — a key verifies only for the zone and sender it is enrolled for
# ---------------------------------------------------------------------------


def _two_enrolled_peers():
    """Peers A and B, both enrolled at one receiver, each scoped to its own zone and identity."""
    priv_a, pub_a = _keypair()
    priv_b, pub_b = _keypair()
    resolver = _peer_resolver(
        {
            "broker:A": (pub_a, "zone-a", ["peer:example"]),
            "broker:B": (pub_b, "zone-b", ["peer:relay"]),
        }
    )
    return priv_a, priv_b, resolver


def test_an_enrolled_key_cannot_sign_for_another_zone():
    """B holds a key the receiver knows, and signs an envelope that names A's
    zone and A's identity. The signature is sound and still must not verify."""
    _, priv_b, resolver = _two_enrolled_peers()
    b_claiming_zone_a = signer_from_pem("broker:B", "zone-a", priv_b)
    forged = _signed_outbound(b_claiming_zone_a)
    result = verify_chain(forged, resolver)
    assert not result.ok
    assert (result.reason, result.detail) == (SIGNATURE_INVALID, SIGNER_ZONE_MISMATCH)
    assert result.signer_key_id is None

    out, drops, _ = _run(forged, gate=make_gate(resolver))
    assert out is None
    assert [(d.reason, d.detail, d.chain_verified) for d in drops] == [
        (SIGNATURE_INVALID, SIGNER_ZONE_MISMATCH, False)
    ]


def test_an_enrolled_key_cannot_sign_for_another_sender():
    """B signs in its own zone but claims A's sender identity, the value the
    receiver's trust map keys on."""
    _, priv_b, resolver = _two_enrolled_peers()
    signer_b = signer_from_pem("broker:B", "zone-b", priv_b)
    as_a = stamp_outbound(
        zone="zone-b",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:example",
        turn_tainted=False,
        event_id="evt-1",
        principal="example-agent",
        audience=_RECV,
        payload=dict(_ORIGINAL_PAYLOAD),
        ts=_TS,
        expiry=_EXPIRY,
        signer=signer_b,
    )
    result = verify_chain(as_a, resolver)
    assert not result.ok
    assert (result.reason, result.detail) == (SIGNATURE_INVALID, SIGNER_IDENTITY_OUT_OF_SCOPE)

    in_scope = as_a.model_copy(update={"chain_signatures": []})
    in_scope = in_scope.model_copy(update=_sender(channel_identity="peer:relay"))
    in_scope = in_scope.model_copy(update={"chain_signatures": [signer_b.sign_envelope(in_scope)]})
    assert verify_chain(in_scope, resolver).ok  # the same key, for its own sender, verifies


def test_each_peer_still_verifies_within_its_own_scope():
    priv_a, priv_b, resolver = _two_enrolled_peers()
    assert verify_chain(_signed_outbound(signer_from_pem("broker:A", "zone-a", priv_a)), resolver).ok
    relayed = stamp_outbound(
        zone="zone-b",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:relay",
        turn_tainted=False,
        event_id="evt-2",
        principal="downstream",
        audience=_RECV,
        payload={"signal": "hold"},
        ts=_TS,
        expiry=_EXPIRY,
        signer=signer_from_pem("broker:B", "zone-b", priv_b),
    )
    result = verify_chain(relayed, resolver)
    assert result.ok and result.signer_key_id == "broker:B" and result.detail is None


def _relayed_two_hops():
    """B relays A's envelope: an upstream hop from zone-a, then B's own. Returns
    the signed envelope and a resolver that knows B."""
    priv_a, _ = _keypair()
    priv_b, pub_b = _keypair()
    first = _signed_outbound(signer_from_pem("broker:A", "zone-a", priv_a))
    relayed = stamp_outbound(
        zone="zone-b",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:relay",
        turn_tainted=False,
        event_id="evt-2",
        principal="downstream",
        audience=_RECV,
        payload={"signal": "hold"},
        ts=_TS,
        expiry=_EXPIRY,
        evidence=["token:pass", "sig:pass"],
        inbound=first,
        signer=signer_from_pem("broker:B", "zone-b", priv_b),
    )
    return relayed, _peer_resolver({"broker:B": (pub_b, "zone-b", ["peer:relay"])})


_UPSTREAM_HOP_MUTATIONS = {
    "zone": {"zone": "zone-z"},
    "source": {"source": "owner:wes"},
    "evidence": {"evidence": ["sig:pass"]},
    "label": {"label": "untrusted"},
    "ts": {"ts": _EXPIRY},
}


def test_the_hop_mutation_table_covers_every_hop_field():
    assert set(_UPSTREAM_HOP_MUTATIONS) == set(ProvenanceEntry.model_fields)


@pytest.mark.parametrize("field", sorted(_UPSTREAM_HOP_MUTATIONS))
def test_no_field_of_an_upstream_hop_can_change_after_signing(field):
    """The relay's signature covers the hops it carried, not only its own."""
    relayed, resolver = _relayed_two_hops()
    assert verify_chain(relayed, resolver).ok
    upstream = relayed.provenance[0].model_copy(update=_UPSTREAM_HOP_MUTATIONS[field])
    tampered = relayed.model_copy(update={"provenance": [upstream, relayed.provenance[1]]})
    result = verify_chain(tampered, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


# Changes a lossy binding would miss: each differs from the signed value only in
# the way a normalizing, truncating or reordering bug would erase.
_FINE_GRAINED_MUTATIONS = {
    "ts: one second later the same day": lambda e: {"ts": "2026-07-10T00:00:01+00:00"},
    "expiry: same instant, another offset": lambda e: {"expiry": "2026-07-10T02:00:00+01:00"},
    "expiry: same instant, Z spelling": lambda e: {"expiry": "2026-07-10T01:00:00Z"},
    "event_id: trailing space": lambda e: {"event_id": e.event_id + " "},
    "event_id: case": lambda e: {"event_id": e.event_id.upper()},
    "principal: case": lambda e: {"principal": e.principal.upper()},
    "audience: case": lambda e: {"audience": e.audience.upper()},
    "audience: trailing space": lambda e: {"audience": e.audience + " "},
    "sender.evidence: reordered": lambda e: {
        "sender": e.sender.model_copy(update={"evidence": list(reversed(e.sender.evidence))})
    },
    "hops: reordered": lambda e: {"provenance": list(reversed(e.provenance))},
    "payload: integer respelled as a float": lambda e: {"payload": {"signal": 1.0}},
}


@pytest.mark.parametrize("name", sorted(_FINE_GRAINED_MUTATIONS))
def test_bound_values_are_bound_exactly(name):
    relayed, resolver = _relayed_two_hops()
    relayed = relayed.model_copy(update={"payload": {"signal": 1}, "chain_signatures": []})
    priv_b, pub_b = _keypair()
    signer_b = signer_from_pem("broker:B", "zone-b", priv_b)
    resolver = _peer_resolver({"broker:B": (pub_b, "zone-b", ["peer:relay"])})
    signed = relayed.model_copy(update={"chain_signatures": [signer_b.sign_envelope(relayed)]})
    assert len(signed.sender.evidence) == 2 and verify_chain(signed, resolver).ok

    changed = signed.model_copy(update=_FINE_GRAINED_MUTATIONS[name](signed))
    assert changed != signed or name.startswith("payload")  # 1 == 1.0 in Python, not on the wire
    result = verify_chain(changed, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_the_signer_named_in_a_signature_is_bound():
    """One key enrolled under two ids. Relabelling a signature from one id to the
    other leaves the key, the zone and the scope the same, so only the signed
    ``predicate.signer`` can tell the two apart."""
    priv, pub = _keypair()
    scope = ("zone-a", ["peer:example"])
    resolver = _peer_resolver({"broker:A": (pub, *scope), "broker:A-alias": (pub, *scope)})
    env = _signed_outbound(signer_from_pem("broker:A", "zone-a", priv))
    assert verify_chain(env, resolver).ok
    relabelled = env.chain_signatures[0].model_copy(update={"key_id": "broker:A-alias"})
    result = verify_chain(env.model_copy(update={"chain_signatures": [relabelled]}), resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_a_signature_must_name_the_zone_of_the_hop_it_adds():
    """B signs with its own key and its own zone, over an envelope whose top hop
    says the message left zone-a."""
    _, priv_b, resolver = _two_enrolled_peers()
    signer_b = signer_from_pem("broker:B", "zone-b", priv_b)
    as_zone_a = stamp_outbound(
        zone="zone-a",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:relay",
        turn_tainted=False,
        event_id="evt-1",
        principal="example-agent",
        audience=_RECV,
        payload=dict(_ORIGINAL_PAYLOAD),
        ts=_TS,
        expiry=_EXPIRY,
        signer=signer_b,
    )
    assert as_zone_a.provenance[-1].zone == "zone-a" and as_zone_a.chain_signatures[0].zone == "zone-b"
    result = verify_chain(as_zone_a, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


@pytest.mark.parametrize("copies", [1, 2, 3])
def test_scope_is_checked_on_every_signature_however_many_ride(copies):
    """A key outside its scope stays outside it when its signature is repeated,
    and a second signer's good signature does not carry it."""
    priv_a, priv_b, resolver = _two_enrolled_peers()
    honest = _signed_outbound(signer_from_pem("broker:A", "zone-a", priv_a))
    forged_by_b = signer_from_pem("broker:B", "zone-a", priv_b).sign_envelope(
        honest.model_copy(update={"chain_signatures": []})
    )
    only_b = honest.model_copy(update={"chain_signatures": [forged_by_b] * copies})
    assert not verify_chain(only_b, resolver).ok
    a_then_b = honest.model_copy(
        update={"chain_signatures": [*honest.chain_signatures, *[forged_by_b] * copies]}
    )
    result = verify_chain(a_then_b, resolver)
    assert not result.ok and result.detail == SIGNER_ZONE_MISMATCH


def test_identity_scope_is_checked_however_many_signatures_ride():
    """B signs in its own zone, claims A's identity, and sends its signature twice."""
    _, priv_b, resolver = _two_enrolled_peers()
    signer_b = signer_from_pem("broker:B", "zone-b", priv_b)
    as_a = stamp_outbound(
        zone="zone-b",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:example",
        turn_tainted=False,
        event_id="evt-1",
        principal="example-agent",
        audience=_RECV,
        payload=dict(_ORIGINAL_PAYLOAD),
        ts=_TS,
        expiry=_EXPIRY,
        signer=signer_b,
    )
    for copies in (1, 2, 3):
        repeated = as_a.model_copy(update={"chain_signatures": as_a.chain_signatures * copies})
        result = verify_chain(repeated, resolver)
        assert not result.ok and result.detail == SIGNER_IDENTITY_OUT_OF_SCOPE


def test_the_order_of_the_hops_is_signed():
    """Two upstream hops swapped, with the signer's own top hop left in place so
    that nothing but the signature can object."""
    priv_b, pub_b = _keypair()
    signer_b = signer_from_pem("broker:B", "zone-b", priv_b)
    resolver = _peer_resolver({"broker:B": (pub_b, "zone-b", ["peer:relay"])})
    relayed = stamp_outbound(
        zone="zone-b",
        agent_identity="relay",
        channel_type="webhook",
        channel_identity="peer:relay",
        turn_tainted=True,
        event_id="evt-2",
        principal="downstream",
        audience=_RECV,
        payload={"signal": "hold"},
        ts=_TS,
        expiry=_EXPIRY,
        ingested_sources=["connector:mcp-news", "connector:mcp-mail"],
        signer=signer_b,
    )
    assert len(relayed.provenance) == 3 and verify_chain(relayed, resolver).ok
    first, second, top = relayed.provenance
    swapped = relayed.model_copy(update={"provenance": [second, first, top]})
    result = verify_chain(swapped, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_verification_does_not_accept_a_padded_signature(signer_and_resolver):
    """The schema refuses a padded `sig` on the wire. An envelope built past the
    schema must still fail here, not verify with whatever the padding carried."""
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer)
    padded = env.chain_signatures[0].model_copy(
        update={"sig": env.chain_signatures[0].sig + "\n" + " " * 64}
    )
    result = verify_chain(env.model_copy(update={"chain_signatures": [padded]}), resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


def test_casefold_is_the_identity_rule_on_both_sides(signer_and_resolver):
    """`ß` casefolds to `ss` and lowercases to itself. The signer, the adapters
    and the key scope all have to use the same one of those."""
    priv, pub = _keypair()
    signer = signer_from_pem("broker:A", "zone-a", priv)
    resolver = _peer_resolver({"broker:A": (pub, "zone-a", ["peer:Maße"])})
    env = _signed_outbound(signer).model_copy(update={"chain_signatures": []})
    env = env.model_copy(update=_sender(channel_identity="peer:Maße"))
    env = env.model_copy(update={"chain_signatures": [signer.sign_envelope(env)]})
    received = env.model_copy(update=_sender(channel_identity=canonical_identity("peer:Maße")))
    assert received.sender.channel_identity == "peer:masse"
    assert verify_chain(received, resolver).ok


# ---------------------------------------------------------------------------
# S9 — an envelope is addressed to one receiver
# ---------------------------------------------------------------------------


def _receive_at(zone: str, wire: str, resolver, dedupe_store: set):
    """One airlock, `zone` its own id: the real webhook adapter, verification ON."""
    token = "s3cr3t-token"
    drops: list[Any] = []
    out = dispatch(
        WebhookRequest(headers={"x-airlock-token": token}, body=wire),
        adapter=SignedWebhookAdapter(WebhookAdapterConfig(), token),
        trust_map=_trust_map(),
        screen=None,
        verify_chain=make_gate(resolver),
        dedupe_store=dedupe_store,
        drops=drops,
        now=_NOW,
        zone=zone,
    )
    return out, drops


def test_an_envelope_signed_for_one_receiver_is_refused_at_another(signer_and_resolver):
    """Broker A signs an envelope for receiver r1. Receiver r2 enrols A's key
    with the same scope and serves a principal of the same name, so before the
    envelope named its receiver the same bytes verified at r2 as well, for
    anyone holding r2's transport token. One operator's two environments are
    the plain case."""
    signer, resolver = signer_and_resolver  # A's key, enrolled alike at r1 and r2
    wire = _signed_outbound(signer, audience="r1").to_wire()
    assert verify_chain(EventTrigger.model_validate_json(wire), resolver).ok

    seen_at_r2: set = set()
    out, drops = _receive_at("r2", wire, resolver, seen_at_r2)
    assert out is None and seen_at_r2 == set()
    # A's signature is genuine and was never looked at: A is not named.
    assert [(d.reason, d.chain_verified, d.signer_key_id) for d in drops] == [
        ("audience_mismatch", False, None)
    ]

    # Re-addressing the captured envelope to r2 does not help: the field is signed.
    readdressed = json.dumps({**json.loads(wire), "audience": "r2"})
    out, drops = _receive_at("r2", readdressed, resolver, seen_at_r2)
    assert out is None and seen_at_r2 == set()
    assert [(d.reason, d.chain_verified) for d in drops] == [(SIGNATURE_INVALID, False)]

    out, drops = _receive_at("r1", wire, resolver, set())
    assert out is not None and drops == []
    assert out.audience == "r1"
    assert out.provenance[-1].evidence == ["token:pass", "sig:pass", "custody:declared"]


def test_audience_is_checked_with_verification_off():
    """The audience check is not part of signature verification. An unsigned
    envelope for another receiver is refused by an airlock that verifies nothing."""
    unsigned = _unsigned(audience="r1")
    out, drops, _ = _run(unsigned, gate=None)  # this airlock is `_RECV`
    assert out is None
    assert [(d.reason, d.chain_verified) for d in drops] == [("audience_mismatch", False)]


# ---------------------------------------------------------------------------
# The wire form: one serialization, bounded, proven to read back
# ---------------------------------------------------------------------------


def test_wire_form_is_ascii_and_reads_back_equal(signer_and_resolver):
    signer, resolver = signer_and_resolver
    env = _signed_outbound(signer, payload={"note": "café \uffff \u2028", "n": 10**30})
    body = env.to_wire()
    assert body.isascii()
    assert EventTrigger.model_validate_json(body) == env
    assert verify_chain(EventTrigger.model_validate_json(body), resolver).ok


def test_an_envelope_past_the_size_ceiling_is_not_forwardable():
    big = _unsigned().model_copy(
        update=_sender(evidence=["x" * 1024] * (MAX_ENVELOPE_BYTES // 1024 + 1))
    )
    with pytest.raises(ValueError, match="over"):
        big.to_wire()
    assert len(big.to_wire(max_bytes=None)) > MAX_ENVELOPE_BYTES


def test_a_signature_has_one_spelling_and_a_bounded_count(signer_and_resolver):
    """Lenient base64 lets `sig` carry any amount of padding on an envelope that
    still verifies, and an unbounded list lets one captured signature be repeated
    to make the receiver verify it thousands of times."""
    signer, _ = signer_and_resolver
    good = _signed_outbound(signer).chain_signatures[0]
    wire = json.loads(_signed_outbound(signer).to_wire())

    for padded in (good.sig + "\n", " " + good.sig, good.sig[:-2] + "!!" + good.sig[-2:], "AAAA"):
        with pytest.raises(ValueError):
            ChainSignature(**{**good.model_dump(), "sig": padded})

    wire["chain_signatures"] = wire["chain_signatures"] * (MAX_CHAIN_SIGNATURES + 1)
    with pytest.raises(ValueError):
        EventTrigger.model_validate(wire)
    wire["chain_signatures"] = wire["chain_signatures"][:MAX_CHAIN_SIGNATURES]
    assert EventTrigger.model_validate(wire)


# ---------------------------------------------------------------------------
# The verification-keys secret: closed shape, loud on anything else
# ---------------------------------------------------------------------------


def _keys_secret(monkeypatch, text: str) -> None:
    monkeypatch.setenv(keys_mod.VERIFY_KEYS_SECRET_ARN_ENV, "arn:verify")
    monkeypatch.setattr(keys_mod, "_fetch_secret", lambda arn: text)


def test_an_empty_key_map_is_verification_on_with_nobody_enrolled(monkeypatch):
    """An empty map must not read as "verification off": every signer is unknown."""
    _keys_secret(monkeypatch, "{}")
    resolver = resolve_verification_keys()
    assert resolver is not None and resolver("broker:A") is None
    priv, _ = _keypair()
    env = _signed_outbound(signer_from_pem("broker:A", "zone-a", priv))
    assert verify_chain(env, resolver).reason == SIGNER_UNKNOWN


@pytest.mark.parametrize("text", ["[]", '"PEM"', "null", "3"], ids=["list", "string", "null", "number"])
def test_a_secret_that_is_not_a_map_fails_closed(monkeypatch, text):
    _keys_secret(monkeypatch, text)
    with pytest.raises(SigningConfigError):
        resolve_verification_keys()


def test_a_key_id_listed_twice_is_refused(monkeypatch):
    """A JSON parser keeps the last duplicate silently, so a second entry would
    replace the first one's key and scope with nothing said."""
    _, pub = _keypair()
    entry = json.dumps(
        {**_CUSTODY, "public_key": pub, "zone": "zone-a", "sender_identities": ["peer:example"]}
    )
    _keys_secret(monkeypatch, f'{{"broker:A": {entry}, "broker:A": {entry}}}')
    with pytest.raises(SigningConfigError, match="broker:A"):
        resolve_verification_keys()


@pytest.mark.parametrize("public_key", ["not a pem", 7, None], ids=["garbage", "number", "null"])
def test_a_bad_public_key_names_the_key_and_nothing_else(monkeypatch, public_key):
    entry = {
        **_CUSTODY,
        "public_key": public_key,
        "zone": "zone-a",
        "sender_identities": ["peer:example"],
    }
    _keys_secret(monkeypatch, json.dumps({"broker:A": entry}))
    with pytest.raises(SigningConfigError) as raised:
        resolve_verification_keys()
    assert "broker:A" in str(raised.value) and "not a pem" not in str(raised.value)


# ---------------------------------------------------------------------------
# Second review: every signature, exact sizes, one spelling, fixed vectors
# ---------------------------------------------------------------------------


def test_the_limits_are_the_documented_numbers():
    """The ceilings are compared against each other and against a queue limit
    elsewhere. Pinned here so that widening one is a visible decision."""
    assert (MAX_ENVELOPE_BYTES, MAX_FORWARD_BYTES, MAX_CHAIN_SIGNATURES) == (196608, 262144, 8)


def _unsigned_of_wire_size(size: int) -> EventTrigger:
    base = _unsigned().model_copy(update=_sender(evidence=[""]))
    pad = size - len(base.to_wire())
    return base.model_copy(update=_sender(evidence=["x" * pad]))


def test_the_size_ceiling_is_inclusive_and_exact():
    at = _unsigned_of_wire_size(MAX_ENVELOPE_BYTES)
    assert len(at.to_wire()) == MAX_ENVELOPE_BYTES
    with pytest.raises(ValueError, match="over"):
        _unsigned_of_wire_size(MAX_ENVELOPE_BYTES + 1).to_wire()


def _outbound(signer, evidence):
    return stamp_outbound(
        zone="zone-a",
        agent_identity="example",
        channel_type="webhook",
        channel_identity="peer:example",
        turn_tainted=False,
        event_id="evt-1",
        principal="example-agent",
        audience=_RECV,
        payload=dict(_ORIGINAL_PAYLOAD),
        ts=_TS,
        expiry=_EXPIRY,
        evidence=evidence,
        signer=signer,
    )


def test_a_sender_never_returns_an_envelope_its_signature_pushed_over_the_ceiling(
    signer_and_resolver,
):
    """The signature adds to the size. An envelope that fits unsigned and not
    signed must be refused when it is stamped, not dropped by every receiver."""
    signer, _ = signer_and_resolver
    # The evidence string lands on the sender claim and on the hop, so each
    # character of padding adds two bytes.
    room = MAX_ENVELOPE_BYTES - len(_outbound(None, [""]).to_wire())
    fits_unsigned = ["x" * ((room - 50) // 2)]
    unsigned_size = len(_outbound(None, fits_unsigned).to_wire())
    assert MAX_ENVELOPE_BYTES - 60 < unsigned_size <= MAX_ENVELOPE_BYTES
    with pytest.raises(ValueError, match="over"):
        _outbound(signer, fits_unsigned)
    assert _outbound(signer, ["x" * ((room - 400) // 2)]).chain_signatures


def _second_signature_cases():
    def unknown_signer(env, good, priv):
        return good.model_copy(update={"key_id": "broker:nobody"}), SIGNER_UNKNOWN

    def bad_signature(env, good, priv):
        return good.model_copy(update={"sig": base64_of(bytes(64))}), SIGNATURE_INVALID

    def prefix_cover(env, good, priv):
        return good.model_copy(update={"covers": 0}), SIGNATURE_INVALID

    def wrong_zone(env, good, priv):
        return good.model_copy(update={"zone": "zone-z"}), SIGNATURE_INVALID

    def other_payload_type(env, good, priv):
        statement = build_statement(env, key_id="broker:A", zone="zone-a")
        raw = load_private_key(priv).sign(pae("text/plain", statement))
        return good.model_copy(update={"payload_type": "text/plain", "sig": base64_of(raw)}), SIGNATURE_INVALID

    return [unknown_signer, bad_signature, prefix_cover, wrong_zone, other_payload_type]


def base64_of(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


@pytest.mark.parametrize("make", _second_signature_cases(), ids=lambda f: f.__name__)
@pytest.mark.parametrize("position", ["alone", "after a good signature"])
def test_every_signature_must_pass_every_check(make, position):
    priv, pub = _keypair()
    signer = signer_from_pem("broker:A", "zone-a", priv)
    resolver = _peer_resolver({"broker:A": (pub, "zone-a", ["peer:example"])})
    env = _signed_outbound(signer)
    good = env.chain_signatures[0]
    bad, reason = make(env.model_copy(update={"chain_signatures": []}), good, priv)
    signatures = [bad] if position == "alone" else [good, bad]
    result = verify_chain(env.model_copy(update={"chain_signatures": signatures}), resolver)
    assert not result.ok and result.reason == reason and result.signer_key_id is None


def test_the_signer_refuses_an_envelope_past_the_ceiling_on_its_own(signer_and_resolver):
    """Called directly, without `stamp_outbound` and its final check."""
    signer, _ = signer_and_resolver
    with pytest.raises(ValueError, match="over"):
        signer.sign_envelope(_unsigned_of_wire_size(MAX_ENVELOPE_BYTES + 1))


def test_a_co_signature_from_another_zone_is_refused_as_not_the_top_hop():
    """B adds its own genuine signature, in its own zone, to A's envelope. Every
    signature has to name the zone of the top hop, so this is refused before B's
    key or scope is looked at: the result carries no scope detail."""
    priv_a, priv_b, resolver = _two_enrolled_peers()
    env = _signed_outbound(signer_from_pem("broker:A", "zone-a", priv_a))
    from_b = signer_from_pem("broker:B", "zone-b", priv_b).sign_envelope(
        env.model_copy(update={"chain_signatures": []})
    )
    result = verify_chain(
        env.model_copy(update={"chain_signatures": [*env.chain_signatures, from_b]}), resolver
    )
    assert not result.ok and (result.reason, result.detail) == (SIGNATURE_INVALID, None)


def test_the_result_names_the_first_signer_when_two_keys_sign():
    priv_1, pub_1 = _keypair()
    priv_2, pub_2 = _keypair()
    scope = ("zone-a", ["peer:example"])
    resolver = _peer_resolver({"broker:A1": (pub_1, *scope), "broker:A2": (pub_2, *scope)})
    env = _signed_outbound(signer_from_pem("broker:A1", "zone-a", priv_1))
    second = signer_from_pem("broker:A2", "zone-a", priv_2).sign_envelope(
        env.model_copy(update={"chain_signatures": []})
    )
    result = verify_chain(
        env.model_copy(update={"chain_signatures": [*env.chain_signatures, second]}), resolver
    )
    assert result.ok and result.signer_key_id == "broker:A1"


def test_a_key_out_of_scope_is_named_only_after_its_signature_verified():
    """The `detail` says an enrolled key was used outside its scope. A forged
    signature that merely claims that key id must not earn the same detail."""
    _, priv_b, resolver = _two_enrolled_peers()
    as_a = _outbound(None, []).model_copy(update=_sender(channel_identity="peer:example"))
    as_a = as_a.model_copy(
        update={
            "provenance": [
                ProvenanceEntry(zone="zone-b", source="peer:relay", label="trusted", ts=_TS)
            ]
        }
    )
    real = signer_from_pem("broker:B", "zone-b", priv_b).sign_envelope(as_a)
    forged = real.model_copy(update={"sig": base64_of(bytes(64))})
    out_of_scope = verify_chain(as_a.model_copy(update={"chain_signatures": [real]}), resolver)
    garbage = verify_chain(as_a.model_copy(update={"chain_signatures": [forged]}), resolver)
    assert out_of_scope.detail == SIGNER_IDENTITY_OUT_OF_SCOPE
    assert garbage.reason == SIGNATURE_INVALID and garbage.detail is None


def test_a_signature_has_exactly_one_base64_spelling(signer_and_resolver):
    """The last base64 character of a 64-byte value has four bits that encode
    nothing, so sixteen strings decode to the same signature."""
    import base64

    signer, _ = signer_and_resolver
    good = _signed_outbound(signer).chain_signatures[0]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    raw = base64.b64decode(good.sig)
    aliases = [
        candidate
        for letter in alphabet
        if (candidate := good.sig[:-3] + letter + "==") != good.sig
        and base64.b64decode(candidate) == raw
    ]
    assert len(aliases) == 15
    for alias in aliases:
        with pytest.raises(ValueError):
            ChainSignature(**{**good.model_dump(), "sig": alias})


def test_known_answer_for_the_pae_the_statement_and_the_signature():
    """Fixed inputs, fixed outputs. Ed25519 is deterministic, so a change to the
    PAE, the statement type, the statement's shape or the canonical form shows
    up here as a different value. Changing the statement on purpose means a new
    predicate type and new values in this test."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    assert pae(DSSE_PAYLOAD_TYPE, b"abc") == b"DSSEv1 28 application/vnd.in-toto+json 3 abc"

    signer = ChainSigner(
        key_id="broker:A",
        zone="zone-a",
        _private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
    )
    env = _signed_outbound(signer)
    statement = build_statement(
        env.model_copy(update={"chain_signatures": []}), key_id="broker:A", zone="zone-a"
    )
    assert (
        hashlib.sha256(statement).hexdigest()
        == "747cfa2c04c70b59ac07f4afca53d906ba9b8bfe54928e0fcb4582245e298929"
    )
    assert env.chain_signatures[0].sig == (
        "uT1AKKfy6q/YRF3RAU4i7979O09v0nUF0ax9pHwxCV6MHl4e8vIJnpfYrEgSwL9U"
        "7wvkiU+s47CsRsZGMOmeDw=="
    )
    assert env.chain_signatures[0].payload_type == DSSE_PAYLOAD_TYPE


def test_the_origin_flag_must_be_exactly_true(signer_and_resolver):
    """An adapter is exempt from chain verification only when it says so with
    the boolean. Anything else, a truthy string or a mock included, is verified."""
    _, resolver = signer_and_resolver

    class _Claims(_RecordingAdapter):
        originates_envelope = "false"

    unsigned = _unsigned()
    drops: list[Any] = []
    out = dispatch(
        None,
        adapter=_Claims(unsigned),
        trust_map=_trust_map(),
        screen=None,
        verify_chain=make_gate(resolver),
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone=_RECV,
    )
    assert out is None and [d.reason for d in drops] == [SIGNATURE_MISSING]


@pytest.mark.parametrize(
    "change, reason",
    [
        ({"expiry": _EXPIRED}, "expired"),
        ({"principal": "someone-else"}, "principal_mismatch"),
    ],
)
def test_later_drops_cite_the_verification_that_passed(change, reason):
    """Once gate 3.5 has verified a chain, the drop records of the gates after
    it say so and name the signer; before this they would read as unverified."""
    priv, pub = _keypair()
    signer = signer_from_pem("broker:A", "zone-a", priv)
    resolver = _peer_resolver({"broker:A": (pub, "zone-a", ["peer:example"])})
    unsigned = _signed_outbound(signer).model_copy(update={"chain_signatures": [], **change})
    env = unsigned.model_copy(update={"chain_signatures": [signer.sign_envelope(unsigned)]})
    out, drops, _ = _run(env, gate=make_gate(resolver))
    assert out is None
    assert [(d.reason, d.chain_verified, d.signer_key_id) for d in drops] == [
        (reason, True, "broker:A")
    ]


def test_the_identity_rule_is_the_same_in_every_module():
    from safe_agents.channels import owner as owner_mod
    from safe_agents.channels import webhook as webhook_mod

    for raw in ["peer:Example", " peer:Maße ", "PEER:İstanbul", "peer:ﬁx", "peer:ſ"]:
        assert (
            canonical_identity(raw)
            == webhook_mod._canonical_identity(raw)
            == owner_mod._canonical_identity(raw)
        )
    assert canonical_identity("peer:Maße") == "peer:masse"  # casefold, not lower


@pytest.mark.parametrize(
    "entry_change",
    [
        pytest.param({"zone": " zone-a"}, id="zone with leading whitespace"),
        pytest.param({"zone": "zone-a\n"}, id="zone with a trailing newline"),
        pytest.param({"sender_identities": ["peer:example", "  "]}, id="whitespace-only identity"),
    ],
)
def test_key_scope_values_that_could_never_match_are_refused(monkeypatch, entry_change):
    _, pub = _keypair()
    entry = {**_CUSTODY, "public_key": pub, "zone": "zone-a", "sender_identities": ["peer:example"]}
    _keys_secret(monkeypatch, json.dumps({"broker:A": {**entry, **entry_change}}))
    with pytest.raises(SigningConfigError, match="broker:A"):
        resolve_verification_keys()


def test_a_field_listed_twice_inside_one_key_entry_is_refused(monkeypatch):
    _, pub = _keypair()
    body = json.dumps({**_CUSTODY, "public_key": pub, "sender_identities": ["peer:example"]})[:-1]
    _keys_secret(monkeypatch, f'{{"broker:A": {body}, "zone": "zone-a", "zone": "zone-z"}}}}')
    with pytest.raises(SigningConfigError, match="zone"):
        resolve_verification_keys()


def test_key_ids_are_matched_exactly(monkeypatch):
    _, pub = _keypair()
    entry = {**_CUSTODY, "public_key": pub, "zone": "zone-a", "sender_identities": ["peer:example"]}
    _keys_secret(monkeypatch, json.dumps({"broker:A": entry}))
    resolver = resolve_verification_keys()
    assert resolver("broker:A") is not None
    assert resolver("BROKER:A") is None and resolver("broker:A ") is None


def test_a_malformed_secret_does_not_ride_out_on_the_error(monkeypatch):
    """A JSON decode error carries the document it was parsing, and here the
    document is the secret. Nothing chained to the raised error may hold it."""
    _keys_secret(monkeypatch, '{"broker:A": {"public_key": "PEM-TEXT-IN-THE-SECRET"')
    with pytest.raises(SigningConfigError) as raised:
        resolve_verification_keys()
    assert raised.value.__cause__ is None
    assert "PEM-TEXT-IN-THE-SECRET" not in str(raised.value)


# ---------------------------------------------------------------------------
# S10: the custody record of a verification key
# ---------------------------------------------------------------------------

_CUSTODY_ENTRY = "custody:declared"
_LINEAGE = ProvenanceTier(MATURITY_LINEAGE)
_SIGNED_LINEAGE_DECLARED = ProvenanceTier(MATURITY_SIGNED_LINEAGE, CUSTODY_DECLARED)


def _scoped_entry(**custody) -> dict:
    """One verification-key entry with a valid scope and exactly the custody fields given."""
    _, pub = _keypair()
    return {"public_key": pub, "zone": "zone-a", "sender_identities": ["peer:example"], **custody}


@pytest.mark.parametrize(
    "custody, says",
    [
        pytest.param({}, "no custody record", id="no custody record at all"),
        pytest.param({"signer_posture": 2}, "custody_evidence", id="posture with no evidence class"),
        pytest.param({"custody_evidence": "declared"}, "signer_posture", id="evidence class with no posture"),
        *[
            pytest.param(
                {"signer_posture": posture, "custody_evidence": "declared"},
                "signer_posture must be",
                id=f"posture {posture!r}",
            )
            for posture in [0, 4, -1, True, False, 2.0, "2", None, [2]]
        ],
        *[
            pytest.param(
                {"signer_posture": 2, "custody_evidence": evidence},
                "custody_evidence must be",
                id=f"evidence class {evidence!r}",
            )
            for evidence in ["verified", "Declared", " declared", "", None, 1, ["declared"]]
        ],
        pytest.param(
            {"signer_posture": 3, "custody_evidence": "attested"},
            "reserved; no procedure in this version produces it",
            id="attested is a reserved name",
        ),
    ],
)
def test_a_verification_key_without_a_valid_custody_record_is_refused(monkeypatch, custody, says):
    """A custody record is required, has no default, and takes its values from
    closed sets. The refusal names the key and the fault and carries no key material."""
    entry = _scoped_entry(**custody)
    _keys_secret(monkeypatch, json.dumps({"broker:A": entry}))
    with pytest.raises(SigningConfigError) as raised:
        resolve_verification_keys()
    message = str(raised.value)
    assert "broker:A" in message and says in message
    assert entry["public_key"] not in message and "BEGIN PUBLIC KEY" not in message


@pytest.mark.parametrize("posture, separated", [(1, False), (2, True), (3, True)])
def test_each_posture_on_the_ladder_is_accepted_and_only_two_and_up_are_agent_separated(
    monkeypatch, posture, separated
):
    entry = _scoped_entry(signer_posture=posture, custody_evidence="declared")
    _keys_secret(monkeypatch, json.dumps({"broker:A": entry}))
    resolver = resolve_verification_keys()
    key = resolver("broker:A")
    assert (key.signer_posture, key.custody_evidence) == (posture, CUSTODY_DECLARED)
    assert key.agent_separated_custody is separated
    assert resolver.enrolled == (key,)


def test_the_custody_vocabulary_is_the_drafts_and_the_threshold_is_posture_two():
    assert CUSTODY_EVIDENCE_CLASSES == {"declared", "attested"}
    assert (CUSTODY_DECLARED, CUSTODY_ATTESTED) == ("declared", "attested")
    assert AGENT_SEPARATED_MIN_POSTURE == 2


def _signed_by(postures: list[int]):
    """One envelope signed by ``len(postures)`` keys of zone-a, each enrolled at
    the posture given. Returns ``(envelope, resolver)``."""
    pairs = [_keypair() for _ in postures]
    key_ids = [f"broker:A{n}" for n in range(len(postures))]
    resolver = _peer_resolver(
        {key_id: (pub, "zone-a", ["peer:example"]) for key_id, (_, pub) in zip(key_ids, pairs)},
        postures=dict(zip(key_ids, postures)),
    )
    env = _signed_outbound(signer_from_pem(key_ids[0], "zone-a", pairs[0][0]))
    bare = env.model_copy(update={"chain_signatures": []})
    signatures = [
        signer_from_pem(key_id, "zone-a", priv).sign_envelope(bare)
        for key_id, (priv, _) in zip(key_ids, pairs)
    ]
    return env.model_copy(update={"chain_signatures": signatures}), resolver


_CUSTODY_CASES = [
    pytest.param([1], False, id="one key at posture 1"),
    pytest.param([2], True, id="one key at posture 2"),
    pytest.param([3], True, id="one key at posture 3"),
    pytest.param([2, 3], True, id="two keys, both agent-separated"),
    pytest.param([2, 1], False, id="two keys, the second at posture 1"),
    pytest.param([1, 2], False, id="two keys, the first at posture 1"),
]


@pytest.mark.parametrize("postures, separated", _CUSTODY_CASES)
def test_a_verified_chain_reports_the_custody_records_of_every_signing_key(postures, separated):
    """Custody is reported for the chain only when EVERY signature was made by a
    key recorded in agent-separated custody. The record has no bearing on
    whether the chain verifies: it passes at any posture."""
    env, resolver = _signed_by(postures)
    result = verify_chain(env, resolver)
    assert result.ok and result.signer_key_id == "broker:A0"
    assert result.agent_separated_custody is separated
    assert result.custody_evidence == CUSTODY_DECLARED
    assert envelope_provenance_tier(result) == (_SIGNED_LINEAGE_DECLARED if separated else _LINEAGE)


@pytest.mark.parametrize("postures, separated", _CUSTODY_CASES)
def test_custody_evidence_is_stamped_only_when_every_signing_key_is_agent_separated(
    postures, separated
):
    """`custody:declared` follows `sig:pass` in the receiver's hop evidence. A
    chain signed by a key recorded at posture 1 is still verified and still
    gets `sig:pass`, with no custody entry."""
    env, resolver = _signed_by(postures)
    out, drops, _ = _run(env, gate=make_gate(resolver))
    assert out is not None and drops == []
    expected = ["token:pass", "sig:pass", *([_CUSTODY_ENTRY] if separated else [])]
    assert out.provenance[-1].evidence == expected


def test_a_failed_verification_reports_no_custody(signer_and_resolver):
    """Custody fields stay unset on any failure, like the signer fields: a gate
    that did not verify must not report records for keys it did not accept."""
    signer, resolver = signer_and_resolver  # enrolled at posture 2
    forged = _signed_outbound(signer).model_copy(update={"payload": {"tampered": True}})
    result = verify_chain(forged, resolver)
    assert not result.ok
    assert (result.agent_separated_custody, result.custody_evidence) == (False, None)
    assert envelope_provenance_tier(result) == _LINEAGE
    out, drops, _ = _run(forged, gate=make_gate(resolver))
    assert out is None and [d.reason for d in drops] == [SIGNATURE_INVALID]


def test_no_custody_evidence_with_verification_off(signer_and_resolver):
    """With the gate off nothing was verified, so nothing is recorded, even for
    a chain whose signer is one this receiver would have on record."""
    signer, _ = signer_and_resolver
    out, drops, _ = _run(_signed_outbound(signer), gate=None)
    assert out is not None and drops == []
    assert out.provenance[-1].evidence == ["token:pass"]


def test_no_custody_evidence_for_an_envelope_the_adapter_built_itself():
    """The gate is skipped for an originating adapter. It records neither a
    signature check nor a custody record, even when the gate it was handed
    would have reported both."""

    class _Originates(_RecordingAdapter):
        originates_envelope = True

    gate_calls: list[EventTrigger] = []

    def gate(envelope: EventTrigger) -> ChainVerifyResult:
        gate_calls.append(envelope)
        return ChainVerifyResult(
            ok=True, signer_key_id="broker:A", agent_separated_custody=True, custody_evidence="declared"
        )

    def run(adapter):
        return dispatch(
            None,
            adapter=adapter,
            trust_map=_trust_map(),
            screen=None,
            verify_chain=gate,
            dedupe_store=set(),
            drops=[],
            now=_NOW,
            zone=_RECV,
        )

    out = run(_Originates(_unsigned()))
    assert gate_calls == [] and out.provenance[-1].evidence == ["token:pass"]
    # The same gate, reached through an adapter that does not originate, stamps both.
    out = run(_RecordingAdapter(_unsigned()))
    assert len(gate_calls) == 1
    assert out.provenance[-1].evidence == ["token:pass", "sig:pass", _CUSTODY_ENTRY]


def test_a_passing_gate_that_reports_no_custody_gets_sig_pass_alone():
    """Custody is opt-in on the result. A gate that reports a pass and says
    nothing about custody is recorded as verified and no more."""
    out, drops, _ = _run(_unsigned(), gate=lambda envelope: ChainVerifyResult(ok=True))
    assert out is not None and out.provenance[-1].evidence == ["token:pass", "sig:pass"]


@pytest.mark.parametrize(
    "configured, postures, expected",
    [
        pytest.param(False, [], _LINEAGE, id="verification off"),
        pytest.param(False, [2, 3], _LINEAGE, id="verification off, whatever the records say"),
        pytest.param(True, [], _LINEAGE, id="verification on, nobody enrolled"),
        pytest.param(True, [1], _LINEAGE, id="the one enrolled key at posture 1"),
        pytest.param(True, [2, 3, 1], _LINEAGE, id="one enrolled key of three at posture 1"),
        pytest.param(True, [2], _SIGNED_LINEAGE_DECLARED, id="the one enrolled key at posture 2"),
        pytest.param(True, [2, 3], _SIGNED_LINEAGE_DECLARED, id="every enrolled key agent-separated"),
    ],
)
def test_the_tier_a_deployments_custody_records_support(configured, postures, expected):
    """`signed-lineage` needs verification on, somebody enrolled, and every
    enrolled key recorded in agent-separated custody. The class is named with it."""
    _, resolver = _signed_by(postures) if postures else (None, _peer_resolver({}))
    tier = deployment_provenance_tier(
        verification_configured=configured, enrolled_keys=resolver.enrolled
    )
    assert tier == expected
    assert (tier.custody_evidence is None) == (tier.maturity != MATURITY_SIGNED_LINEAGE)


@pytest.mark.parametrize(
    "result, expected",
    [
        pytest.param(None, _LINEAGE, id="the gate did not run"),
        pytest.param(ChainVerifyResult(ok=False, reason=SIGNATURE_INVALID), _LINEAGE, id="failed"),
        pytest.param(ChainVerifyResult(ok=True), _LINEAGE, id="passed, custody not reported"),
        pytest.param(
            ChainVerifyResult(ok=True, custody_evidence="declared"),
            _LINEAGE,
            id="passed, a signing key outside agent-separated custody",
        ),
        pytest.param(
            ChainVerifyResult(ok=False, agent_separated_custody=True, custody_evidence="declared"),
            _LINEAGE,
            id="a failed result is never raised by its custody fields",
        ),
        pytest.param(
            ChainVerifyResult(ok=True, agent_separated_custody=True, custody_evidence="declared"),
            _SIGNED_LINEAGE_DECLARED,
            id="passed, every signing key agent-separated",
        ),
    ],
)
def test_the_tier_one_verification_result_supports(result, expected):
    assert envelope_provenance_tier(result) == expected


def test_the_maturity_names_are_the_promotion_predicates():
    """`signing` restates two maturity names so it imports nothing from the
    broker. They must stay the names the promotion predicate ranks."""
    from typing import get_args

    from safe_agents.broker.grants.predicate import ProvenanceMaturity

    assert {MATURITY_LINEAGE, MATURITY_SIGNED_LINEAGE} <= set(get_args(ProvenanceMaturity))
