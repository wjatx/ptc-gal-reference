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
    key_resolver_from_map,
    resolve_signer,
    resolve_verification_keys,
)
from safe_agents.channels.manifest import WebhookAdapterConfig
from safe_agents.channels.publish import stamp_outbound
from safe_agents.channels.schemas import EventTrigger, ProvenanceEntry, SenderIdentity
from safe_agents.channels.signing import (
    PREDICATE_TYPE,
    SIGNATURE_INVALID,
    SIGNATURE_MISSING,
    SIGNER_UNKNOWN,
    BoundContext,
    ChainSigner,
    build_statement,
    canonical_identity,
    make_gate,
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


@pytest.fixture
def signer_and_resolver():
    priv, pub = _keypair()
    signer = signer_from_pem("broker:A", "zone-a", priv)
    resolver = key_resolver_from_map({"broker:A": pub})
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


def test_no_full_cover_signature_invalid(signer_and_resolver):
    signer, resolver = signer_and_resolver
    # Sign only a prefix, then append a hop the sending broker never committed
    # to. Every present signature verifies, but none covers the full chain, so
    # the sending broker did not commit to the hop it just added — fail closed.
    prefix = [ProvenanceEntry(zone="zone-a", source="peer:example", label="trusted", ts=_TS)]
    context = BoundContext(
        payload={"x": 1},
        payload_digest=None,
        payload_ref=None,
        event_id="evt-1",
        principal="example-agent",
        expiry=_EXPIRY,
        sender_channel_identity="peer:example",
    )
    partial = signer.sign_prefix(prefix, context)
    env = EventTrigger(
        event_id="evt-1",
        principal="example-agent",
        sender=SenderIdentity(channel_type="webhook", channel_identity="peer:example"),
        payload={"x": 1},
        provenance=[
            *prefix,
            ProvenanceEntry(zone="zone-a", source="peer:appended", label="trusted", ts=_TS),
        ],
        chain_signatures=[partial],
        ts=_TS,
        expiry=_EXPIRY,
    )
    result = verify_chain(env, resolver)
    assert not result.ok and result.reason == SIGNATURE_INVALID


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

    assert verify_chain(relayed, key_resolver_from_map({"broker:B": pub_b})).ok


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
    assert verify_chain(env, key_resolver_from_map({"broker:A": pub})).ok


def test_verification_keys_resolve_and_fail_closed(monkeypatch):
    import json

    priv, pub = _keypair()

    # OFF: no ARN → resolver None → gate OFF.
    monkeypatch.delenv(keys_mod.VERIFY_KEYS_SECRET_ARN_ENV, raising=False)
    assert resolve_verification_keys() is None

    monkeypatch.setenv(keys_mod.VERIFY_KEYS_SECRET_ARN_ENV, "arn:verify")
    monkeypatch.setattr(keys_mod, "_fetch_secret", lambda arn: json.dumps({"broker:A": pub}))
    resolver = resolve_verification_keys()
    assert resolver is not None and resolver("broker:A") is not None and resolver("nope") is None

    # A malformed secret fails closed rather than silently disabling verification.
    monkeypatch.setattr(keys_mod, "_fetch_secret", lambda arn: "not json")
    with pytest.raises(SigningConfigError):
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
        zone="recv",
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
    assert out.provenance[-1].evidence == ["token:pass", "sig:pass"]


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
        payload={"signal": "hold", "ticker": "ACME"},
        ts=_TS,
        expiry=_EXPIRY,
        inbound=first,
        signer=signer_b,
    )
    # Only B's full-cover signature rides the relayed envelope, so the
    # evidence names B — the broker that actually committed to this chain —
    # never A, whose inbound signature isn't carried across the relay.
    result = verify_chain(relayed, key_resolver_from_map({"broker:B": pub_b}))
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
        zone="recv",
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
        sender=SenderIdentity(channel_type="webhook", channel_identity="peer:example"),
        payload={"x": 1},
        provenance=[ProvenanceEntry(zone="zone-a", source="peer:example", label="trusted", ts=_TS)],
        ts=_TS,
        expiry=_EXPIRY,
    )
    gate = make_gate(key_resolver_from_map({}))
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
        zone="recv",
    )
    assert len(drops2) == 1
    assert drops2[0].chain_verified is False
    assert drops2[0].signer_key_id is None


def test_mutated_sender_replay_fails_verification_no_second_attributed_record(signer_and_resolver):
    """The replay closure (channels/WATCHDOG.md §"Replay soundness"):
    `sender.channel_identity` is now bound into the signed statement
    (`BoundContext.sender_channel_identity`), so a captured signature no
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
        zone="recv",
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
        zone="recv",
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
    canonicalizes `sender_channel_identity` at construction (`stamp_outbound`),
    and `BoundContext.of` canonicalizes again at verify time — idempotent, so
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
        payload={"signal": "hold", "ticker": "ACME"},
        ts=_TS,
        expiry=_EXPIRY,
        inbound=first,
        signer=signer_b,
    )
    assert relayed.sender.channel_identity == "peer:relay"
    assert verify_chain(relayed, key_resolver_from_map({"broker:B": pub_b})).ok
    # Confirms the bound field really is the relay's own claim: a copy whose
    # sender still says "peer:example" (the ORIGINAL sender, not the relay's)
    # does not verify.
    impersonating_original = relayed.model_copy(
        update={"sender": relayed.sender.model_copy(update={"channel_identity": "peer:example"})}
    )
    assert not verify_chain(impersonating_original, key_resolver_from_map({"broker:B": pub_b})).ok


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
            zone="recv",
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


def _context(**overrides) -> BoundContext:
    fields = {
        "payload": _ORIGINAL_PAYLOAD,
        "payload_digest": None,
        "payload_ref": None,
        "event_id": "evt-1",
        "principal": "example-agent",
        "expiry": _EXPIRY,
        "sender_channel_identity": "peer:example",
    }
    return BoundContext(**{**fields, **overrides})


_HOP = ProvenanceEntry(zone="zone-a", source="peer:example", label="trusted", ts=_TS)
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
    statement = json.loads(
        build_statement([_HOP], _context(**raw_original), key_id="broker:A", zone="zone-a")
    )
    assert statement["predicateType"] == PREDICATE_TYPE
    assert PREDICATE_TYPE == "https://safe-agents.dev/provenance-chain/v2"
    assert statement["subject"] == expected_subjects


def test_statement_and_payload_hash_are_canonical_json():
    """Sign and verify agree only because both sides produce one byte string:
    sorted keys, no whitespace, ASCII escapes. Key order on the wire is not content."""
    raw = build_statement(
        [_HOP], _context(payload=_NESTED_PAYLOAD), key_id="broker:A", zone="zone-a"
    )
    statement = json.loads(raw)
    canonical = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert raw == canonical.encode("utf-8")
    assert statement["subject"][0]["digest"]["sha256"] == _payload_hash(
        _NESTED_PAYLOAD
    ).removeprefix("sha256:")

    reordered = json.loads(json.dumps(_NESTED_PAYLOAD, sort_keys=True))
    assert list(reordered) != list(_NESTED_PAYLOAD)  # the fixture really is unsorted
    assert (
        build_statement([_HOP], _context(payload=reordered), key_id="broker:A", zone="zone-a")
        == raw
    )


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
        build_statement([_HOP], _context(**raw_original), key_id="broker:A", zone="zone-a")
