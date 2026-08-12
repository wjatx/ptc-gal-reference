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
from safe_agents.channels.publish import stamp_outbound
from safe_agents.channels.schemas import EventTrigger, ProvenanceEntry, SenderIdentity
from safe_agents.channels.signing import (
    SIGNATURE_INVALID,
    SIGNATURE_MISSING,
    SIGNER_UNKNOWN,
    BoundContext,
    ChainSigner,
    canonical_identity,
    make_gate,
    signer_from_pem,
    verify_chain,
)
from safe_agents.channels.tests.test_adapters import StubInboundAdapter
from safe_agents.channels.trust_map import ChannelTrustMap, TrustMapEntry

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


def _signed_outbound(signer: ChainSigner, *, turn_tainted: bool = False, inbound=None):
    return stamp_outbound(
        zone="zone-a",
        agent_identity="example",
        channel_type="webhook",
        channel_identity="peer:example",
        turn_tainted=turn_tainted,
        event_id="evt-1",
        principal="example-agent",
        payload={"signal": "buy", "ticker": "ACME"},
        ts=_TS,
        expiry=_EXPIRY,
        inbound=inbound,
        signer=signer,
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
    import hashlib
    import json as _json

    fake = {"signal": "sell", "ticker": "ACME"}
    pinned = "sha256:" + hashlib.sha256(
        _json.dumps({"signal": "buy", "ticker": "ACME"}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    tampered = env.model_copy(update={"payload": fake, "payload_digest": pinned})
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
# sa#161 Phase A1 — evidence-of-check: verify_chain populates signer identity
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
