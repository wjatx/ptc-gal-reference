"""channels.publish — the outbound A2A seam (`peer.publish`, sa#156).

See channels/PUBLISH.md for the normative contract; this module is the typed
encoding of the one clause that cannot live in a connector: **the outbound
provenance is broker-stamped from the sending turn, never authored by the
agent**. `stamp_outbound` is the sender-side mirror of `stamp_inbound`
(channels/trust_map.py) — the label is a deterministic function of the
broker-held turn's taint state, never a caller assertion and never a model
judgment. The `peer` connector that actually transports the result is pure
transport (reference-tier, consumer-owned); it receives an already-stamped
envelope and never constructs provenance.

Two protections, together end-to-end (TRUST-MAPPING.md §"The one-way rule —
sender side"):
  1. broker-stamped provenance (here) — a tainted turn publishes an `untrusted`
     entry the agent can neither remove nor relabel;
  2. `peer.publish` is `external=True, effect="write"`, so a tainted turn's
     publish escalates to require_approval at the PDP (broker/TAINT.md §5).
"""

from __future__ import annotations

from safe_agents.channels.schemas import EventTrigger, ProvenanceEntry, SenderIdentity
from safe_agents.channels.signing import BoundContext, ChainSigner, canonical_identity


def stamp_outbound(
    *,
    zone: str,
    agent_identity: str,
    channel_type: str,
    turn_tainted: bool,
    event_id: str,
    principal: str,
    payload: dict,
    ts: str,
    expiry: str,
    channel_identity: str | None = None,
    evidence: list[str] | None = None,
    inbound: EventTrigger | None = None,
    ingested_sources: list[str] | None = None,
    payload_digest: str | None = None,
    payload_ref: str | None = None,
    signer: ChainSigner | None = None,
) -> EventTrigger:
    """Construct the outbound EventTrigger with a broker-stamped provenance hop.

    The one sanctioned path from a sending turn to a publishable envelope
    (channels/PUBLISH.md P3). The sending-zone hop's ``label`` is derived from
    ``turn_tainted`` alone — ``"untrusted"`` iff the broker-held turn is tainted,
    else ``"trusted"`` — so a compromised agent has no path to publish a
    ``trusted`` chain over content it read from an untrusted source. The caller
    supplies ``turn_tainted`` from the broker-held ``TurnContext.tainted``, never
    from anything the agent authored.

    Lineage, not just a taint bit (#168, PTC §8). A fresh origination that read
    from an untrusted connector (e.g. ``connector:mcp-news``) would otherwise
    compress those real sources into a single taint boolean on the sending-zone
    hop — the receiver would see only ``peer:<agent>`` and could never apply its
    OWN trust map to the true origin. When the caller supplies
    ``ingested_sources`` (the broker-held ``TurnContext.to_taint().sources`` —
    the sources that tainted this turn), each is carried as its own ``untrusted``
    origin hop ahead of the sending-zone hop, so the receiver's ``ingest_chain``
    re-derives taint from the actual source under its own map. This is *lineage
    fidelity*, not correctness-of-propagation (whether a model faithfully carried
    taint through a transform is the banked §8 problem, unsolved by carrying
    sources or by signing).

    Parameters
    ----------
    zone / agent_identity:
        This sending zone's id and its published peer identity. The hop's
        ``source`` is ``"peer:<agent_identity>"``.
    channel_type / channel_identity:
        The TRANSPORT the sender uses and the identity the receiver's trust map
        keys on — NOT the sender's class. ``channel_type`` must match the
        receiver adapter's own type (e.g. ``"webhook"``), which the receiver's
        ``normalize`` gate enforces; ``channel_identity`` (default
        ``agent_identity``) is the exact string the receiver's trust map row
        matches (e.g. ``"peer:example"``). The receiver derives
        ``sender_class="peer-agent"`` from its map — the sender never asserts it.
    turn_tainted:
        The broker-held turn's taint state (``TurnContext.tainted``). The ONLY
        input to the sending-zone hop label — never a caller/agent assertion.
    event_id / principal / payload:
        The agent-authored intent: idempotency key, the TARGET principal at the
        peer (an addressing label), and the parsed, bounded payload.
    inbound:
        When relaying an inbound EventTrigger onward, its chain is preserved and
        this zone's hop is appended (additive only — upstream entries are never
        edited). ``None`` originates a fresh chain.
    ingested_sources:
        The real source ids that tainted this turn
        (``TurnContext.to_taint().sources``). Each not already present in the
        (inbound) chain is carried as an ``untrusted`` origin hop, preserving
        lineage the receiver re-derives under its own trust map. Sources already
        carried by ``inbound.provenance`` are not duplicated. Every recorded
        taint source is untrusted by construction (``TurnContext`` only records
        the sources that failed its map), so these hops are always ``untrusted``.

    signer:
        The broker's Ed25519 signing identity (``channels.signing.ChainSigner``),
        resolved at cold start from a Secrets-Manager-held key — never in the
        agent image, and never a caller/agent assertion. When supplied, this
        zone signs the FULL outbound chain (preserved upstream hops included),
        bound to this envelope's payload and anti-replay identity
        (channels/SIGNING.md). Inbound signatures are not carried onward — a relay
        re-packages the envelope, so they could not verify against it; the
        upstream *hops* still ride as lineage. ``None`` emits an unsigned chain
        (today's trust-by-transport behavior).

    Returns
    -------
    EventTrigger
        Ready for the `peer` connector to transport. ``sender_class`` is absent
        (receiver-owned, §C4).
    """
    upstream = [*inbound.provenance] if inbound is not None else []
    already_carried = {entry.source for entry in upstream}
    origin_hops = [
        ProvenanceEntry(zone=zone, source=source, evidence=[], label="untrusted", ts=ts)
        for source in (ingested_sources or [])
        if source not in already_carried
    ]
    hop = ProvenanceEntry(
        zone=zone,
        source=f"peer:{agent_identity}",
        evidence=list(evidence or []),
        label="untrusted" if turn_tainted else "trusted",
        ts=ts,
    )
    provenance = [*upstream, *origin_hops, hop]
    # Per-envelope signing: this zone signs the FULL chain as it leaves — the
    # preserved upstream hops included — bound to THIS envelope's payload and
    # anti-replay identity. Inbound signatures are NOT carried onward: a relay
    # re-packages a fresh payload/event_id/principal, so an upstream broker's
    # signature (over its own envelope) can never verify against this one. The
    # upstream *hops* still ride (lineage the receiver re-derives taint from,
    # #168); attributing each intermediate signer across a relay needs nested
    # per-hop attestations and is deferred to the normative spec (#178). Unsigned
    # when no signer is configured.
    chain_signatures: list = []
    if signer is not None:
        context = BoundContext(
            payload=payload,
            payload_digest=payload_digest,
            payload_ref=payload_ref,
            event_id=event_id,
            principal=principal,
            expiry=expiry,
            # Binds THIS zone's own sender claim into the signature (never an
            # inbound/relayed one — a relay signs its own claim, channels/
            # SIGNING.md S2), canonicalized so an honest but non-canonically-
            # spelled claim still verifies once the receiver's gate 3 normalize
            # canonicalizes it (`canonical_identity`, idempotent either order).
            sender_channel_identity=canonical_identity(channel_identity or agent_identity),
        )
        chain_signatures.append(signer.sign_prefix(provenance, context))
    return EventTrigger(
        event_id=event_id,
        principal=principal,
        sender=SenderIdentity(
            channel_type=channel_type,
            channel_identity=channel_identity or agent_identity,
            evidence=list(evidence or []),
        ),
        payload=payload,
        payload_digest=payload_digest,
        payload_ref=payload_ref,
        provenance=provenance,
        chain_signatures=chain_signatures,
        ts=ts,
        expiry=expiry,
    )
