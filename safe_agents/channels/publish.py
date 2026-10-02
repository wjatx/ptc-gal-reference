"""channels.publish — the outbound A2A seam (`peer.publish`).

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
from safe_agents.channels.signing import ChainSigner


def stamp_outbound(
    *,
    zone: str,
    agent_identity: str,
    channel_type: str,
    turn_tainted: bool,
    event_id: str,
    principal: str,
    audience: str,
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

    Lineage, not just a taint bit (PTC §8). A fresh origination that read
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
    audience:
        The zone id of the receiving airlock this envelope is addressed to. Set
        by the broker from its own configuration of the peer it is sending to,
        never by the agent. The receiver refuses an envelope whose ``audience``
        is not its own zone, compared exactly, and the signature covers the
        field, so an envelope signed for one receiver cannot be delivered to
        another or re-addressed (channels/SIGNING.md S9).
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
        bound to this envelope's content and every other signed field
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
    envelope = EventTrigger(
        event_id=event_id,
        principal=principal,
        audience=audience,
        sender=SenderIdentity(
            channel_type=channel_type,
            channel_identity=channel_identity or agent_identity,
            evidence=list(evidence or []),
        ),
        payload=payload,
        payload_digest=payload_digest,
        payload_ref=payload_ref,
        provenance=provenance,
        ts=ts,
        expiry=expiry,
    )
    if signer is not None:
        envelope = _signed(envelope, signer)
    # Whatever leaves here goes straight to a transport. Refuse now, loudly, an
    # envelope the receiver would drop as not forwardable: checked on the FINAL
    # envelope, since the signature adds to its size.
    envelope.to_wire()
    return envelope


def _signed(envelope: EventTrigger, signer: ChainSigner) -> EventTrigger:
    # Per-envelope signing: this zone signs the FULL chain as it leaves — the
    # preserved upstream hops included — together with the finished envelope it
    # sits on. The signer is handed the envelope itself, so what is signed is what
    # is sent, including THIS zone's own sender claim (never an inbound/relayed
    # one — a relay signs its own claim, channels/SIGNING.md S2). Inbound
    # signatures are NOT carried onward: a relay re-packages a fresh
    # payload/event_id/principal, so an upstream broker's signature (over its own
    # envelope) can never verify against this one. The upstream *hops* still ride
    # (lineage the receiver re-derives taint from); attributing each intermediate
    # signer across a relay needs nested per-hop attestations and is deferred to
    # the normative spec.
    return envelope.model_copy(update={"chain_signatures": [signer.sign_envelope(envelope)]})
