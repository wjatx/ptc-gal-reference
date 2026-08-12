"""Consumer-side polarity -> liveness-default derivation (sa#160).

**This is NOT base code.** It lives under `examples/` on purpose. The base ships
the liveness MECHANISM — a typed `Envelope.liveness` field and the deterministic
`Liveness.overdue()` predicate — and stays polarity-blind. The decision that an
*act-safe* agent should default its dead-man's-switch ON (a silenced monitor is
the harm) while an *abstain-safe* agent should default it OFF (silence is the
safe outcome) is a per-consumer safe-default judgement. Putting that mapping in
the base is the exact latent safety bug CLAUDE.md forbids ("the safe-default
polarity must NEVER be in the base"), so it is re-derived here, per agent.

The two worked consumers make the asymmetry concrete:

  * **sepsis-detection** (`polarity: act`) — failing to alert a deteriorating
    patient can be fatal. Forced abstention IS the harm, so liveness defaults ON
    with a tight deadline: a monitor that has gone quiet must page.
  * **missileer** (`polarity: abstain`) — silence is the safe outcome; not
    acting is always safe. Liveness defaults OFF; a dead-man's-switch here would
    only manufacture false pages.

Either default is overridable per agent (`resolve_liveness(..., override=...)`),
because polarity sets the *default*, not the ceiling — an abstain-safe agent
with a genuine liveness SLA can still opt in, and an act-safe agent can loosen
its deadline (a larger `deadline_seconds`) when its own risk analysis warrants.
"""
from __future__ import annotations

from typing import Literal, Optional

from safe_agents.broker.schemas.envelope import Liveness

Polarity = Literal["abstain", "act"]

# The act-safe default: page if the monitor has not completed its alerting op
# within 15 minutes. `expected_op` is the sign of life — a successful
# `notify.send` audit append — not a bespoke heartbeat.
_ACT_SAFE_DEFAULT = Liveness(expected_op="notify.send", deadline_seconds=900)


def derive_default_liveness(polarity: Polarity) -> Optional[Liveness]:
    """The polarity -> liveness-default mapping (consumer-owned).

    act  -> ON  (forced abstention is the harm; a silenced agent must page)
    abstain -> OFF (silence is safe; a dead-man's-switch would only false-page)

    Returns None for the abstain-safe default, meaning the Envelope carries no
    liveness contract — unset = OFF, honestly.
    """
    if polarity == "act":
        return _ACT_SAFE_DEFAULT
    return None


def resolve_liveness(
    polarity: Polarity, override: Optional[Liveness] = None
) -> Optional[Liveness]:
    """Resolve the effective liveness contract for an agent.

    A per-agent `override` (e.g. one that turns an abstain-safe agent's switch
    ON, or loosens an act-safe agent's deadline) wins over the polarity-derived
    default. Pass `override` only when the agent's own risk analysis departs
    from the polarity default; otherwise the default stands. (Note: `override=
    None` means "no override", not "force OFF" — it is indistinguishable from
    omitting the argument. Turning an act-safe agent's switch fully off is
    deliberately not expressible here; that is a risk decision that should be
    loud, not a None passed through a helper.)
    """
    if override is not None:
        return override
    return derive_default_liveness(polarity)
