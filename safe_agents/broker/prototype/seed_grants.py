"""seed_grants.py — DEPRECATED delegate to the grant-ceremony command surface (#123).

This entrypoint was the out-of-band grant seed for the broker's AWS read-mode
(sa#36 Phase C1) and, in store mode, the de-facto re-stamp path after an
envelope-hash change. Both jobs now belong to the sanctioned ceremony commands:

    python -m safe_agents.broker.grants.commands seed      # bootstrap (this delegate)
    python -m safe_agents.broker.grants.commands re-seed   # envelope-hash re-attestation

This module keeps its env-var interface (BROKER_GRANTS_TABLE, BROKER_HMAC_KEY,
BROKER_ENVELOPE_LOAD, BROKER_MANIFEST — all still honored) so existing runbooks
don't break, prints a deprecation banner, and delegates to `commands seed`.

Semantics changed with the retirement (deliberately): seed is now CREATE-ONLY —
an existing grant is skipped, never overwritten (the old blind put_grant
re-stamp is gone), and every grant created gets a bootstrap-typed
PromotionRecord ledger counterpart from birth. To re-stamp grants after a
far-jump envelope-hash change, use `commands re-seed` (same level, refused on
an HMAC-tamper quarantine).

Run with credentials that can WRITE the grants table (promotion role or admin) —
NOT brokerRole. boto3 reads region/credentials/endpoint from the environment.
"""
from __future__ import annotations

import sys

_DEPRECATION_BANNER = """\
================================================================================
DEPRECATED: safe_agents.broker.prototype.seed_grants
The sanctioned grant-mutation path is the ceremony command surface (#123):
    python -m safe_agents.broker.grants.commands seed      (bootstrap)
    python -m safe_agents.broker.grants.commands re-seed   (envelope-hash re-attestation)
Delegating to `commands seed`: create-only — existing grants are SKIPPED, never
overwritten, and each new grant gets a bootstrap ledger record. To re-stamp
grants after an envelope-hash change, use `commands re-seed` instead.
================================================================================"""


def main() -> int:
    print(_DEPRECATION_BANNER, file=sys.stderr)
    # broker_server imports must stay side-effect-free — same belt-and-braces as
    # the ceremony commands themselves, scoped so it never leaks (#210).
    from safe_agents.broker.prototype.boot_config import grant_load_suppressed

    with grant_load_suppressed():
        from safe_agents.broker.grants.commands import main as commands_main

    return commands_main(["seed"])


if __name__ == "__main__":
    raise SystemExit(main())
