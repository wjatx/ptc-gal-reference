# Canonical-serialization migration — runbook

Written 2026-07-28, NOT YET EXECUTED. Companion to `docs/operator-identities.md` (who runs what
under which role); it follows the precedent set by the #246 epoch cut. The change it migrates:
`canonical_grant_payload` and `proposal_to_json` were sorted-keys
+ ASCII but **not compact**, so they emitted Python's default `", "` / `": "` whitespace. Both now
use `separators=(",", ":")`, matching `canonical_record_payload`, `canonical_ack_payload` and
`safe_agents/channels/signing.py`. The rule is stated normatively in `broker/SCHEMAS.md` §1 and pinned by
`test_grants_integrity.py::test_canonical_payload_is_sorted_compact_ascii`.

## Read this first: the failure mode is NOT what it looks like

**A pre-change stored grant does not quarantine. It reads clean.** Verified by construction against
`InMemoryGrantStore` on 2026-07-28: an item whose `data` holds the old whitespace-bearing bytes and
whose `grantHash` is the HMAC over *those* bytes verifies, parses, and is served as authoritative.
The same holds for a pre-change stored proposal. That is #246 working exactly as designed — the
integrity basis is the **stored bytes**, verified verbatim, never a re-serialization of the parsed
model, so a serializer change cannot make an untouched row look tampered.

Two consequences, both load-bearing, and both the opposite of the intuition:

1. **`re-seed` is the wrong tool and will do nothing.** `reseed_command` re-stamps only grants whose
   `envelopeHash` differs from the in-force hash. This change does not move the envelope hash
   (`compute_envelope_hash` was already compact), so every class reports
   `[re-seed] SKIP …: already stamped with the in-force envelope hash`. And in the case where a row
   *had* failed its HMAC, `re-seed` refuses it outright — a store-layer quarantine is an incident,
   never a ceremony.
2. **There is no outage window and no forced ordering.** Old and new bytes coexist safely, so unlike
   the #246 re-shape there is no quarantine→deny period to shrink and no image-first constraint.
   Deploy whenever.

So the migration is **normalization, not recovery**. What is actually wrong with an un-migrated row
is narrower and worth stating precisely: its stored bytes are not the canonical serialization of the
grant they encode. Nothing in this codebase checks that (every verifier digests stored bytes), but
the normative spec about to be filed says stored bytes *are* canonical, and a second implementation
that recomputes an expected HMAC from a reconstructed Grant — the obvious way to write a conformance
checker — will disagree with an un-migrated row and have no way to tell that from a tamper.

## Scope — what is and is not affected

| Item type | Serializer changed? | Stored rows affected |
|---|---|---|
| `GRANT#` | yes (`canonical_grant_payload`) | **yes** — normalize |
| `PROPOSAL#` | yes (`proposal_to_json`) | pending proposals only; they expire — see below |
| `RECORD#` | no (`canonical_record_payload` was already compact) | no |
| `ACK#` | no (`canonical_ack_payload` was already compact) | no |
| `ENVELOPE#` | no (`compute_envelope_hash` was already compact) | no |
| MCP `TOOLDEF#` / `TOOLPROP#` | **no — deliberately unfixed** | no (see "Known divergence") |

**Both deployed environments are in scope: `development` and `production`.** Both are live floors
(the freely-mutable posture, 2026-07-11). Do development first and let it sit long enough to run a
keyed audit before touching production.

**Proposals need no migration leg.** A pending proposal verifies unchanged, is single-shot, and
carries an `expires_at`; it will be ratified, rejected or expire on its own. If you want a clean
cut, the honest move is to let the queue drain and mint any new proposal after the deploy — never to
edit a stored proposal, which is the exact thing the input-integrity corollary exists to forbid
(`broker/grant-lifecycle.md`).

## Option A — do nothing, let it normalize on the next write (recommended if nothing is filed yet)

Every write path serializes fresh: `update_grant` writes `canonical_grant_payload(grant)`, so the
next demotion, tighten, re-ratification, or envelope-hash re-seed normalizes that row for free. The
cost is that the table holds mixed-form rows until each is touched, and a conformance checker run
before then will report them.

Take this option only while the canonicality claim is internal. **Once the spec is filed, mixed-form
rows are a published-contract violation** and Option B is the answer.

## Option B — forced re-mint: archive → delete → `seed`

The #246 shape, and for the same reason: no ceremony command re-mints a row in place at an unchanged
level and unchanged envelope hash, so the re-mint runs through the sanctioned bootstrap path. This
also produces a fresh `bootstrap` PromotionRecord per grant, which is why the archive leg is not
optional — the pre-migration ledger arc is real history and the re-mint restarts it.

Per environment (`ENV` ∈ `development`, `production`), under `docs/operator-identities.md` identities:

**0. Pre-flight.** Confirm the deployed broker image already carries the change, or that you are
willing to have new-form rows read by an old image — which is safe here (verification is verbatim
either way), unlike #246. Record the current grant inventory per principal from the image-baked
manifest's granted classes; **never `Scan` from an acting role** — no acting role holds
`dynamodb:Scan` and the call is IAM-denied.

**1. Archive (the epoch cut, a git-tracked ceremony artifact).** Export the exact `GRANT#` and
`RECORD#` items verbatim into `archives/<date>-canonicalization/<ENV>-grants-pre-canonical.json`,
with a `README.md` stating what the artifact is, why delete+re-mint rather than transform, and the
provenance (session summary reference). Match the wording convention the #246 epoch cut
established.

**2. Delete the archived `GRANT#` and `RECORD#` items.** Leave `ENVELOPE#`, `PROPOSAL#`, `ACK#` and
every MCP item alone — none of them changed shape.

> **Operational gotcha, confirmed in `infra/lib/identity-stack.ts`:** **no ceremony role holds
> `dynamodb:DeleteItem` on the grants table.** PromotionRole has GetItem/Query/PutItem/UpdateItem;
> the only `DeleteItem` grant anywhere is the agent's counters-table idempotency eviction. The delete
> leg therefore runs out-of-band under an admin identity, exactly as the #246 legs did. That is not a
> gap to fix — a ceremony role that could delete grants would be a laundering seam — but it does mean
> this step is deliberately outside the ceremony surface and must be recorded as such in the archive
> README.

**3. Re-mint under PromotionRole.**

```
export AWS_PROFILE=<the profile that can assume the ENV PromotionRole>
export BROKER_STORE=dynamo
export BROKER_GRANTS_TABLE=safe-agents-<ENV>-grants
export BROKER_MANIFEST=<path to the image-baked manifest for this principal>
export BROKER_ENVELOPE_LOAD=store          # or leave unset for manifest mode
export BROKER_HMAC_KEY=<the env-scoped broker HMAC key>
python -m safe_agents.broker.grants.commands seed
```

Repeat per principal — `seed` is manifest-driven and mints the grants of exactly one manifest's
principal. Notes that bite:

- `BROKER_HMAC_KEY` **must be the same key the broker reads with**, or every re-minted grant
  quarantines on the broker's next read. It is fetched under ambient credentials *before* assuming
  PromotionRole (the one residual admin touch, per `docs/operator-identities.md`).
- In manifest mode, `_resolve_envelope_hash` **refuses** if the manifest's principal is not the
  principal being seeded (#199) — that refusal is the guard against minting a grant under the wrong
  envelope, so read the error rather than reaching for another manifest.
- `seed` never overwrites: if step 2 missed an item you will get
  `[seed] SKIP …: grant already exists`, which means that coordinate did **not** migrate. Treat a
  non-zero SKIP count as a failed run.
- `seed` reads each grant back and fails loudly if it comes back quarantined or absent.

**4. Verify.** Keyed audit under AuditorRole, and confirm `skipped_rules=[]` — a skipped rule is a
rule that did not run, which is not the same claim as a clean floor:

```
GRANTS_AUDIT_LIVE=1 GRANTS_AUDIT_ENV=<ENV> \
  .venv/bin/python -m pytest safe_agents/broker/tests/test_grants_audit_live.py -q
```

`GRANTS_AUDIT_ENV` selects the environment — **not** `BROKER_GRANTS_TABLE`; this has cost a session
before. (`python -m safe_agents.broker.grants.audit_command --table <name>` is the programmatic
equivalent, but per `docs/operator-identities.md` it has not yet had a live run, so prefer the pytest
path for anything load-bearing.)

Then bounce the broker service and confirm from its boot log that the grants load un-quarantined.

**5. The proof that is not optional.** *A promotion is not done until the promoted grant acts once*
— the same applies to a re-mint. A re-minted grant can be quarantine-dead and look perfectly
healthy in the table and in the audit. Exercise at least one
brokered call per re-minted principal, or ride the next scheduled unattended run and record it.
Until that happens the migration is unproven, not done.

**6. Restore levels.** `seed` mints at the manifest's floor level. Any coordinate that had been
promoted above the floor is now at the floor — which is the safe direction, and matches the ease
gradient (getting demoted is easy; getting promoted is a ceremony). Re-promotion runs through the
ordinary `propose` / `ratify` ceremony under Maker/Checker; do not shortcut it. Record in the archive
README which coordinates lost a rung, so the gap between the archived ledger and the live one is
explained rather than discovered later.

## Known divergence, deliberately NOT migrated here

`safe_agents/broker/mcp/proposals.py::canonical_proposal_payload` and
`safe_agents/broker/mcp/registry.py::canonical_row_payload` have the **same** defect and are left
alone by this change. Fixing them moves `GOLDEN_ROW_HMAC` (`test_mcp_row_integrity.py`) and needs its
own archive → delete → re-admit ceremony against both the dev and prod MCP registries — a separate
migration with its own re-vet cost. Both are pinned as `xfail(strict=True)` rows in
`test_grants_integrity.py::test_canonical_payload_is_sorted_compact_ascii`, so the divergence is
visible in every CI run and the suite goes red the moment someone fixes the serializer without
deleting the marker. If the filed spec covers the MCP admission ledger, this becomes urgent for the
same reason the grant basis did.
