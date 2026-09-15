# audit — the append-only audit store and the closed learning loop

> **Status: the store is built.** The implementation ships at `safe_agents/broker/audit/` (the
> hash-chained tape with file and S3 sinks); this directory holds the design notes. The audit + closed learning loop spans
> sa#4 (autonomy & action pipeline) + sa#7 (security & safety); the learning loop draws from
> `auto-agents/book/ch48`.

The broker emits an `AuditRecord` at the moment of every side effect. This directory owns two
things that follow from that: the **store** those records land in (write-once, hash-chained,
external), and the **closed learning loop** that turns accumulated outcomes back into grant
recalibration.

The broker emits; this dir stores and reasons. The `AuditRecord` schema lives in `broker/SCHEMAS.md`.

## The store

Every broker decision — `allow`, `deny`, `transform`, `require_approval`, `abstain` — produces a
record. The store enforces three properties:

**Append-only / write-once.** S3 Object Lock (WORM mode) at the bucket level. The writing IAM
role can `PutObject` but not `DeleteObject` or overwrite. The agent holds no credentials to either
role. "The agent promises to log" is not the mechanism; the mechanism is that no path to modify
exists.

**Hash-chained.** Each record carries `prevHash → hash` over its fields (see `broker/SCHEMAS.md`
for the full `AuditRecord` field list). Any deletion or edit after the fact leaves a detectable
gap. A gap in the chain is itself an auditable event.

**External.** The store lives outside every compute arm (Lambda, EC2, Fargate). It survives an
ephemeral host going away and cannot die with the agent process. A human-readable activity view
is a *projection* of this log; the log is the source of truth.

See `ARCHITECTURE.md` §"The broker is the center" and `broker/README.md` §"Audit" for the
invariant. Infrastructure lives in `infra/` (the Object Lock bucket and its IAM boundaries).

## The closed learning loop

An audit log that only records the past is half the value. The other half is feeding outcomes back
into grant calibration (`auto-agents/book/ch48`).

The loop runs asynchronously — it is never on the critical path of a broker decision:

```
AuditRecords + outcome signals
    → drift detection (registry/)
    → recalibration proposals (PromotionRecord candidates)
    → maker-checker ratification (a human ratifies; a separate process proposes)
    → grant update (feeds re-promotion or demotion back to the grant store)
```

- **Drift detection** is in `registry/` and reads the runtime rollup. The loop here starts *after*
  a drift signal has been raised.
- **Recalibration proposals** are `PromotionRecord` candidates (schema in `broker/SCHEMAS.md`).
  They are *proposals*, not executed changes — the maker-checker path requires a human ratifier.
- **Demotion is deterministic and runs without a model in the loop.** Only promotion (increasing
  autonomy) goes through maker-checker ratification. A bad outcome triggers automatic demotion;
  re-promotion requires evidence and a human.
- **The grant store is writable only by the maker-checker promotion path** — the agent never
  writes it directly, and neither does this loop autonomously.

## Relationships

- `broker/` — emits `AuditRecord`; schema in `broker/SCHEMAS.md`. This dir owns the store, not
  the emission.
- `registry/` — drift detection reads the runtime rollup; this loop acts on drift signals.
- `infra/` — the Object Lock S3 bucket, IAM write role, and the DynamoDB grant table the loop
  proposes updates to.
- `broker/grant-lifecycle.md` — the autonomy state machine; recalibration operates within it.
