# Operator identities — runbook

The operator identity plane (2026-07-14, commits 28b9d16 + 0ff8b5a): every human-run ceremony
function maps to a least-privilege standing IAM role, so no ceremony ever runs from the admin
baseline — an admin baseline converts a failed role-assume into a SILENT fallback with more
authority than intended. `infra/lib/identity-stack.ts` is the source of truth for shapes;
this doc is the operator's how-to.

## The function → identity map

| Function | Command | Identity | Gate context |
|---|---|---|---|
| propose | `grants.commands propose` | **MakerRole** | `makerTrustedPrincipals` |
| ratify / reject / acknowledge | `grants.commands ratify…` | **CheckerRole** | `checkerTrustedPrincipals` |
| seed / re-seed (bootstrap) | `grants.commands seed/re-seed` | **PromotionRole** (operator gate) | `promotionTrustedPrincipals` |
| tighten (voluntary, any level → in-loop) | `grants.commands tighten` | **PromotionRole** (operator gate) | `promotionTrustedPrincipals` |
| demotion runner + term lapse (drills / out-of-band) | `grants.runner` | **DemotionRole** (operator gate) | `demotionTrustedPrincipals` |
| keyed grants audit | `grants.audit_command --table…` or `test_grants_audit_live` (keyed) | **AuditorRole** | `auditorTrustedPrincipals` |
| keyless CI audit | grants-audit workflow | WatcherRole (OIDC) | `githubOidcSubjects` |

Role ARNs come from CloudFormation exports: `safe-agents-{env}-{maker,checker,auditor,promotion,demotion}-role-arn`.

Notes:
- **MakerRole** has NO Secrets Manager access at all; **CheckerRole/PromotionRole** read only
  `*/issuer/*`; **DemotionRole** reads only `*/evaluator/*`; **AuditorRole**'s only secret is the
  env-scoped broker HMAC key (it fetches its own — a fully admin-free audit). For
  maker/checker/promotion flows the operator fetches `BROKER_HMAC_KEY` under ambient credentials
  BEFORE assuming (the one residual admin touch).
- **There are TWO ledger-signing identities, and the split is the control.** The issuer key signs
  the records that RAISE or re-license authority (`promotion`, `bootstrap`, `tightening`,
  `reattestation`); the evaluator key
  signs the records that LOWER it (`demotion`, `lapse`). Verification binds record type to signing
  role, so disjoint IAM namespaces mean the deterministic demotion runner — which has no human and
  no model in its loop — cannot mint a record that promotes, and the human-ratified path cannot
  mint one that claims a demotion trigger fired. Pinned by `identity/secret-reader` and
  `identity/evaluator-signing-split`; do not merge the two namespaces to simplify a deploy.
  The PUBLIC halves are the deliberate exception: WatcherRole and AuditorRole read BOTH
  verify-key SSM parameters, because an audit must verify every record type it walks, and
  verifying is not signing. **Configure the two parameters together** — an auditing identity
  holding only one reports `RECORD_ROLE_UNRESOLVED` against the other role's records rather than
  passing them. See `RECORD_SIGNING_EPOCH` below.
- MakerRole writes via **conditional UpdateItem only** (the proposal store's append idiom — a
  PutItem-shaped first cut was IAM-denied live), and since the maker/checker write split that UpdateItem is
  **`LeadingKeys`-confined to `PROPOSAL#*` / `TOOLPROP#*`** on the grants and mcp-registry
  tables. Maker-mint is now structurally impossible rather than condition-guarded: a `GRANT#`
  or `TOOLDEF#` write is refused by IAM before any store condition is evaluated (proven live on
  both floors, 2026-07-28). **Its reads are deliberately unconditioned** — the maker reads the
  anchored grant, the envelope and the registry row for the propose-time re-vet, so scoping the
  reads would break evidence assembly. `identity/maker-cannot-mint-a-grant-row` pins both
  directions; do not relax it to make a deploy pass.
- Maker≠checker is credential separation (GAL §8): propose under MakerRole, ratify under
  CheckerRole — two ARNs the ceremony compares; the proposer cannot mint the checker's.
- **`propose` and `ratify` both need `BROKER_MANIFEST`, in either `BROKER_ENVELOPE_LOAD` mode.**
  The blast class of a promotion is derived from the ToolOp the manifest's `tool_ops` declares for
  the action class, raised by the in-force envelope's `confidence.high_blast` list. `propose`
  takes no blast flags, and refuses an action class the manifest does not declare. `ratify`
  derives the class again, prints it, and refuses a stored proposal whose class differs: reject
  that proposal and propose again. Both refuse a manifest whose principal is not the proposal's.
  In store mode the checker therefore reads the principal's `ENVELOPE#` row, which CheckerRole's
  grants-table `GetItem` already covers.
- **The keyed audit has two invocations, both floor-proven.** `python -m
  safe_agents.broker.grants.audit_command --table <name> [--json]` landed 2026-07-26 as the
  operator/programmatic path and is the one a wrapper's `posture` command shells out to; its first
  live run was
  2026-08-05 against `safe-agents-development-grants` under AuditorRole (keyed, verify-keys,
  clean exit 0, counts identical to the pytest path). `test_grants_audit_live` remains the
  floor path the CI workflow runs — unchanged. Both share `run_audit`, so they cannot disagree
  about the rules, only about how the table is reached.

## The assume idiom (ALWAYS use the identity guard)

A failed assume from an admin baseline silently falls back to admin — this bit live twice.
Never proceed past an assume without verifying:

```bash
# 1. (maker/checker/promotion flows only) fetch the HMAC key under ambient creds FIRST
export BROKER_HMAC_KEY=$(aws secretsmanager get-secret-value \
  --secret-id safe-agents/{env}/broker-hmac-key --query SecretString --output text)

# 2. assume, with retry for trust-propagation lag on a fresh deploy
CREDS=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$PURPOSE" \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text) || exit 1
export AWS_ACCESS_KEY_ID=$(echo $CREDS | awk '{print $1}') \
       AWS_SECRET_ACCESS_KEY=$(echo $CREDS | awk '{print $2}') \
       AWS_SESSION_TOKEN=$(echo $CREDS | awk '{print $3}')

# 3. THE GUARD — abort if not under the intended role
aws sts get-caller-identity --query Arn --output text | grep -q "$ROLE_NAME" \
  || { echo "NOT under $ROLE_NAME — aborting"; exit 1; }
```

Related zsh gotcha: brace ARN variables (`${VAR}`) — bare `$VAR:...` triggers history
modifiers and mangles ARNs.

## Signing key material — what CDK does NOT create

`IdentityStack` creates no Secret and no Parameter (`identity-stack.ts:22-24`). It grants access to
ARN *patterns*; the material behind them is operator-provisioned, out of band, once per
environment. Two signing identities means two key pairs, four objects:

| Object | Kind | Read by | Env var |
|---|---|---|---|
| `safe-agents/{env}/issuer/signing-key` | Secrets Manager, PEM private key | Promotion, Checker | `ISSUER_SIGNING_KEY_SECRET_ARN` |
| `/safe-agents/{env}/issuer/verify-keys` | SSM `String`, JSON `{key_id: public_pem}` | Watcher, Auditor | `ISSUER_VERIFY_KEYS_PARAM` |
| `safe-agents/{env}/evaluator/signing-key` | Secrets Manager, PEM private key | Demotion | `EVALUATOR_SIGNING_KEY_SECRET_ARN` |
| `/safe-agents/{env}/evaluator/verify-keys` | SSM `String`, JSON `{key_id: public_pem}` | Watcher, Auditor | `EVALUATOR_VERIFY_KEYS_PARAM` |

The verify-key parameters must be plain `String`, not `SecureString`: neither read-only identity
holds `kms:Decrypt` on an SSM key, so a `SecureString` is unreadable by the audit that needs it.
Public key material in a `SecureString` buys nothing and breaks the audit.

**The signing env contract is SIX names per role.** For each of `ISSUER_` /
`EVALUATOR_`:

| Suffix | Required? |
|---|---|
| `_SIGNING_KEY_SECRET_ARN` | one key source, **exactly one** of ARN or FILE; both set REFUSES |
| `_SIGNING_KEY_FILE` | the local no-AWS arm only; refused outright on the dynamo arm |
| `_SIGNING_KEY_ID` | **required whenever a key source is set** — a signer no verifier can resolve |
| `_SIGNING_ZONE` | **required whenever a key source is set** (or `--zone` per invocation) |
| `_VERIFY_KEYS_PARAM` | on the auditing identity, not the signing one |
| `_VERIFY_KEYS_FILE` | the local no-AWS arm of the same: a file holding the JSON map the parameter holds. **Exactly one** of PARAM or FILE; both set REFUSES |

The zone is not decoration: it is baked into the DSSE statement as attribution
(`record_signing.py`, `predicate.signer.zone`), so `resolve_signer_for_role` **refuses** a key
source with no zone rather than defaulting one — *"a signer a verifier cannot resolve or attribute
is a misconfiguration, never a silent default"*. A key_id with no key source refuses too:
half-configured signing never degrades to an unsigned record.

**Give each role its own key_id.** `resolve_record_key_resolvers` refuses at cold start if any
`key_id` appears in BOTH verify-key maps — *"one key cannot hold two signing roles, or the
evaluator could mint promotion records"*. Reusing a key_id across the two roles quietly undoes the
split this whole section exists for, so it fails loudly and early instead.

The secret NAME only needs to fall inside the namespace the IAM grant matches (`*/issuer/*`,
`*/evaluator/*`); the names above are the convention. Provisioning an evaluator key pair:

```bash
ENVNAME=development
openssl genpkey -algorithm ed25519 -out /tmp/evaluator.pem
chmod 600 /tmp/evaluator.pem
openssl pkey -in /tmp/evaluator.pem -pubout -out /tmp/evaluator.pub

aws secretsmanager create-secret \
  --name "safe-agents/${ENVNAME}/evaluator/signing-key" \
  --secret-string "file:///tmp/evaluator.pem" \
  --kms-key-id "$(aws cloudformation list-exports \
      --query "Exports[?Name=='safe-agents-${ENVNAME}-secrets-key-arn'].Value" --output text)"

# key_id is the operator's choice; it is what a ledger verifier resolves the
# signature by, and it must match EVALUATOR_SIGNING_KEY_ID on the runner.
aws ssm put-parameter --type String --overwrite \
  --name "/safe-agents/${ENVNAME}/evaluator/verify-keys" \
  --value "$(jq -Rn --arg k "${ENVNAME}-evaluator-1" \
      --rawfile pem /tmp/evaluator.pub '{($k): $pem}')"

shred -u /tmp/evaluator.pem 2>/dev/null || rm -P /tmp/evaluator.pem
```

Then set on whatever runs `grants.runner`: `EVALUATOR_SIGNING_KEY_SECRET_ARN` (the ARN from
`create-secret`), `EVALUATOR_SIGNING_KEY_ID` (`${ENVNAME}-evaluator-1` above) and
`EVALUATOR_SIGNING_ZONE`. All three, or the runner refuses. The local no-AWS arm uses
`EVALUATOR_SIGNING_KEY_FILE` in place of the ARN — mutually exclusive with it, and refused on the
dynamo arm, exactly as `ISSUER_SIGNING_KEY_FILE` is.

**Ordering, and the trap.** Deploy the Identity stack FIRST, then provision — `create-secret`
needs the secrets CMK the stack's exports name, and the IAM grants are namespace patterns that do
not care whether the secret exists yet. The trap is on the OTHER side: an **empty or missing
verify-keys parameter does not fail the write path, only the read path**. The runner signs happily
with a key nobody can resolve, and only the audit notices (see the next section). Publish the
public key BEFORE the first signed demotion or lapse, and close the loop by running the keyed
audit under AuditorRole once a record has landed — the standing rule that a promotion is not done
until the promoted grant acts once applies to a signing key too.

## Auditing the two roles — `RECORD_SIGNING_EPOCH`

On whatever identity runs the audit, set **both** verify-key parameters and the epoch:

```bash
export ISSUER_VERIFY_KEYS_PARAM=/safe-agents/{env}/issuer/verify-keys
export EVALUATOR_VERIFY_KEYS_PARAM=/safe-agents/{env}/evaluator/verify-keys
export RECORD_SIGNING_EPOCH=2026-09-19T00:00:00+00:00   # ISO-8601, WITH offset
```

`RECORD_SIGNING_EPOCH` is the instant record signing was adopted at. With it set, EVERY record
must carry a verifying signature of its role (GAL-SPEC §6.10), whatever its type and whatever its
`ts`. No record is exempt because of its own timestamp. On an unsigned record that field was
written by whoever wrote the row, so the audit does not take it as evidence of age. An unsigned
record from before signing was adopted is a `RECORD_SIGNATURE_VERIFIES` violation like any other,
and it stays one until an operator dispositions it (see "Unsigned history" below). Four behaviours
to know, all of them chosen so that a misconfiguration cannot read as coverage:

- **Unset** — safe and self-announcing. The scope stays what it was (promotion required, lapse
  only if it carries a signature) plus a loud `record-signing-epoch-unset` annotation saying the
  all-types requirement is NOT enforced. Never a silent narrowing.
- **Naive or unparseable** — the audit exits **2** (`could not run`), never 1. A missing UTC
  offset is refused by name: *"the epoch must name an unambiguous instant."* Callers key on
  2-vs-1, so do not collapse them.
- **In the future** — a `RECORD_SIGNING_EPOCH_VALID` **violation**, un-waivable. An epoch after
  the evaluation instant is not yet in force. It narrows nothing: the audit still checks every
  record of every type, so the report carries this violation and a finding for each unsigned
  record. Correct the value. It cannot be acknowledged.
- **Only one verify param set** — the other role's records fail `RECORD_SIGNATURE_VERIFIES` with
  reason `RECORD_ROLE_UNRESOLVED`: *"a role we cannot check is never a role that passes."* So the
  two parameters are **required together**, not independently useful.

That last point is sharper than "once an epoch is set": a **signed lapse record produces a finding
even with no epoch configured**, because a lapse that carries a signature is verified in the
no-epoch scope too. An auditing identity given only `ISSUER_VERIFY_KEYS_PARAM` starts reporting
against evaluator-signed records as soon as one exists — not when the epoch is turned on.

A key_id known to the wrong role fails as `RECORD_SIGNER_WRONG_ROLE`, and one known to both as
`RECORD_SIGNER_ROLE_AMBIGUOUS`. Both are the split doing its job; neither is a reason to merge the
maps.

**On a local (sqlite) floor** there is no parameter store, so the same two maps are given as
files: `ISSUER_VERIFY_KEYS_FILE` and `EVALUATOR_VERIFY_KEYS_FILE`, each naming a file that holds
the JSON `{key_id: public_pem}` map. The content is public, so the file needs no owner-only mode.
Everything above applies unchanged, including the refusal of a key_id that appears in both maps.
`python -m safe_agents.broker.grants.audit_command --sqlite PATH` reads them, and on that arm it
audits the MCP admitted-tool registry in the same run, verifying admission records under the
issuer's keys (`broker/MCP-HOST.md`, "Where the stored registry is audited").

With NEITHER role's verify source set, `RECORD_SIGNATURE_VERIFIES` is skipped entirely and
annotated `record-signing-epoch-unenforceable`. Read `skipped_rules`, not just `clean`: a report
with no violations and a skipped signature rule is a different claim from one with nothing skipped.

### Unsigned history: acknowledge each record, or re-mint the ledger

A ledger that predates record signing can hold unsigned records of any type. Setting the epoch
makes each one a `RECORD_SIGNATURE_VERIFIES` violation, and the audit exits 1 until every one is
dispositioned. There are two ways to do that.

**Acknowledge the record.** Run the keyed audit under AuditorRole and read the violations:

```bash
python -m safe_agents.broker.grants.audit_command --table safe-agents-{env}-grants --json
```

Each unsigned record is reported at its coordinate, with a detail of this form:

```
bootstrap record ts=2026-06-01T00:00:00+00:00 no grant -> in-loop (stored bytes sha256:<64 hex>) carries no DSSE signature; it must be signed by the issuer identity
```

Read the record before excusing it (`pk = RECORD#<coordinate>`, `sk = <ts>#<type>`). The finding
names the record's type, its `ts`, the level change it makes and the digest of its stored bytes,
and nothing about who wrote it. A row somebody planted reads the same in the report as honest
history, and the acknowledgment is the step that decides which one it is. Then, under CheckerRole with the issuer signing environment set
(`ISSUER_SIGNING_KEY_SECRET_ARN`, `ISSUER_SIGNING_KEY_ID`, `ISSUER_SIGNING_ZONE`), acknowledge that
one finding:

```bash
python -m safe_agents.broker.grants.commands acknowledge \
  --table-name safe-agents-{env}-grants \
  --rule RECORD_SIGNATURE_VERIFIES \
  --coordinate '<coordinate, exactly as reported>' \
  --detail '<detail, exactly as reported>' \
  --rationale '<why this record is honest history>'
```

It is one command per record. The acknowledgment is a signed record of its own, appended beside the
ledger. It binds the rule, the coordinate and the sha256 of the detail, and the detail carries the
sha256 of the record's stored bytes, so it excuses those bytes and no others. If the row is later
replaced at the same coordinate, type and `ts`, the detail changes and the violation returns. Run
the audit again: the record now appears under `acknowledged` with the waiver reference, and the
exit code is 0 once no other violation is outstanding.

An acknowledgment of a `RECORD_SIGNATURE_VERIFIES` finding made before the detail carried the
digest binds the old wording. It no longer matches, the violation returns, and the record must be
acknowledged again.

**Re-mint the ledger.** Where a coordinate's history can be restarted, the archive, delete and
`seed` procedure in `docs/grant-canonicalization-runbook.md` (Option B) replaces it with a new
`bootstrap` record, which `seed` signs when the issuer key is configured. `re-seed` is not a
way to re-mint history: it re-stamps a grant's envelope hash and appends one new `reattestation`
record, which it signs with the issuer key (`--zone` / `ISSUER_SIGNING_ZONE`), and it leaves every
earlier record as it was. With no issuer key configured it refuses and writes nothing.

## Deploying the Identity stack

**Every Identity deploy must re-pass ALL FIVE trust contexts or CDK drops the gates**
(same genre as the channels image-tag pins). All five name the deploying operator today.

Derive the ARN rather than pasting one: a literal account ARN here is a foreign principal
in five IAM **trust policies** for anyone but its author, and this block is meant to be
copy-pasted. The same `sts get-caller-identity` call is already THE GUARD above.

> ⚠️ **All five contexts, every time. A missing one degrades silently, and in two different
> ways** (#112). `trustedPrincipalsFromContext` returns `[]` when its key is unset, and unset is
> indistinguishable from empty. What happens next depends on which role you dropped, so do not
> carry the blanket "it deletes the role" version of this warning — it is true for three of the
> five and wrong for the other two:
>
> - **Maker, Checker, Auditor** are synthesized only when their context is non-empty
>   (`if (principals.length > 0)`, `identity-stack.ts:368/463/553`). Omit one on a redeploy and
>   CloudFormation **removes an existing role** with no error and nothing that reads as a warning.
>   Drop maker and checker together and you have quietly removed maker≠checker.
> - **Promotion and Demotion** are created **unconditionally**. Their context is *additive* to the
>   trust policy (`identity-stack.ts:231-240, 309-318`): supplied, the named ARNs join the service
>   principals; omitted, trust reverts to `computePrincipals()` alone. The role, its policies and
>   its `*-role-arn` export are untouched. What breaks is the human path — `sts:assume-role` fails,
>   and per the guard at the top of this doc a failed assume from an admin baseline falls back to
>   admin, which is the exact hazard the gate exists to close.
>
> Until #112 lands, the protections are: pass all five, and **read `cdk diff` for
> resource-level removals before deploying** — capture it with `> file 2>&1`, because cdk writes
> the diff to stderr and a plain `> file` yields an empty file that any grep passes vacuously.
> A MakerRole-only change shows exactly one resource: `[~] AWS::IAM::Policy
> MakerRole/DefaultPolicy`.
>
> If you need the values for an already-deployed stack, reconstruct them from the deployed trust
> policies rather than guessing: `aws iam get-role --role-name <phys> --query
> Role.AssumeRolePolicyDocument` over the five `*Role` physical ids in
> `SafeAgents-Identity-{env}`.

```bash
CLI=$(aws sts get-caller-identity --query Arn --output text)
echo "deploying with trust principal: $CLI"   # confirm before proceeding
# If that prints an arn:aws:sts::...:assumed-role/... form, do NOT use it verbatim:
# an assumed-role ARN is not valid as an IAM trust principal. Pass the underlying
# role ARN (arn:aws:iam::<acct>:role/<name>) instead.
npx cdk deploy SafeAgents-Identity-{env} -c environment={env} \
  -c checkerTrustedPrincipals=$CLI -c demotionTrustedPrincipals=$CLI \
  -c promotionTrustedPrincipals=$CLI -c makerTrustedPrincipals=$CLI \
  -c auditorTrustedPrincipals=$CLI \
  -c githubOidcSubjects=repo:<owner>/<repo>:*,repo:<owner>@<owner-id>/<repo>@<repo-id>:* \
  --require-approval never
```

`githubOidcSubjects` is the sixth context, and the one whose omission fails silently. Unset, the
deploy succeeds and both read-only watcher roles trust a sentinel no GitHub token can present, so
a CI workflow that assumed them (the keyless grants audit) stops working with nothing in the deploy
output to say why. Pass both spellings of the repository whose workflows assume them; drop the line
only if no workflow does. `docs/cdk-context-contract.md` explains the two forms.

Verify after deploy: `aws iam get-role --role-name <role> --query Role.AssumeRolePolicyDocument`
— gated NEW roles (Maker/Checker/Auditor) trust ONLY the named ARNs; gated EXISTING roles
(Promotion/Demotion) trust the three service principals PLUS the named ARNs (the deployment
binding is never displaced).

## Adding a new operator identity (the checklist)

The idiom is context-gated trust, OFF by default, pinned by conformance. In one pass:

1. **Shape the role from the command's actual API calls**, not from intuition — read the store
   code for the write verbs (UpdateItem-vs-PutItem matters; the MakerRole first cut got this
   wrong and IAM caught it). Grant read-only wherever the function judges what it reads
   (counters rule).
2. **Gate on `<x>TrustedPrincipals`** via `trustedPrincipalsFromContext` in
   `identity-stack.ts`. New role → ArnPrincipals only. Existing service role → ADDITIVE
   CompositePrincipal. Publish the ARN export.
3. **Conformance rows** (`infra/tests/conformance.ts`): off-by-default, trust shape,
   permission shape (or permissions-unchanged for trust-only gates), and update the
   all-gates-on composition row's role count.
4. **Deploy both floors** with ALL contexts (see above).
5. **Live-prove at first use**: run the real ceremony under the role (identity-guarded),
   plus negative probes for the authority it must NOT have. A role is not done until it has
   acted once and been denied once.
6. Update the table in this doc.
