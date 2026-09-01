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
| ratify / reject / acknowledge | `grants.commands ratify…` | **CheckerRole** (#202) | `checkerTrustedPrincipals` |
| seed / re-seed (bootstrap) | `grants.commands seed/re-seed` | **PromotionRole** (operator gate) | `promotionTrustedPrincipals` |
| tighten (voluntary, any level → in-loop) | `grants.commands tighten` | **PromotionRole** (operator gate) | `promotionTrustedPrincipals` |
| demotion runner (drills / out-of-band) | `grants.runner` | **DemotionRole** (operator gate) | `demotionTrustedPrincipals` |
| keyed grants audit | `grants.audit_command --table…` or `test_grants_audit_live` (keyed) | **AuditorRole** | `auditorTrustedPrincipals` |
| keyless CI audit | grants-audit workflow | WatcherRole (OIDC) | `githubOidcSubjects` |

Role ARNs come from CloudFormation exports: `safe-agents-{env}-{maker,checker,auditor,promotion,demotion}-role-arn`.

Notes:
- **MakerRole** has NO Secrets Manager access at all; **CheckerRole/PromotionRole** read only
  `*/issuer/*`; **AuditorRole**'s only secret is the env-scoped broker HMAC key (it fetches its
  own — a fully admin-free audit). For maker/checker/promotion flows the operator fetches
  `BROKER_HMAC_KEY` under ambient credentials BEFORE assuming (the one residual admin touch).
- MakerRole writes via **conditional UpdateItem only** (the proposal store's append idiom — a
  PutItem-shaped first cut was IAM-denied live), and since #203 that UpdateItem is
  **`LeadingKeys`-confined to `PROPOSAL#*` / `TOOLPROP#*`** on the grants and mcp-registry
  tables. Maker-mint is now structurally impossible rather than condition-guarded: a `GRANT#`
  or `TOOLDEF#` write is refused by IAM before any store condition is evaluated (proven live on
  both floors, 2026-07-28). **Its reads are deliberately unconditioned** — the maker reads the
  anchored grant, the envelope and the registry row for the propose-time re-vet, so scoping the
  reads would break evidence assembly. `identity/maker-cannot-mint-a-grant-row` pins both
  directions; do not relax it to make a deploy pass.
- Maker≠checker is credential separation (GAL §8): propose under MakerRole, ratify under
  CheckerRole — two ARNs the ceremony compares; the proposer cannot mint the checker's.
- **The keyed audit has two invocations, both floor-proven.** `python -m
  safe_agents.broker.grants.audit_command --table <name> [--json]` landed 2026-07-26 (#252) as the
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

## Deploying the Identity stack

**Every Identity deploy must re-pass ALL FIVE trust contexts or CDK drops the gates**
(same genre as the channels image-tag pins). All five name the deploying operator today.

Derive the ARN rather than pasting one: a literal account ARN here is a foreign principal
in five IAM **trust policies** for anyone but its author, and this block is meant to be
copy-pasted. The same `sts get-caller-identity` call is already THE GUARD above.

> ⚠️ **All five contexts, every time. A missing one degrades silently, and in two different
> ways** (#309). `trustedPrincipalsFromContext` returns `[]` when its key is unset, and unset is
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
> Until #309 lands, the protections are: pass all five, and **read `cdk diff` for
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
  --require-approval never
```

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
