import { Aws, Stack } from 'aws-cdk-lib';
import {
  ArnPrincipal,
  CompositePrincipal,
  Effect,
  OpenIdConnectPrincipal,
  OpenIdConnectProvider,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { FoundationStackProps } from './foundation-props';
import { importValue, publish } from './naming';

/**
 * IdentityStack — the four boundary IAM roles (agent / broker / promotion / demotion) that
 * physically encode the core invariants: the agent holds no connector credentials (#1) and the
 * broker runs under a separate IAM identity (#3).
 *
 * Implements sa#15. Gates on StateStack (#14) — role policies are scoped to the table / bucket /
 * KMS ARNs StateStack exports (dependency wired in the entrypoint). No Secret resources are
 * created here; the broker's scoped read access to the <agent>/connectors/* ARN pattern is
 * modeled via IAM policy. Concrete secrets are added per-agent later.
 */
export class IdentityStack extends Stack {
  constructor(scope: Construct, id: string, props: FoundationStackProps) {
    super(scope, id, props);

    const env = props.environment;

    // ── Import StateStack ARNs ────────────────────────────────────────────────────────────────────
    // All resource ARNs come from StateStack exports so policies are exactly scoped — no wildcards,
    // no account-level assumptions. (agent-runs-table-arn is imported here for the watcher role's
    // read-only Query + CMK Decrypt; the other four boundary roles don't need it.)
    const grantsTableArn    = importValue(env, 'grants-table-arn');
    const mcpRegistryTableArn = importValue(env, 'mcp-registry-table-arn');
    const countersTableArn  = importValue(env, 'counters-table-arn');
    const intentsTableArn   = importValue(env, 'intents-table-arn');
    const auditBucketArn    = importValue(env, 'audit-bucket-arn');
    const ledgerBucketArn   = importValue(env, 'ledger-bucket-arn');
    const tablesKeyArn      = importValue(env, 'tables-key-arn');
    const auditKeyArn       = importValue(env, 'audit-key-arn');
    const ledgerKeyArn      = importValue(env, 'ledger-key-arn');
    const secretsKeyArn     = importValue(env, 'secrets-key-arn');
    const agentRunsTableArn = importValue(env, 'agent-runs-table-arn');

    // ── Compute service principals ────────────────────────────────────────────────────────────────
    // Each role starts broad (EC2 + ECS tasks + Lambda) so the foundation stack has no dependency
    // on compute-arm stacks. Per-arm trust is tightened in the arm stacks: EC2 adds an
    // instance-profile condition, Fargate scopes to the task definition, Lambda to the function ARN.
    const computePrincipals = () =>
      new CompositePrincipal(
        new ServicePrincipal('ec2.amazonaws.com'),
        new ServicePrincipal('ecs-tasks.amazonaws.com'),
        new ServicePrincipal('lambda.amazonaws.com'),
      );

    // ── 1. agentRole — the dumbest role ───────────────────────────────────────────────────────────
    // The agent holds ZERO AWS authority. No inline policy statements — no Secrets Manager access,
    // no dynamodb write on the grants table, no writes anywhere. Egress to connectors is enforced
    // at the network layer (NetworkStack), not through IAM. A fully compromised agent "can still
    // only ask." The absence of any policy is the guarantee; nothing to add, nothing to audit away.
    const agentRole = new Role(this, 'AgentRole', {
      assumedBy: computePrincipals(),
      description: `safe-agents ${env} - agent compute role (zero authority; egress = broker only)`,
    });
    // No addToPolicy calls. Intentional.

    // ── 2. brokerRole — holds the keys, cannot promote itself ────────────────────────────────────
    // The broker reads secrets and enforces grants; it is the sole path from agent to connector.
    // It has NO write access to the grants table — only promotionRole and demotionRole may alter
    // grants. The broker can neither promote itself nor the agent.
    const brokerRole = new Role(this, 'BrokerRole', {
      assumedBy: computePrincipals(),
      description: `safe-agents ${env} - broker process role (sole secret reader; no grants write)`,
    });

    // Secrets Manager: read only, scoped to the <agent>/connectors/* layout.
    // The broker is the ONLY IAM principal that may read connector credentials; the agent role has
    // no secretsmanager action at all. No secret ARNs are known at the foundation level — the
    // wildcard prefix pattern enforces the per-agent namespace boundary.
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resources: [
          `arn:${Aws.PARTITION}:secretsmanager:${Aws.REGION}:${Aws.ACCOUNT_ID}:secret:*/connectors/*`,
        ],
      }),
    );

    // KMS: decrypt only on the secrets CMK (to unwrap secret values returned by Secrets Manager).
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt'],
        resources: [secretsKeyArn],
      }),
    );

    // DynamoDB — grants table: READ ONLY. The broker reads grants to make decisions; it must not
    // write them. Index resources are included for Query calls on any GSIs added later.
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:Query'],
        resources: [grantsTableArn, `${grantsTableArn}/index/*`],
      }),
    );

    // DynamoDB — MCP admitted-tool registry (#174): READ ONLY. The McpHost reads admitted
    // TOOLDEF# rows at discovery time to two-key-admit an (server_id, tool_name); it never
    // writes them. Mirrors "the broker cannot write grants" — the admission ceremony
    // (safe_agents/broker/mcp/commands.py) is the registry's only writer, and this read-only
    // statement makes that an IAM fact, not just a convention. (KMS: the table rides the same
    // tablesKey CMK the broker already decrypts via the blanket kms:Decrypt/GenerateDataKey
    // statement below — no separate key statement needed.)
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:Query'],
        resources: [mcpRegistryTableArn, `${mcpRegistryTableArn}/index/*`],
      }),
    );

    // DynamoDB — counters + intents: read/write. The broker tracks per-principal budget counters
    // and records durable Intent state for the require_approval path.
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:Query'],
        resources: [
          countersTableArn, `${countersTableArn}/index/*`,
          intentsTableArn,  `${intentsTableArn}/index/*`,
        ],
      }),
    );

    // DynamoDB — counters ONLY: DeleteItem (idempotency eviction, #148). Two uses, both on
    // IDEM# items. A stored NON-EXECUTED outcome (deny/abstain/require_approval) is evicted on
    // read so the key becomes recordable again once a retry actually executes — leaving it would
    // block put-if-absent and force every later retry to re-execute. And enforce() RELEASES its
    // own in-flight claim on those same outcomes, plus when a fault lands before any side effect
    // could have happened; it is also the operator's path to clear a claim stranded by a crashed
    // broker. The claim's two terminal transitions (executed/failed) are conditional UpdateItem
    // CAS, covered by the statement above. Deliberately NOT granted on grants (read-only to the
    // broker) or intents (terminal-state transitions are UpdateItem CAS, never delete).
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:DeleteItem'],
        resources: [countersTableArn],
      }),
    );

    // KMS: decrypt + generate data key for DynamoDB table I/O (customer-managed CMK on all tables).
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
        resources: [tablesKeyArn],
      }),
    );

    // S3 audit bucket: PutObject + GetObject on objects, ListBucket on the bucket. No
    // DeleteObject — tamper-evidence rests on Object Lock/WORM plus the hash chain, NOT on
    // read-denial. GetObject is REQUIRED to resume the chain on restart (sa#132): the sink
    // lists keys to find the max sequence number (sa#104), then must READ that record's
    // body to compute the previous hash for the next link — a broker task cycle with
    // records present and no GetObject crash-loops at startup. The broker reading records
    // it wrote itself is not an exfiltration channel; "cannot tamper" still holds.
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:PutObject', 's3:GetObject'],
        resources: [`${auditBucketArn}/*`],
      }),
    );
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:ListBucket'],
        resources: [auditBucketArn],
      }),
    );

    // KMS: generate data key + encrypt for audit writes; Decrypt because the chain-resume
    // GetObject (sa#132) reads an SSE-KMS object — S3 decrypts server-side on the caller's
    // KMS permissions.
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:GenerateDataKey', 'kms:Encrypt', 'kms:Decrypt'],
        resources: [auditKeyArn],
      }),
    );

    // S3 ledger bucket (sa#131): PutObject ONLY. This bucket has no Object Lock — it is the
    // agent's durable ledger/brief copy, not the tamper-evident audit chain — so IAM is the
    // sole append-only enforcement: no Delete*, no PutObjectAcl, no GetObject, and no
    // ListBucket (the audit sink lists keys only to resume its hash chain; the ledger has no
    // chain to resume). The broker can add records; it can never read back, rewrite, or remove.
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:PutObject'],
        resources: [`${ledgerBucketArn}/*`],
      }),
    );

    // KMS: generate data key + encrypt for ledger writes (SSE-KMS on the ledger bucket).
    brokerRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:GenerateDataKey', 'kms:Encrypt'],
        resources: [ledgerKeyArn],
      }),
    );

    // ── 3. promotionRole — maker-checker grants writer ────────────────────────────────────────────
    // DESIGN NOTE: Both promotionRole and demotionRole write the grants table. The load-bearing
    // invariant is that the AGENT and the BROKER cannot write grants — not that demotion cannot.
    // Promotion raises authority via the recorded maker-checker path (a human ratifies the
    // PromotionRecord); demotion lowers it deterministically with no model in the loop
    // (per ARCHITECTURE.md "recorded maker-checker promotion + automatic deterministic demotion").
    // Distinct roles so each can be independently rotated, monitored, and audited.
    // Operator assumability (context-gated OFF, the shared idiom — see DemotionRole below):
    // seed / re-seed are the bootstrap ceremony ops that legitimately run under THIS role, and
    // before this gate they ran as raw admin (or via temp trust surgery, the pre-#202 pain).
    // The gate is ADDITIVE to the service-principal deployment binding. #203 later moves
    // seed/re-seed off PromotionRole entirely (the LeadingKeys write split); until then this
    // is the sanctioned operator path.
    const promotionPrincipals = trustedPrincipalsFromContext(this, 'promotionTrustedPrincipals');
    const promotionRole = new Role(this, 'PromotionRole', {
      assumedBy:
        promotionPrincipals.length > 0
          ? new CompositePrincipal(
              computePrincipals(),
              ...promotionPrincipals.map((arn) => new ArnPrincipal(arn)),
            )
          : computePrincipals(),
      description: `safe-agents ${env} - maker-checker promotion role (grants writer; human-ratified path only)`,
    });

    promotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:Query', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
        resources: [grantsTableArn, `${grantsTableArn}/index/*`],
      }),
    );

    promotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
        resources: [tablesKeyArn],
      }),
    );

    // Counters table: READ ONLY. The ceremony's propose command reads the windowed evidence
    // counters (the same scoped principal+op+UTC-day keys the PEP meters) to assemble the
    // promotion predicate's inputs. GetItem only — the ceremony must not be able to move a
    // counter it judges by (the same rule as the demotion runner below).
    promotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem'],
        resources: [countersTableArn],
      }),
    );

    // Secrets Manager: the ISSUER signing key only, under the */issuer/* namespace. The grant
    // issuer signs each PromotionRecord (DSSE, the #181 machinery) with its own Ed25519 identity —
    // deliberately a SEPARATE key from the broker's chain-signing key: the broker cannot sign
    // promotions, symmetric with "the broker cannot write grants". The namespace split is the
    // enforcement: promotion reads */issuer/*, broker reads */connectors/*, and neither can read
    // the other's (the onlyBrokerReadsConnectorSecrets conformance row pins this).
    //
    // Deliberately NO */evaluator/* either. The issuer key signs the records that RAISE authority
    // (promotion, bootstrap, tightening); the evaluator key signs the records that LOWER it
    // (demotion, lapse). Verification binds record type to signing role, so an identity holding
    // only this key cannot mint a record asserting that a demotion trigger fired — the mirror of
    // the demotion role being unable to mint a promotion. See DemotionRole below.
    promotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resources: [
          `arn:${Aws.PARTITION}:secretsmanager:${Aws.REGION}:${Aws.ACCOUNT_ID}:secret:*/issuer/*`,
        ],
      }),
    );

    // KMS: decrypt only on the secrets CMK (to unwrap the issuer key), mirroring the broker.
    promotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt'],
        resources: [secretsKeyArn],
      }),
    );

    // ── 4. demotionRole — deterministic demotion, no model in the loop ───────────────────────────
    // See DESIGN NOTE above. UpdateItem only — no PutItem API — which limits blast radius but does
    // NOT by itself prevent minting: dynamodb:UpdateItem authorizes upsert-creation. The
    // lower-never-mint / append-only guarantees are enforced by the store's ConditionExpressions
    // (attribute_exists for grant updates, attribute_not_exists for ledger appends); IAM narrows
    // what a compromised runner could reach rather than proving the invariant.
    // Operator assumability (context-gated OFF, the #202 idiom): the runner's deployment
    // binding is a service task, but drills and out-of-band operator runs must execute under
    // THIS role — not fall back to an ambient admin when an assume fails silently (the
    // 2026-07-14 #192 drill ran its demotion as CLI_User for exactly that reason). When the
    // `demotionTrustedPrincipals` context names IAM principal ARNs, they are ADDED to the
    // trust policy alongside the service principals — additive, never replacing the
    // deployment binding. Unset ⇒ the default synth stays byte-for-byte service-only.
    const demotionPrincipals = trustedPrincipalsFromContext(this, 'demotionTrustedPrincipals');
    const demotionRole = new Role(this, 'DemotionRole', {
      assumedBy:
        demotionPrincipals.length > 0
          ? new CompositePrincipal(
              computePrincipals(),
              ...demotionPrincipals.map((arn) => new ArnPrincipal(arn)),
            )
          : computePrincipals(),
      description: `safe-agents ${env} - deterministic demotion role (grants writer; no model in loop; evaluator-signing reader)`,
    });

    demotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:Query', 'dynamodb:UpdateItem'],
        resources: [grantsTableArn, `${grantsTableArn}/index/*`],
      }),
    );

    demotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
        resources: [tablesKeyArn],
      }),
    );

    // Counters table: READ ONLY. The demotion runner re-derives budget_breach from
    // the durable error_budget counter (the same scoped key the PEP meters), so the
    // trigger evaluation never depends on signal delivery. GetItem only — the runner
    // must not be able to move a counter it judges by.
    demotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem'],
        resources: [countersTableArn],
      }),
    );

    // Secrets Manager: the EVALUATOR signing key only, under the */evaluator/* namespace. The
    // demotion evaluator (grants.runner: the lapse pass, then the demotion pass) DSSE-signs the
    // `demotion` and `lapse` records it appends to the ceremony ledger, so it needs a signing
    // identity of its own — and deliberately NOT the issuer's.
    //
    // The split is STRUCTURAL, and it is the point of this statement. Verification binds record
    // type to signing role: a `promotion` / `bootstrap` / `tightening` record verifies only
    // against an ISSUER key, a `demotion` / `lapse` record only against an EVALUATOR key. Because
    // the namespaces are disjoint in IAM, the deterministic evaluator — which runs with no human
    // and no model in its loop — cannot mint a record that raises authority, and the
    // human-ratified promotion path cannot mint a record that claims a trigger fired. Neither
    // signing identity can forge the other's records, and that is an IAM fact rather than a
    // convention the signing code is trusted to honor.
    //
    // Mirrors the promotion role's */issuer/* grant exactly (same actions, same namespace idiom,
    // same secrets-CMK decrypt below). Pinned by identity/secret-reader and
    // identity/evaluator-signing-split in infra/tests/conformance.ts.
    demotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resources: [
          `arn:${Aws.PARTITION}:secretsmanager:${Aws.REGION}:${Aws.ACCOUNT_ID}:secret:*/evaluator/*`,
        ],
      }),
    );

    // KMS: decrypt only on the secrets CMK (to unwrap the evaluator key), mirroring promotion.
    demotionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt'],
        resources: [secretsKeyArn],
      }),
    );

    // ── 4b. checkerRole — the standing ratifier identity (#202; OPTIONAL, context-gated OFF) ──────
    // Synthesized ONLY when the `checkerTrustedPrincipals` context names at least one IAM
    // principal ARN — the default synth stays byte-for-byte five roles. Retires the per-ceremony
    // trust-policy surgery on PromotionRole (a real privilege window whose revocation is
    // eventually consistent): the checker's separation from the maker becomes TOPOLOGICAL — a
    // standing role trusted for the named principals — instead of ceremonial.
    //
    // Honest claim (GAL §8): this guarantees TWO CREDENTIALS, one of which the proposer cannot
    // mint; it evidences who held them. It does not and cannot guarantee two humans — that is an
    // org control the platform can evidence, never enforce. The high-blast always-human-
    // ratification lock is unaffected: this is about WHICH credential ratifies, not whether a
    // human does.
    //
    // Permissions are ratify/acknowledge-shaped: grants-table read/write + tables CMK, and the
    // */issuer/* signing key + secrets CMK (the checker signs PromotionRecords and
    // acknowledgment waivers). Deliberately NO counters read (evidence assembly is the maker's
    // propose), NO */connectors/* and NO */evaluator/* (the namespace split holds three ways: the
    // checker cannot read connector credentials, the broker cannot sign promotions, and the
    // ratifier cannot sign a demotion or a lapse — that key is the demotion evaluator's alone).
    const checkerPrincipals = trustedPrincipalsFromContext(this, 'checkerTrustedPrincipals');

    if (checkerPrincipals.length > 0) {
      const checkerRole = new Role(this, 'CheckerRole', {
        assumedBy: new CompositePrincipal(
          ...checkerPrincipals.map((arn) => new ArnPrincipal(arn)),
        ),
        description: `safe-agents ${env} - standing maker-checker ratifier role (#202; grants writer; issuer-signing reader)`,
      });

      checkerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['dynamodb:GetItem', 'dynamodb:Query', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
          resources: [grantsTableArn, `${grantsTableArn}/index/*`],
        }),
      );

      checkerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
          resources: [tablesKeyArn],
        }),
      );

      // Secrets Manager: the ISSUER namespace only — ratify DSSE-signs the PromotionRecord and
      // acknowledge DSSE-signs the waiver, both with the issuer's own Ed25519 identity.
      checkerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
          resources: [
            `arn:${Aws.PARTITION}:secretsmanager:${Aws.REGION}:${Aws.ACCOUNT_ID}:secret:*/issuer/*`,
          ],
        }),
      );

      checkerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['kms:Decrypt'],
          resources: [secretsKeyArn],
        }),
      );

      // MCP admitted-tool registry (#174): admit-ratify burns the TOOLPROP# proposal, appends
      // the TOOLREC# admission record, and writes the TOOLDEF# row — ALL via conditional
      // update_item (registry.py: "writes go through update_item under a ConditionExpression").
      // Unlike CheckerRole's grants statement above, deliberately NO PutItem — the MCP store
      // surface is UpdateItem-only end-to-end, first admission and re-vet alike. The issuer
      // secretsmanager statement above already covers admission-record signing; not duplicated.
      checkerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['dynamodb:GetItem', 'dynamodb:Query', 'dynamodb:UpdateItem'],
          resources: [mcpRegistryTableArn, `${mcpRegistryTableArn}/index/*`],
        }),
      );

      publish(this, env, 'checker-role-arn', checkerRole.roleArn);
    }

    // ── 4c. makerRole — the standing proposer identity (OPTIONAL, context-gated OFF) ─────────────
    // The maker half of maker≠checker (GAL §8), completing the operator plane the CheckerRole
    // started: before this role, `commands propose` ran under a raw admin baseline — weak
    // proposedBy provenance on DSSE-signed records, and the baseline every failed assume
    // silently fell back to. Propose-shaped permissions: grants-table read (the anchored grant +
    // the store-loaded envelope) + UpdateItem (the HMAC'd PROPOSAL# item — the proposal store
    // writes via CONDITIONAL update_item, the same append idiom as the ledger; deliberately no
    // PutItem, which can overwrite unconditionally) + counters GetItem (the windowed evidence
    // reads) + tables CMK. Deliberately NO */issuer/* (the maker cannot sign a record) and NO
    // */connectors/*. First-use note: the initial cut granted PutItem instead and IAM denied
    // the live propose — the conformance row pins the corrected shape.
    //
    // The maker-cannot-mint write split (#203), closing the caveat this comment used to
    // carry. Until now UpdateItem on the shared table could technically upsert a GRANT#
    // item and the store's ConditionExpressions were the only guard — detection, not
    // prevention. The reads and the write are now SEPARATE statements so the write can be
    // key-scoped without touching the reads.
    //
    // Read-denied is NOT a stricter write-denied: the maker legitimately reads the anchored
    // grant and the store-loaded envelope to build a proposal, so GetItem/Query stay
    // unconditioned across the whole table. Folding the condition into the combined
    // statement would have broken evidence assembly, which is the shape of mistake this
    // split exists to make impossible.
    //
    // LeadingKeys constrains the PARTITION KEY, which is exactly where our key spaces
    // divide: the maker writes PROPOSAL# (grants table) and TOOLPROP# (mcp registry); the
    // checker writes GRANT#/RECORD#/TOOLDEF#/TOOLREC#. A maker attempting a GRANT# upsert
    // is now refused by IAM before the store's condition is ever evaluated.
    //
    // The sqlite half of #203 achieves the same property by a different mechanism — a
    // filesystem has no per-identity access control, so there the grant space moves to its
    // own database file on a read-only mount and the KERNEL refuses. Same property, two
    // substrates, deliberately not a shared abstraction.
    const makerPrincipals = trustedPrincipalsFromContext(this, 'makerTrustedPrincipals');
    if (makerPrincipals.length > 0) {
      const makerRole = new Role(this, 'MakerRole', {
        assumedBy: new CompositePrincipal(
          ...makerPrincipals.map((arn) => new ArnPrincipal(arn)),
        ),
        description: `safe-agents ${env} - standing maker/proposer role (propose-shaped; no issuer signing, no connectors)`,
      });

      // READ: unconditioned. Evidence assembly reads the anchored grant + envelope.
      makerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['dynamodb:GetItem', 'dynamodb:Query'],
          resources: [grantsTableArn, `${grantsTableArn}/index/*`],
        }),
      );

      // WRITE: PROPOSAL# only. ForAllValues is required — it asserts EVERY key the request
      // touches is in the allowed set, where the bare (Any) form would pass a request that
      // merely included one permitted key.
      makerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['dynamodb:UpdateItem'],
          resources: [grantsTableArn, `${grantsTableArn}/index/*`],
          conditions: {
            'ForAllValues:StringLike': { 'dynamodb:LeadingKeys': ['PROPOSAL#*'] },
          },
        }),
      );

      makerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
          resources: [tablesKeyArn],
        }),
      );

      // Counters: READ ONLY — evidence assembly reads the windowed scoped counters; the maker
      // must not be able to move a counter it builds evidence from (same rule as promotion/
      // demotion above).
      makerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['dynamodb:GetItem'],
          resources: [countersTableArn],
        }),
      );

      // MCP admitted-tool registry (#174): the admit-propose leg writes the HMAC'd TOOLPROP#
      // proposal item via a CONDITIONAL update_item (attribute_not_exists — the same append
      // idiom as the grants PROPOSAL# store; safe_agents/broker/mcp/proposals.py). GetItem +
      // Query read the current row for the propose-time re-vet check. Deliberately NO PutItem
      // — same reasoning as the grants proposal statement above: an unconditional overwrite
      // would let a maker mint a row outright.
      //
      // Split for the same #203 reason as the grants table: the re-vet READ must see the
      // current TOOLDEF# row, so reads stay unconditioned while the write is confined to
      // TOOLPROP#. A maker can no longer upsert a TOOLDEF# row and admit a tool outright,
      // which is the MCP twin of minting a grant.
      makerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['dynamodb:GetItem', 'dynamodb:Query'],
          resources: [mcpRegistryTableArn, `${mcpRegistryTableArn}/index/*`],
        }),
      );

      makerRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['dynamodb:UpdateItem'],
          resources: [mcpRegistryTableArn, `${mcpRegistryTableArn}/index/*`],
          conditions: {
            'ForAllValues:StringLike': { 'dynamodb:LeadingKeys': ['TOOLPROP#*'] },
          },
        }),
      );

      publish(this, env, 'maker-role-arn', makerRole.roleArn);
    }

    // ── 4d. auditorRole — the standing KEYED-audit identity (OPTIONAL, context-gated OFF) ────────
    // The operator-run keyed grants audit (tamper rows + signature verification) previously ran
    // as raw admin. This role is the watcher's read-only posture PLUS exactly the broker HMAC
    // key (the one secret the keyed tamper check needs) — and nothing else: no writes anywhere,
    // no */connectors/*, no */issuer/* (verify keys are PUBLIC, read from SSM). The CI watcher
    // stays keyless by design; this is the operator's full-coverage complement.
    const auditorPrincipals = trustedPrincipalsFromContext(this, 'auditorTrustedPrincipals');
    if (auditorPrincipals.length > 0) {
      const auditorRole = new Role(this, 'AuditorRole', {
        assumedBy: new CompositePrincipal(
          ...auditorPrincipals.map((arn) => new ArnPrincipal(arn)),
        ),
        description: `safe-agents ${env} - standing keyed-audit role (read-only grants + broker HMAC key + issuer/evaluator verify-keys params)`,
      });

      auditorRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['dynamodb:Scan', 'dynamodb:GetItem', 'dynamodb:Query'],
          resources: [grantsTableArn, `${grantsTableArn}/index/*`],
        }),
      );

      // Decrypt only — the auditor reads records other identities wrote; it never writes.
      auditorRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['kms:Decrypt'],
          resources: [tablesKeyArn],
        }),
      );

      // The audit resolves the grants table from the stack export (its documented
      // interface); without this the role forces the GRANTS_AUDIT_TABLE_NAME bypass —
      // found live in the sa#4 terminal proof. ListExports is unscopeable read-only
      // metadata (the API supports only '*').
      auditorRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['cloudformation:ListExports'],
          resources: ['*'],
        }),
      );

      // The broker HMAC key, env-scoped by full name — NOT a namespace wildcard: the keyed
      // tamper rows re-derive each grant's HMAC, which requires the same key the broker
      // writes with. The only secret this role can read.
      auditorRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
          resources: [
            `arn:${Aws.PARTITION}:secretsmanager:${Aws.REGION}:${Aws.ACCOUNT_ID}:secret:safe-agents/${env}/broker-hmac-key*`,
          ],
        }),
      );

      auditorRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['kms:Decrypt'],
          resources: [secretsKeyArn],
        }),
      );

      // The issuer AND evaluator PUBLIC verify keys (#194) — the same two parameters the CI
      // watcher reads. An audit must verify EVERY record type it walks, so it needs both key
      // sets: issuer keys for promotion/bootstrap/tightening, evaluator keys for demotion/lapse.
      // Reading both is not a hole in the signing split — these are PUBLIC keys, and verifying is
      // not signing. The split lives on the PRIVATE halves in Secrets Manager, which this role
      // reads neither of (its only secret is the broker HMAC key above).
      //
      // Grant both together or neither. A role resolving only one param does not audit a narrower
      // scope — it reports RECORD_ROLE_UNRESOLVED against the other role's records ("a role we
      // cannot check is never a role that passes"), so a one-sided grant reads as a dirty floor.
      auditorRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['ssm:GetParameter'],
          resources: [
            `arn:${Aws.PARTITION}:ssm:${Aws.REGION}:${Aws.ACCOUNT_ID}:parameter/safe-agents/${env}/issuer/verify-keys`,
            `arn:${Aws.PARTITION}:ssm:${Aws.REGION}:${Aws.ACCOUNT_ID}:parameter/safe-agents/${env}/evaluator/verify-keys`,
          ],
        }),
      );

      publish(this, env, 'auditor-role-arn', auditorRole.roleArn);
    }

    // ── 5. watcherRole — GitHub Actions OIDC watcher (read-only) ────────────────────────────────────
    // Assumed by the safe-agents#140 liveness watcher and the #62 grants-integrity audit running in
    // GitHub Actions, not by compute principals — it trusts the account's existing GitHub OIDC
    // provider, scoped to this repo. Read-only: Query on agent-runs, Scan/GetItem on grants, plus
    // Decrypt (no GenerateDataKey) on the tables CMK, since the watcher only ever reads records
    // other identities have already written.
    const githubOidc = OpenIdConnectProvider.fromOpenIdConnectProviderArn(
      this,
      'GithubOidcProvider',
      `arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com`,
    );

    // The OIDC subjects the two read-only watcher roles trust, named by the
    // deployer. Unset trusts nobody; see githubOidcSubjectsFromContext below.
    //
    // PASS BOTH SPELLINGS OF YOUR REPO, because GitHub emits two. The plain
    // `owner/repo` form is what older organizations send. Newer ones append the
    // immutable numeric org and repo IDs, so the SAME workflow presents
    // `repo:owner@<org-id>/repo@<repo-id>:ref:...`. That is not a custom
    // sub-claim template; it is GitHub's default for recent orgs.
    //
    // This was found the hard way: after an org transfer the name-form pattern
    // was updated, deployed and verified as correct in IAM, and the grants audit
    // STILL failed `sts:AssumeRoleWithWebIdentity`. The trust policy was right
    // about a subject GitHub was not sending. Only CloudTrail's
    // `userIdentity.principalId` showed the real claim. Accepting both forms is
    // no weaker than accepting one, since each pins the same org and repo, and
    // the ID form is RENAME-proof: the numbers outlive any repo or org rename.
    const githubSubjects = githubOidcSubjectsFromContext(this);

    const watcherRole = new Role(this, 'WatcherRole', {
      assumedBy: new OpenIdConnectPrincipal(githubOidc, {
        StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' },
        StringLike: { 'token.actions.githubusercontent.com:sub': githubSubjects },
      }),
      description: `safe-agents ${env} - GitHub Actions OIDC watcher (read-only agent-runs + grants audit + issuer/evaluator verify-keys + CMK decrypt)`,
    });

    watcherRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:Query'],
        resources: [agentRunsTableArn],
      }),
    );

    // DynamoDB — grants table: READ ONLY (Scan for the full-table audit sweep, GetItem for spot
    // reads). The #62 grants-integrity audit counts in-force grants against the ceremony ledger,
    // so the auditing identity must be structurally unable to write the table it judges — no
    // Put/Update/Delete, same rule as the demotion runner's counters read. It also deliberately
    // does NOT get the broker HMAC key (the secrets namespace split): CI runs the KEYLESS audit
    // and skips tamper rows; the keyed tamper audit is operator-run.
    watcherRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:Scan', 'dynamodb:GetItem'],
        resources: [grantsTableArn],
      }),
    );

    watcherRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt'],
        resources: [tablesKeyArn],
      }),
    );

    // SSM — the issuer AND evaluator verify-keys parameters (#194): each signer's PUBLIC Ed25519
    // keys by key_id, so the grants audit can run RECORD_SIGNATURE_VERIFIES read-only over every
    // record type in the ledger (issuer keys verify promotion/bootstrap/tightening, evaluator
    // keys verify demotion/lapse). Deliberately Parameter Store, not Secrets Manager: verify keys
    // are public material, and the watcher keeps reading NO Secrets Manager at all (the
    // namespace-split doctrine — the */issuer/* PRIVATE signing key stays promotion-side and the
    // */evaluator/* one demotion-side). An auditor that can verify both and sign neither is
    // exactly the posture we want — and both params are granted together deliberately, since a
    // role holding one resolves the other's records to RECORD_ROLE_UNRESOLVED rather than
    // skipping them.
    watcherRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['ssm:GetParameter'],
        resources: [
          `arn:${Aws.PARTITION}:ssm:${Aws.REGION}:${Aws.ACCOUNT_ID}:parameter/safe-agents/${env}/issuer/verify-keys`,
          `arn:${Aws.PARTITION}:ssm:${Aws.REGION}:${Aws.ACCOUNT_ID}:parameter/safe-agents/${env}/evaluator/verify-keys`,
        ],
      }),
    );

    // ── 6. campaignWatcherRole — GitHub Actions OIDC campaign watchdog (read-only) ──────────────────
    // Assumed by the sa#161 scheduled campaign-watchdog GitHub Actions runner — the SAME OIDC trust
    // idiom as watcherRole above (this account's GitHub OIDC provider, scoped to the subjects the
    // `githubOidcSubjects` context names), unconditional like watcherRole (no operator-trust gate). A
    // separate role rather than widening watcherRole: its read surface is different (it correlates
    // the channels airlock's audit objects and tails the broker/airlock CloudWatch Logs, never the
    // grants table or agent-runs), and each watcher stays independently rotatable/scopeable.
    // Structurally unable to write anything: no dynamodb:*, no secretsmanager:*, no kms:*, no
    // logs:PutLogEvents/CreateLogGroup — the campaign watchdog observes, it never mutates.
    const campaignWatcherRole = new Role(this, 'CampaignWatcherRole', {
      assumedBy: new OpenIdConnectPrincipal(githubOidc, {
        StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' },
        StringLike: { 'token.actions.githubusercontent.com:sub': githubSubjects },
      }),
      description: `safe-agents ${env} - GitHub Actions OIDC campaign watchdog (read-only channels audit objects + broker/airlock logs)`,
    });

    // S3 — audit bucket: GetObject scoped to exactly the two channels audit prefixes the watchdog
    // correlates (channels/SCREENING.md's DropRecord/ScreenRecord sinks, written under
    // channels/drops/ and channels/verdicts/ — see safe_agents/channels/stores.py). ListBucket is
    // scoped to the SAME two prefixes via an s3:prefix condition, never the whole bucket: the audit
    // hash-chain records and the PromotionRecord ledger live outside these prefixes and stay
    // unreadable to this role.
    campaignWatcherRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:GetObject'],
        resources: [`${auditBucketArn}/channels/drops/*`, `${auditBucketArn}/channels/verdicts/*`],
      }),
    );
    campaignWatcherRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:ListBucket'],
        resources: [auditBucketArn],
        conditions: {
          StringLike: { 's3:prefix': ['channels/drops/*', 'channels/verdicts/*'] },
        },
      }),
    );

    // CloudWatch Logs — read-only, scoped to exactly the two log groups the watchdog correlates
    // against: the broker service's decision log and the airlock's structured events (the sa#153
    // handler_error/screen_error silent-failure signals) — never a `/safe-agents/${env}/*`
    // wildcard. FilterLogEvents is the primary cross-stream correlation call; DescribeLogStreams +
    // GetLogEvents are the read-only companions needed to page a specific stream.
    campaignWatcherRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['logs:FilterLogEvents', 'logs:DescribeLogStreams', 'logs:GetLogEvents'],
        resources: [
          `arn:${Aws.PARTITION}:logs:${Aws.REGION}:${Aws.ACCOUNT_ID}:log-group:/safe-agents/${env}/broker:*`,
          `arn:${Aws.PARTITION}:logs:${Aws.REGION}:${Aws.ACCOUNT_ID}:log-group:/safe-agents/${env}/channels-airlock:*`,
        ],
      }),
    );
    // No addToPolicy calls beyond the three above.

    // ── Cross-stack outputs ───────────────────────────────────────────────────────────────────────
    // Published as both CloudFormation exports and SSM parameters (naming.ts convention).
    // Arm stacks and the broker stack import these ARNs to configure task / instance roles.
    publish(this, env, 'agent-role-arn',           agentRole.roleArn);
    publish(this, env, 'broker-role-arn',          brokerRole.roleArn);
    publish(this, env, 'promotion-role-arn',       promotionRole.roleArn);
    publish(this, env, 'demotion-role-arn',        demotionRole.roleArn);
    publish(this, env, 'watcher-role-arn',         watcherRole.roleArn);
    publish(this, env, 'campaign-watcher-role-arn', campaignWatcherRole.roleArn);
  }
}

/**
 * The GitHub Actions OIDC subject patterns the read-only watcher roles trust, from the
 * `githubOidcSubjects` context (string, comma-separated string, or string[]).
 *
 * Unset is deliberately NOT "trust any repository". It yields a sentinel that no GitHub token
 * can present, so both roles still synthesize (their ARNs are exported, and the conformance
 * suite asserts those exports) while being assumable by nobody until a deployer names their own
 * repository. The sentinel names the fix, so an operator reading the trust policy in the console
 * sees what to pass rather than a plausible-looking pattern that silently matches nothing.
 */
const GITHUB_OIDC_SUBJECT_UNSET = 'repo:UNSET-pass-the-githubOidcSubjects-context:*';

function githubOidcSubjectsFromContext(scope: Construct): string[] {
  const ctx = scope.node.tryGetContext('githubOidcSubjects') as string | string[] | undefined;
  const subjects = (Array.isArray(ctx) ? ctx : (ctx ?? '').split(','))
    .map((subject) => subject.trim())
    .filter((subject) => subject.length > 0);
  return subjects.length > 0 ? subjects : [GITHUB_OIDC_SUBJECT_UNSET];
}

/**
 * Parse a `<x>TrustedPrincipals` context value (string, comma-separated string, or string[])
 * into a clean list of IAM principal ARNs. The shared idiom behind the operator-assumability
 * gates (#202 checkerTrustedPrincipals, #192 demotionTrustedPrincipals): unset or empty means
 * the gate is OFF and the default synth is unchanged.
 */
function trustedPrincipalsFromContext(scope: Construct, key: string): string[] {
  const ctx = scope.node.tryGetContext(key) as string | string[] | undefined;
  return (Array.isArray(ctx) ? ctx : (ctx ?? '').split(','))
    .map((arn) => arn.trim())
    .filter((arn) => arn.length > 0);
}
