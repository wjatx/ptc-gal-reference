import { Duration, Stack } from 'aws-cdk-lib';
import { AttributeType, BillingMode, Table, TableEncryption } from 'aws-cdk-lib/aws-dynamodb';
import { Key } from 'aws-cdk-lib/aws-kms';
import { BlockPublicAccess, Bucket, BucketEncryption, ObjectLockRetention } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { isEphemeral, removalPolicyFor } from './environment';
import { FoundationStackProps } from './foundation-props';
import { publish, resourceName } from './naming';

/**
 * StateStack — durable state that must survive any ephemeral compute arm and exist before the
 * broker runs: the four DynamoDB tables (grants / counters / intents / agent-runs), the S3
 * Object Lock (WORM) audit bucket, and the customer-managed KMS keys.
 *
 * Implements sa#14. IdentityStack (#15) depends on this stack's exported ARNs to scope its role
 * policies; nothing downstream runs until this stack is deployed.
 */
export class StateStack extends Stack {
  constructor(scope: Construct, id: string, props: FoundationStackProps) {
    super(scope, id, props);

    const env = props.environment;

    // ── KMS ──────────────────────────────────────────────────────────────────────────────────────
    // Four CMKs so each surface (tables / audit / ledger / secrets) has independent key policy and
    // rotation schedule. Rotation is annual on AWS-managed schedule; enableKeyRotation opts into it.

    const tablesKey = new Key(this, 'TablesKey', {
      description: `safe-agents ${env} - DynamoDB tables CMK`,
      enableKeyRotation: true,
      removalPolicy: removalPolicyFor(env),
    });

    const auditKey = new Key(this, 'AuditKey', {
      description: `safe-agents ${env} - S3 audit bucket CMK`,
      enableKeyRotation: true,
      removalPolicy: removalPolicyFor(env),
    });

    // The ledger bucket gets its own CMK (not auditKey) for the same per-surface reason: the
    // ledger is a distinct consumer surface — the broker holds Encrypt on it for agent-ledger
    // appends — and reusing auditKey would couple that surface into the audit chain's key policy.
    const ledgerKey = new Key(this, 'LedgerKey', {
      description: `safe-agents ${env} - S3 ledger bucket CMK`,
      enableKeyRotation: true,
      removalPolicy: removalPolicyFor(env),
    });

    // The Secrets Manager secret store itself is built in IdentityStack (#15), but its CMK is
    // provisioned here so StateStack owns the full key estate and IdentityStack can import the ARN.
    const secretsKey = new Key(this, 'SecretsKey', {
      description: `safe-agents ${env} - Secrets Manager connector credentials CMK`,
      enableKeyRotation: true,
      removalPolicy: removalPolicyFor(env),
    });

    // ── DynamoDB ─────────────────────────────────────────────────────────────────────────────────
    // All tables: on-demand billing, PITR, customer-managed encryption, RETAIN.
    //
    // Key schema: the broker uses a single-table design — every item is keyed by a generic
    // (pk, sk) pair with a type prefix (GRANT#/COUNTER#/IDEM#/LEDGER#/INTENT#). This MUST match
    // what broker/{grants,enforcement,approval}/store.py actually write (verified against the
    // local arm + 444 broker tests); the earlier per-domain stubs (principal/actionClass,
    // principal/period, id) were a SCHEMAS.md design guess the implementation never followed.
    //
    //   grants:   pk = "GRANT#<principal>"  sk = "CLASS#<actionClass>"
    //   counters: pk = "COUNTER#|IDEM#|LEDGER#<key>"  sk = "v0"
    //   intents:  pk = "INTENT#<id>"  sk = "v0"  (+ a `ttl` attribute for auto-expiry)
    //   agent-runs: PK=agentId, SK=runId — the AGENT's run record (not a broker store), so it
    //               keeps its own domain schema (RUNNER-CONTRACT element 5).
    //   channel-dedupe: pk = dedupe_pk (+ a `ttl` attribute for dedupe-window auto-expiry) — the
    //               channels airlock's idempotency store (sa#152). A standalone single-key table,
    //               not a broker single-table item; owned here as shared substrate, consumed by
    //               ChannelsStack. No sort key: a dedupe claim is a single point read + put.
    //   mcp-registry: the #174 MCP admitted-tool registry (broker/MCP-HOST.md). Single-table,
    //               same generic (pk, sk) shape as grants, holding three item-key prefixes:
    //               `TOOLDEF#<server_id>#<tool_name>` (the admitted row, sk="ROW"),
    //               `TOOLREC#<server_id>#<tool_name>` (the append-only admission ledger, sk=ts),
    //               and `TOOLPROP#…` (the single-shot admit-propose proposal — see
    //               safe_agents/broker/mcp/{registry,signing,proposals}.py). Mirrors "the broker
    //               cannot write grants": the admission ceremony
    //               (safe_agents/broker/mcp/commands.py) is this table's ONLY writer — the broker
    //               only ever reads it at MCP discovery time.

    const grantsTable = new Table(this, 'GrantsTable', {
      tableName: resourceName(env, 'grants'),
      partitionKey: { name: 'pk', type: AttributeType.STRING },
      sortKey: { name: 'sk', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tablesKey,
      removalPolicy: removalPolicyFor(env),
    });

    const mcpRegistryTable = new Table(this, 'McpRegistryTable', {
      tableName: resourceName(env, 'mcp-registry'),
      partitionKey: { name: 'pk', type: AttributeType.STRING },
      sortKey: { name: 'sk', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tablesKey,
      removalPolicy: removalPolicyFor(env),
    });

    const countersTable = new Table(this, 'CountersTable', {
      tableName: resourceName(env, 'counters'),
      partitionKey: { name: 'pk', type: AttributeType.STRING },
      sortKey: { name: 'sk', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tablesKey,
      removalPolicy: removalPolicyFor(env),
    });

    const intentsTable = new Table(this, 'IntentsTable', {
      tableName: resourceName(env, 'intents'),
      partitionKey: { name: 'pk', type: AttributeType.STRING },
      sortKey: { name: 'sk', type: AttributeType.STRING },
      timeToLiveAttribute: 'ttl', // broker DynamoIntentStore sets `ttl` for intent auto-expiry
      billingMode: BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tablesKey,
      removalPolicy: removalPolicyFor(env),
    });

    const agentRunsTable = new Table(this, 'AgentRunsTable', {
      tableName: resourceName(env, 'agent-runs'),
      partitionKey: { name: 'agentId', type: AttributeType.STRING },
      sortKey: { name: 'runId', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tablesKey,
      removalPolicy: removalPolicyFor(env),
    });

    const channelDedupeTable = new Table(this, 'ChannelDedupeTable', {
      tableName: resourceName(env, 'channel-dedupe'),
      partitionKey: { name: 'dedupe_pk', type: AttributeType.STRING },
      timeToLiveAttribute: 'ttl', // channels airlock sets `ttl` for dedupe-window auto-expiry
      billingMode: BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      encryption: TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tablesKey,
      removalPolicy: removalPolicyFor(env),
    });

    // ── S3 Audit Bucket ──────────────────────────────────────────────────────────────────────────
    // Object Lock in GOVERNANCE mode provides WORM: objects cannot be deleted or overwritten during
    // the retention window. GOVERNANCE (vs COMPLIANCE) preserves an escape hatch for admins with
    // s3:BypassGovernanceRetention while still blocking the broker/agent roles entirely.
    //
    // Retention: 7 years (~2557 days) is the default for security audit logs under common compliance
    // frameworks; adjust per deployment requirements.
    //
    // Durable environments keep a default WORM retention; the ephemeral (development) environment
    // keeps Object Lock *enabled* (it cannot be turned on after creation) but sets no default
    // retention and auto-deletes objects on teardown, so a dev env is hands-off-redeployable without
    // anything being locked. The IAM constraint ("no agent or broker role can delete audit objects")
    // is enforced by role boundaries in IdentityStack (#15) regardless of environment.

    const auditBucket = new Bucket(this, 'AuditBucket', {
      bucketName: resourceName(env, 'audit'),
      objectLockEnabled: true,
      objectLockDefaultRetention: isEphemeral(env)
        ? undefined
        : ObjectLockRetention.governance(Duration.days(2557)), // ~7 years in durable environments
      encryption: BucketEncryption.KMS,
      encryptionKey: auditKey,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      autoDeleteObjects: isEphemeral(env), // dev: empty the bucket on destroy for hands-off teardown
      removalPolicy: removalPolicyFor(env),
    });

    // ── S3 Ledger Bucket ─────────────────────────────────────────────────────────────────────────
    // The durable sink for the agent's briefs + ledger deltas via the `ledger.append` connector
    // (sa#131). Explicitly NO Object Lock, unlike AuditBucket: this is the agent's ledger copy,
    // not the tamper-evident audit chain — append-only ("never delete a prediction") is enforced
    // via brokerRole IAM in IdentityStack (s3:PutObject only, no Delete*, no overwrite-relevant
    // perms), not WORM. Versioned so even a same-key rewrite preserves the prior object rather
    // than replacing it. Same encryption/public-access/SSL floor as AuditBucket; same
    // environment polarity (dev auto-deletes + DESTROYs for hands-off teardown, durable
    // environments RETAIN).
    const ledgerBucket = new Bucket(this, 'LedgerBucket', {
      bucketName: resourceName(env, 'ledger'),
      versioned: true,
      encryption: BucketEncryption.KMS,
      encryptionKey: ledgerKey,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      autoDeleteObjects: isEphemeral(env), // dev: empty the bucket on destroy for hands-off teardown
      removalPolicy: removalPolicyFor(env),
    });

    // ── S3 Deploy Bucket ───────────────────────────────────────────────────────────────────────────
    // Holds the agent code bundles + platform bundles (contract, rhel-bootstrap) that boxes pull at
    // boot via their instance role (s3:GetObject on agents/<name>/* and platform/*). It is shared
    // floor infrastructure — every arm reads from it — so it belongs in the State layer, not in any
    // per-agent or per-bake teardown. (Before this it had no owning stack: bake_teardown deleted it
    // but nothing created it, so it vanished between sessions and broke the next provision at boot.)
    //
    // SSE-S3 (not KMS): the box only needs s3:GetObject, so plain S3-managed encryption avoids
    // granting every agentRole kms:Decrypt on a shared key. Dev auto-deletes objects on destroy so
    // the floor stays hands-off-redeployable.
    const deployBucket = new Bucket(this, 'DeployBucket', {
      bucketName: resourceName(env, 'deploy'),
      encryption: BucketEncryption.S3_MANAGED,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      autoDeleteObjects: isEphemeral(env), // dev: empty the bucket on destroy for hands-off teardown
      removalPolicy: removalPolicyFor(env),
    });

    // ── Cross-stack outputs ───────────────────────────────────────────────────────────────────────
    // Published as both CloudFormation exports and SSM parameters (naming.ts convention).
    // IdentityStack (#15) imports the KMS and resource ARNs to scope role policies precisely.
    // Broker and observability stacks consume the table/bucket names at runtime via SSM.

    // KMS key ARNs
    publish(this, env, 'tables-key-arn', tablesKey.keyArn);
    publish(this, env, 'audit-key-arn', auditKey.keyArn);
    publish(this, env, 'ledger-key-arn', ledgerKey.keyArn);
    publish(this, env, 'secrets-key-arn', secretsKey.keyArn);

    // Table names + ARNs
    publish(this, env, 'grants-table-name', grantsTable.tableName);
    publish(this, env, 'grants-table-arn', grantsTable.tableArn);
    publish(this, env, 'counters-table-name', countersTable.tableName);
    publish(this, env, 'counters-table-arn', countersTable.tableArn);
    publish(this, env, 'intents-table-name', intentsTable.tableName);
    publish(this, env, 'intents-table-arn', intentsTable.tableArn);
    publish(this, env, 'agent-runs-table-name', agentRunsTable.tableName);
    publish(this, env, 'agent-runs-table-arn', agentRunsTable.tableArn);
    publish(this, env, 'channel-dedupe-table-name', channelDedupeTable.tableName);
    publish(this, env, 'channel-dedupe-table-arn', channelDedupeTable.tableArn);
    publish(this, env, 'mcp-registry-table-name', mcpRegistryTable.tableName);
    publish(this, env, 'mcp-registry-table-arn', mcpRegistryTable.tableArn);

    // Audit bucket name + ARN
    publish(this, env, 'audit-bucket-name', auditBucket.bucketName);
    publish(this, env, 'audit-bucket-arn', auditBucket.bucketArn);

    // Ledger bucket name + ARN (IdentityStack scopes brokerRole s3:PutObject to this)
    publish(this, env, 'ledger-bucket-name', ledgerBucket.bucketName);
    publish(this, env, 'ledger-bucket-arn', ledgerBucket.bucketArn);

    // Deploy bucket name + ARN (arms scope instance-role s3:GetObject to this; the bundle
    // uploader writes to it)
    publish(this, env, 'deploy-bucket-name', deployBucket.bucketName);
    publish(this, env, 'deploy-bucket-arn', deployBucket.bucketArn);
  }
}
