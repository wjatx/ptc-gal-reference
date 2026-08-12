import { Aws, Duration, Stack } from 'aws-cdk-lib';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import { SnsAction } from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import { Effect, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import { FilterPattern, LogGroup, MetricFilter, RetentionDays } from 'aws-cdk-lib/aws-logs';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import { Environment, isEphemeral, removalPolicyFor } from './environment';
import { FoundationStackProps } from './foundation-props';
import { importValue, publish, resourceName } from './naming';

/**
 * ChannelsStack — the inbound airlock for the channels contracts (sa#152, epic sa#8): a single
 * `POST /inbound` HTTP endpoint that fronts a Lambda running the gate pipeline
 * (`safe_agents.channels.airlock.handler.handler`). An accepted EventTrigger is handed to the
 * broker path via SQS; a refused/dropped one is written as a DropRecord to the audit bucket. The
 * agent never sees a raw inbound message — the airlock is the one place untrusted external input
 * crosses into the platform.
 *
 * It is a COMPONENT stack, not a foundation layer: it imports the durable substrate (the dedupe
 * table, the audit bucket + CMK, the tables CMK) from StateStack's exports and owns everything
 * transient itself — the airlock ECR repo, the accepted-event queue, the webhook shared secret,
 * and its OWN least-privilege execution role. It deliberately imports NOTHING from Network (the
 * Lambda runs outside the VPC — no `vpc` prop) and NOTHING from Identity (the broker's boundary
 * roles are for the broker; the airlock's authority is defined here and scoped to exactly the
 * resources this stack touches).
 *
 * Two-phase bringup (context flag `channelsDeployFunction`, default true): a DockerImageFunction
 * cannot be created before its image exists, so the first deploy runs with the flag false to lay
 * down the repo + queue + secret (skipping the role/function/API), the airlock image is pushed,
 * then a second deploy with the flag true adds the function and the API. This mirrors the broker's
 * `brokerDesiredCount=0` first-deploy analog in ComputeStack.
 */
export class ChannelsStack extends Stack {
  constructor(scope: Construct, id: string, props: FoundationStackProps) {
    super(scope, id, props);

    const env = props.environment;

    // ── Context flags ─────────────────────────────────────────────────────────────────────────────
    // -c reuseChannelsArtifacts=true — reference the ECR repo + log group by name instead of
    // creating them. Needed when RE-creating this stack in a durable (RETAIN-polarity) environment,
    // where those artifacts survive stack deletion by design and a fresh CREATE would collide on
    // their names. Mirrors ComputeStack's reuseComputeArtifacts. Off for a clean-account bringup.
    const reuseArtifactsCtx = this.node.tryGetContext('reuseChannelsArtifacts');
    const reuseArtifacts = reuseArtifactsCtx === true || reuseArtifactsCtx === 'true';

    // -c channelsDeployFunction=false — the two-phase-bringup switch (see the class doc). Default
    // TRUE (undefined means deploy). When false, only repo + queue + secret are synthesized.
    const deployFunctionCtx = this.node.tryGetContext('channelsDeployFunction');
    const deployFunction =
      deployFunctionCtx === undefined
        ? true
        : deployFunctionCtx === true || deployFunctionCtx === 'true';

    // -c channelsAirlockImageTag=<tag|digest> — the image the function runs; default `latest`.
    const imageTag =
      (this.node.tryGetContext('channelsAirlockImageTag') as string | undefined) ?? 'latest';

    // -c channelsManifestPath=/app/agents/channels-manifest.yaml — the in-image path of the
    // CONSUMER's channels manifest (the consumer-image-layer pattern, same shape as ComputeStack's
    // brokerManifestPath). Unset, the base image bakes nothing in. Never bake a consumer path here.
    const manifestPath = this.node.tryGetContext('channelsManifestPath') as string | undefined;

    // -c channelsScreenModelArns=arn1,arn2 — set ONLY when the consumer enables the reference
    // classifier screen: the model/inference-profile ARNs the airlock may invoke. Absent (the
    // shipped default — the screen is OFF), the role carries no bedrock permission at all: an OFF
    // control's authority must not sit in the role. A cross-region inference profile needs the
    // profile ARN plus the foundation-model ARN in every region it may route to.
    const screenModelArnsCtx = this.node.tryGetContext('channelsScreenModelArns') as
      | string
      | undefined;
    const screenModelArns = (screenModelArnsCtx ?? '')
      .split(',')
      .map((arn) => arn.trim())
      .filter(Boolean);

    // -c channelsVerifyKeysArn=<secretArn> — OPTIONAL pointer to an operator-created Secrets
    // Manager secret holding sender-verification public keys (value JSON `{key_id:
    // public_key_pem}`, channels/SIGNING.md). The stack POINTS at it, never creates it — a Layer-3
    // config pointer to Layer-4 material per docs/config-provenance.md. Absent (the shipped
    // default), the airlock gets no BROKER_VERIFY_KEYS_SECRET_ARN and unsigned peers pass
    // (`safe_agents/channels/keys.py::resolve_verification_keys` returns None on an unset ARN).
    const verifyKeysArn = this.node.tryGetContext('channelsVerifyKeysArn') as string | undefined;

    // -c channelsDrainImageTag=<tag|digest> — the drain worker image (sa#155). This tag IS the
    // drain's phase gate: unset (the default), the drain Lambda + event source are not created and
    // the stack synthesizes exactly as before — only the drain ECR repo exists so the image can be
    // pushed before the tag is first supplied (the airlock's two-phase-bringup pattern, with the
    // tag itself as the switch).
    const drainImageTag = this.node.tryGetContext('channelsDrainImageTag') as string | undefined;

    // -c channelsDrainManifestPath / -c channelsDrainReceiver — the drain's image-baked env
    // contract (channels/DRAIN.md D6): the in-image AgentManifest path and the dotted receiver
    // provider path. Both are REQUIRED whenever the image tag is set — a drain without them fails
    // every invocation loudly at runtime, so fail the synth instead.
    const drainManifestPath = this.node.tryGetContext('channelsDrainManifestPath') as
      | string
      | undefined;
    const drainReceiver = this.node.tryGetContext('channelsDrainReceiver') as string | undefined;
    if (drainImageTag && (!drainManifestPath || !drainReceiver)) {
      throw new Error(
        'channelsDrainImageTag is set but channelsDrainManifestPath and/or channelsDrainReceiver ' +
          'is missing — the drain Lambda requires both (channels/DRAIN.md D6). ' +
          'Pass -c channelsDrainManifestPath=<in-image path> -c channelsDrainReceiver=<pkg.module:ClassName>.',
      );
    }
    // The drain lives on the phase-2 path (it is created after the airlock's early return below),
    // so requesting it while channelsDeployFunction=false would pass the D6 guard above and then
    // silently deploy no drain at all. Fail the synth instead of shipping a no-op.
    if (drainImageTag && !deployFunction) {
      throw new Error(
        'channelsDrainImageTag is set but channelsDeployFunction=false — the drain worker is ' +
          'part of the phase-2 deploy and would be silently skipped. Re-run with ' +
          'channelsDeployFunction unset (or true), or drop channelsDrainImageTag for phase 1.',
      );
    }

    // -c channelsMissileerDrainImageTag=<tag|digest> — the SECOND drain consumer (sa#166): its own
    // queue, own log group, own audit-chain prefix, so two consumers never compete on one queue or
    // fork one hash chain. Same phase-gate posture as channelsDrainImageTag: unset (the default),
    // neither the missileer queue nor its drain are created.
    const missileerDrainImageTag = this.node.tryGetContext('channelsMissileerDrainImageTag') as
      | string
      | undefined;
    const missileerDrainManifestPath = this.node.tryGetContext(
      'channelsMissileerDrainManifestPath',
    ) as string | undefined;
    const missileerDrainReceiver = this.node.tryGetContext('channelsMissileerDrainReceiver') as
      | string
      | undefined;
    if (missileerDrainImageTag && (!missileerDrainManifestPath || !missileerDrainReceiver)) {
      throw new Error(
        'channelsMissileerDrainImageTag is set but channelsMissileerDrainManifestPath and/or ' +
          'channelsMissileerDrainReceiver is missing — the drain Lambda requires both ' +
          '(channels/DRAIN.md D6). Pass -c channelsMissileerDrainManifestPath=<in-image path> ' +
          '-c channelsMissileerDrainReceiver=<pkg.module:ClassName>.',
      );
    }
    if (missileerDrainImageTag && !deployFunction) {
      throw new Error(
        'channelsMissileerDrainImageTag is set but channelsDeployFunction=false — the drain ' +
          'worker is part of the phase-2 deploy and would be silently skipped. Re-run with ' +
          'channelsDeployFunction unset (or true), or drop channelsMissileerDrainImageTag for phase 1.',
      );
    }

    // ── Import StateStack substrate ───────────────────────────────────────────────────────────────
    // Every resource ARN comes from a StateStack export so the role policies below are exactly
    // scoped — no wildcards, no account-level assumptions.
    const tablesKeyArn = importValue(env, 'tables-key-arn');
    const auditBucketName = importValue(env, 'audit-bucket-name');
    const auditBucketArn = importValue(env, 'audit-bucket-arn');
    const auditKeyArn = importValue(env, 'audit-key-arn');
    const dedupeTableName = importValue(env, 'channel-dedupe-table-name');
    const dedupeTableArn = importValue(env, 'channel-dedupe-table-arn');
    // Drain-only substrate (the broker runtime's Dynamo/secrets backends).
    const grantsTableName = importValue(env, 'grants-table-name');
    const grantsTableArn = importValue(env, 'grants-table-arn');
    const countersTableName = importValue(env, 'counters-table-name');
    const countersTableArn = importValue(env, 'counters-table-arn');
    const intentsTableName = importValue(env, 'intents-table-name');
    const intentsTableArn = importValue(env, 'intents-table-arn');
    const secretsKeyArn = importValue(env, 'secrets-key-arn');
    const ledgerBucketArn = importValue(env, 'ledger-bucket-arn');
    const ledgerKeyArn = importValue(env, 'ledger-key-arn');

    // ── ECR repository (airlock image) ────────────────────────────────────────────────────────────
    // The airlock container image is pushed here; the function pulls `channelsAirlockImageTag`.
    // Same lifecycle/removal pattern as ComputeStack's repos. Created in both bringup phases.
    const repo = reuseArtifacts
      ? ecr.Repository.fromRepositoryName(this, 'AirlockRepo', resourceName(env, 'airlock'))
      : new ecr.Repository(this, 'AirlockRepo', {
          repositoryName: resourceName(env, 'airlock'),
          imageScanOnPush: true,
          removalPolicy: removalPolicyFor(env),
          ...(isEphemeral(env) && { emptyOnDelete: true }),
          lifecycleRules: [{ maxImageCount: 10, description: 'Keep the last 10 airlock images' }],
        });

    // ── ECR repository (drain worker image, sa#155) ───────────────────────────────────────────────
    // Created unconditionally (even while channelsDrainImageTag is unset) so the drain image can be
    // pushed BEFORE the tag is first supplied — the same repo-before-function bringup order as the
    // airlock's.
    const drainRepo = reuseArtifacts
      ? ecr.Repository.fromRepositoryName(this, 'DrainRepo', resourceName(env, 'channels-drain'))
      : new ecr.Repository(this, 'DrainRepo', {
          repositoryName: resourceName(env, 'channels-drain'),
          imageScanOnPush: true,
          removalPolicy: removalPolicyFor(env),
          ...(isEphemeral(env) && { emptyOnDelete: true }),
          lifecycleRules: [{ maxImageCount: 10, description: 'Keep the last 10 drain images' }],
        });

    // ── SQS accepted-event queue ──────────────────────────────────────────────────────────────────
    // The airlock enqueues an accepted EventTrigger here; the broker path drains it. SSE-SQS
    // (AWS-managed key — the payload is post-screening platform data, not connector credentials, so
    // a CMK is not warranted). enforceSSL matches the State buckets' transport floor. No DLQ: a
    // failed downstream drain is a broker-side concern, and 4 days of retention is ample headroom.
    const acceptedQueue = new sqs.Queue(this, 'AcceptedQueue', {
      queueName: resourceName(env, 'channel-accepted'),
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: Duration.days(4),
      enforceSSL: true,
      // Lambda event-source mappings require queue visibility >= the consumer's timeout — the
      // drain function below runs at 60 s, and AWS guidance is 6x the function timeout. Without
      // this the drain's event source mapping is rejected at deploy (default visibility is 30 s).
      visibilityTimeout: Duration.seconds(360),
    });

    // ── SQS accepted-event queue — missileer drain (sa#166) ──────────────────────────────────────────
    // A SECOND consumer's own queue so it never competes with webhook-peer's `acceptedQueue` — the
    // drain's S3 audit sink resumes a hash chain by prefix, and two drains sharing one queue would
    // interleave messages from both consumers onto whichever runtime happened to poll them. Created
    // ONLY when channelsMissileerDrainImageTag is set (the same phased-bringup gate the drain itself
    // uses below). Same encryption/retention/visibility rationale as `acceptedQueue`.
    const missileerAcceptedQueue = missileerDrainImageTag
      ? new sqs.Queue(this, 'MissileerAcceptedQueue', {
          queueName: resourceName(env, 'channel-accepted-missileer'),
          encryption: sqs.QueueEncryption.SQS_MANAGED,
          retentionPeriod: Duration.days(4),
          enforceSSL: true,
          visibilityTimeout: Duration.seconds(360),
        })
      : undefined;
    if (missileerAcceptedQueue) {
      publish(this, env, 'channel-accepted-missileer-queue-url', missileerAcceptedQueue.queueUrl);
      publish(this, env, 'channel-accepted-missileer-queue-arn', missileerAcceptedQueue.queueArn);
    }

    // ── Webhook shared secret ─────────────────────────────────────────────────────────────────────
    // The inbound shared-secret header the airlock verifies (auth is in-Lambda per the channels
    // contracts — the HTTP API carries no authorizer). A random placeholder is generated so the
    // secret exists post-deploy; the REAL token is seeded out of band and overwrites it.
    const webhookSecret = new Secret(this, 'WebhookSecret', {
      secretName: resourceName(env, 'channels-webhook'),
      description: `safe-agents ${env} - channels inbound webhook shared secret (seeded out of band)`,
      removalPolicy: removalPolicyFor(env),
      generateSecretString: {
        passwordLength: 32,
        excludePunctuation: true,
      },
    });

    // ── Cross-stack outputs (always published) ────────────────────────────────────────────────────
    publish(this, env, 'channel-accepted-queue-url', acceptedQueue.queueUrl);
    publish(this, env, 'channel-accepted-queue-arn', acceptedQueue.queueArn);
    publish(this, env, 'airlock-ecr-uri', repo.repositoryUri);
    publish(this, env, 'drain-ecr-uri', drainRepo.repositoryUri);
    publish(this, env, 'channels-webhook-secret-arn', webhookSecret.secretArn);

    // Phase-1 bringup (channelsDeployFunction=false) stops here: repo + queue + secret exist, the
    // image can be pushed, and a second deploy with the flag on adds the role/function/API below.
    if (!deployFunction) {
      return;
    }

    // ── Log group (explicit, so logs perms scope to it) ───────────────────────────────────────────
    // Created explicitly and handed to the function so the execution role needs NO logs:CreateLogGroup
    // (which forces a wildcard resource) — only CreateLogStream + PutLogEvents on this one group.
    const logGroupName = `/safe-agents/${env}/channels-airlock`;
    const logGroup = reuseArtifacts
      ? LogGroup.fromLogGroupName(this, 'AirlockLogs', logGroupName)
      : new LogGroup(this, 'AirlockLogs', {
          logGroupName,
          retention: RetentionDays.TWO_WEEKS,
          removalPolicy: removalPolicyFor(env),
        });

    // ── Silent-failure alarms (sa#153) ────────────────────────────────────────────────────────────
    // The airlock answers 200-always by design, so its two failure modes are invisible to callers:
    // `handler_error` (an unexpected exception — the message dropped hard) and `screen_error` (the
    // classifier screen failing closed — 100% drop when persistent). Metric filters lift both
    // structured-log events into SafeAgents/Channels and alarm on the FIRST occurrence in any
    // 5-minute window. The Lambda log formatter prefixes level/timestamp before the JSON payload,
    // so these are TEXT term patterns on the quoted substring, not JSON ($.event) patterns.
    // Subscribing the alert topic (email, chat bridge, ...) is a per-environment ops step.
    const alertTopic = new sns.Topic(this, 'AirlockAlerts', {
      topicName: resourceName(env, 'channels-airlock-alerts'),
    });
    publish(this, env, 'channels-airlock-alerts-topic-arn', alertTopic.topicArn);

    const silentFailureEvents: [string, string, string][] = [
      ['HandlerError', 'handler_error', 'airlock handler threw — inbound message dropped hard'],
      ['ScreenError', 'screen_error', 'classifier screen failing closed — persistent means 100% drop'],
    ];
    for (const [name, event, description] of silentFailureEvents) {
      const metric = new MetricFilter(this, `Airlock${name}Filter`, {
        logGroup,
        filterPattern: FilterPattern.literal(`"\\"event\\": \\"${event}\\""`),
        metricNamespace: 'SafeAgents/Channels',
        metricName: `Airlock${name}`,
        metricValue: '1',
      }).metric({ statistic: 'Sum', period: Duration.minutes(5) });
      new cloudwatch.Alarm(this, `Airlock${name}Alarm`, {
        alarmName: resourceName(env, `airlock-${event.replace('_', '-')}`),
        alarmDescription: `safe-agents ${env} - ${description}`,
        metric,
        threshold: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }).addAlarmAction(new SnsAction(alertTopic));
    }

    // ── Execution role (owned by THIS stack) ──────────────────────────────────────────────────────
    // The airlock's authority, defined here rather than imported from Identity: it is scoped to
    // exactly the resources this stack touches. Trusted only by the Lambda service principal.
    const executionRole = new Role(this, 'AirlockExecutionRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: `safe-agents ${env} - channels airlock Lambda execution role (least privilege)`,
    });

    // CloudWatch Logs: write to the pre-created log group only (no CreateLogGroup, no wildcard).
    executionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [
          `arn:${Aws.PARTITION}:logs:${Aws.REGION}:${Aws.ACCOUNT_ID}:log-group:${logGroupName}:*`,
        ],
      }),
    );

    // Dedupe table: GetItem (check the window) + PutItem (claim the id). No Update/Delete/Query —
    // idempotency is a single point read + conditional put.
    executionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:PutItem'],
        resources: [dedupeTableArn],
      }),
    );

    // KMS: decrypt + generate data key for dedupe-table I/O (the table is CMK-encrypted; a reader/
    // writer with table perms but no key perms gets AccessDenied — the CMK gotcha).
    executionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
        resources: [tablesKeyArn],
      }),
    );

    // Audit bucket: PutObject only, scoped to the channels/ prefix — the airlock writes DropRecords
    // under channels/drops/, never anything else, and can never read, overwrite, or delete.
    executionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:PutObject'],
        resources: [`${auditBucketArn}/channels/*`],
      }),
    );

    // KMS: generate data key for the SSE-KMS audit writes.
    executionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:GenerateDataKey'],
        resources: [auditKeyArn],
      }),
    );

    // SQS: send only — the airlock hands an accepted event to the broker path, nothing more.
    executionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['sqs:SendMessage'],
        resources: [acceptedQueue.queueArn],
      }),
    );

    // Secrets Manager: read the webhook shared secret to verify the inbound header.
    executionRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue'],
        resources: [webhookSecret.secretArn],
      }),
    );

    // Secrets Manager: read the sender-verification keys secret ONLY when the consumer wires
    // signature verification (channelsVerifyKeysArn context, see above) — an operator-owned
    // secret the stack points at but never creates. Absent, this grants nothing at all and the
    // default synth stays byte-for-byte unchanged (see the conformance row).
    if (verifyKeysArn) {
      executionRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['secretsmanager:GetSecretValue'],
          resources: [verifyKeysArn],
        }),
      );
    }

    // Bedrock: present ONLY when the consumer wires the reference classifier screen (see the
    // channelsScreenModelArns context note above). Scoped to exactly the declared ARNs.
    if (screenModelArns.length > 0) {
      executionRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['bedrock:InvokeModel'],
          resources: screenModelArns,
        }),
      );
    }

    // ── Airlock Lambda (container image) ──────────────────────────────────────────────────────────
    // No VpcConfig — the airlock sits OUTSIDE the agent VPC by design (it fronts untrusted external
    // input; it is not agent egress). arm64 matches the base image; 256 MB / 15 s is ample for the
    // deterministic gate pipeline (the one model-judged gate calls out to a classifier, still well
    // inside the timeout).
    const fn = new lambda.DockerImageFunction(this, 'Airlock', {
      functionName: resourceName(env, 'airlock'),
      code: lambda.DockerImageCode.fromEcr(repo, { tagOrDigest: imageTag }),
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: Duration.seconds(15),
      role: executionRole,
      logGroup,
      environment: {
        CHANNELS_DEDUPE_TABLE: dedupeTableName,
        CHANNELS_DROP_BUCKET: auditBucketName,
        CHANNELS_DROP_PREFIX: 'channels/drops/',
        CHANNELS_ACCEPTED_QUEUE_URL: acceptedQueue.queueUrl,
        CHANNELS_WEBHOOK_SECRET_ARN: webhookSecret.secretArn,
        // The consumer's channels-manifest path inside the (consumer-layered) image — see the
        // channelsManifestPath context note above. Unset = the base image bakes nothing in.
        ...(manifestPath ? { CHANNELS_MANIFEST: manifestPath } : {}),
        // The exact env name safe_agents/channels/keys.py::resolve_verification_keys reads. Unset
        // = unsigned peers pass (see the channelsVerifyKeysArn context note above).
        ...(verifyKeysArn ? { BROKER_VERIFY_KEYS_SECRET_ARN: verifyKeysArn } : {}),
      },
    });

    // ── HTTP API ──────────────────────────────────────────────────────────────────────────────────
    // Exactly one route: POST /inbound → Lambda proxy. No authorizer (the shared-secret header is
    // checked in-Lambda per the channels contracts). The default stage carries EXPLICIT route
    // throttling rather than relying on the account default, closing that gap at the edge.
    const api = new apigwv2.HttpApi(this, 'AirlockApi', {
      apiName: resourceName(env, 'airlock'),
      createDefaultStage: false,
    });
    api.addRoutes({
      path: '/inbound',
      methods: [apigwv2.HttpMethod.POST],
      integration: new HttpLambdaIntegration('AirlockIntegration', fn),
    });
    const stage = new apigwv2.HttpStage(this, 'DefaultStage', {
      httpApi: api,
      autoDeploy: true,
      throttle: { rateLimit: 10, burstLimit: 20 },
    });

    publish(this, env, 'airlock-url', stage.url);

    // ── Drain worker(s) (sa#155, two-consumer split sa#166) ───────────────────────────────────────
    // The worker-side half of the airlock (channels/DRAIN.md §"Reference binding"): drains an
    // accepted queue, builds an ephemeral in-process BrokerRuntime per message, ingests the
    // envelope's provenance chain into the broker-held turn, then hands the envelope to the
    // consumer's Receiver. Each drain is gated entirely on its own image tag — unset, that drain
    // (and its dedicated queue, for missileer) does not exist. The two drains share the Dynamo
    // tables / audit bucket / ledger bucket / secrets substrate (per-principal scoping is an
    // app-layer concern); the ONLY per-drain isolation at the infra layer is the queue each reads
    // and the BROKER_AUDIT_PREFIX each resumes its hash chain under.
    const drainShared: DrainSharedProps = {
      env,
      reuseArtifacts,
      drainRepo,
      tablesKeyArn,
      grantsTableArn,
      grantsTableName,
      countersTableArn,
      countersTableName,
      intentsTableArn,
      intentsTableName,
      auditBucketArn,
      auditBucketName,
      auditKeyArn,
      ledgerBucketArn,
      ledgerKeyArn,
      secretsKeyArn,
    };

    if (drainImageTag) {
      // The primary drain keeps the ORIGINAL construct ids (id '') so it stays the SAME
      // CloudFormation resources the single-drain stack deployed — a namespaced id would change the
      // logical ids and force CloudFormation to create a new drain with the same explicit physical
      // names (function `channels-drain`, log group `/channels-drain`) before deleting the old one,
      // which collides and rolls back. In-place update: only its image tag + manifest/receiver env
      // change (this is the missileer->webhook-peer cutover on the existing accepted queue).
      this.addDrain('', acceptedQueue, {
        imageTag: drainImageTag,
        manifestPath: drainManifestPath!,
        receiver: drainReceiver!,
        logGroupName: `/safe-agents/${env}/channels-drain`,
        auditPrefix: 'audit-drain/',
        exportKey: 'channels-drain-function-name',
        functionName: resourceName(env, 'channels-drain'),
        ...drainShared,
      });
    }

    if (missileerDrainImageTag && missileerAcceptedQueue) {
      this.addDrain('Missileer', missileerAcceptedQueue, {
        imageTag: missileerDrainImageTag,
        manifestPath: missileerDrainManifestPath!,
        receiver: missileerDrainReceiver!,
        logGroupName: `/safe-agents/${env}/channels-drain-missileer`,
        auditPrefix: 'audit-drain-missileer/',
        exportKey: 'channels-drain-missileer-function-name',
        functionName: resourceName(env, 'channels-drain-missileer'),
        ...drainShared,
      });
    }
  }

  /**
   * Builds one drain consumer's full worker-side stack: log group, least-privilege execution role,
   * container-image Lambda, and SQS event source on the PASSED queue. `id` namespaces every
   * construct id (and the drain's own CFN export) so two drains can coexist in one stack. See the
   * class doc's "Drain worker(s)" comment above for the isolation rationale (own queue, own
   * BROKER_AUDIT_PREFIX; everything else shared).
   */
  private addDrain(
    id: string,
    acceptedQueue: sqs.IQueue,
    opts: DrainSharedProps & {
      imageTag: string;
      manifestPath: string;
      receiver: string;
      logGroupName: string;
      auditPrefix: string;
      exportKey: string;
      functionName: string;
    },
  ): lambda.DockerImageFunction {
    const {
      env,
      reuseArtifacts,
      drainRepo,
      tablesKeyArn,
      grantsTableArn,
      countersTableArn,
      intentsTableArn,
      auditBucketArn,
      auditBucketName,
      auditKeyArn,
      ledgerBucketArn,
      ledgerKeyArn,
      secretsKeyArn,
      grantsTableName,
      countersTableName,
      intentsTableName,
      imageTag,
      manifestPath,
      receiver,
      logGroupName,
      auditPrefix,
      exportKey,
      functionName,
    } = opts;

    const drainLogGroup = reuseArtifacts
      ? LogGroup.fromLogGroupName(this, `${id}DrainLogs`, logGroupName)
      : new LogGroup(this, `${id}DrainLogs`, {
          logGroupName,
          retention: RetentionDays.TWO_WEEKS,
          removalPolicy: removalPolicyFor(env),
        });

    // Execution role — owned here, scoped to exactly what one drained message touches: the
    // accepted queue (consume) plus the broker runtime's backends (the brokerRole's statements
    // re-derived for a Lambda: grants read-only, counters/intents read-write, audit chain
    // append+resume, connector secrets read) — least privilege, resource-level, no wildcards
    // beyond the connector-namespace prefix the broker itself carries.
    const drainRole = new Role(this, `${id}DrainExecutionRole`, {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: `safe-agents ${env} - channels ${id} drain Lambda execution role (least privilege)`,
    });

    // CloudWatch Logs: the pre-created log group only (no CreateLogGroup, no wildcard).
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [
          `arn:${Aws.PARTITION}:logs:${Aws.REGION}:${Aws.ACCOUNT_ID}:log-group:${logGroupName}:*`,
        ],
      }),
    );

    // SQS: consume THIS drain's accepted queue, nothing more (SSE-SQS — no KMS needed for the queue).
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:GetQueueAttributes'],
        resources: [acceptedQueue.queueArn],
      }),
    );

    // DynamoDB — grants table: READ ONLY (the broker posture: decisions read grants, never write).
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:Query'],
        resources: [grantsTableArn, `${grantsTableArn}/index/*`],
      }),
    );

    // DynamoDB — counters + intents: read/write (budget counters, require_approval Intents).
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:Query'],
        resources: [
          countersTableArn,
          `${countersTableArn}/index/*`,
          intentsTableArn,
          `${intentsTableArn}/index/*`,
        ],
      }),
    );

    // KMS: the tables CMK — every table above is CMK-encrypted; table perms without key perms is
    // an AccessDenied at the first read.
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
        resources: [tablesKeyArn],
      }),
    );

    // S3 audit bucket: append + chain-resume, the brokerRole's exact posture (sa#132) — GetObject
    // and ListBucket exist ONLY so the audit sink can re-hash the last record; no DeleteObject.
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:PutObject', 's3:GetObject'],
        resources: [`${auditBucketArn}/*`],
      }),
    );
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:ListBucket'],
        resources: [auditBucketArn],
      }),
    );
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:GenerateDataKey', 'kms:Encrypt', 'kms:Decrypt'],
        resources: [auditKeyArn],
      }),
    );

    // S3 ledger bucket: PutObject ONLY, the brokerRole's exact posture (sa#131) — the drain
    // runtime wires the same connectors the broker does (the worked-example receiver's action is
    // ledger.append), and the append-only invariant is IAM-enforced: no Delete*, no Get, no List.
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['s3:PutObject'],
        resources: [`${ledgerBucketArn}/*`],
      }),
    );
    // KMS: generate data key + encrypt for ledger writes (SSE-KMS on the ledger bucket).
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:GenerateDataKey', 'kms:Encrypt'],
        resources: [ledgerKeyArn],
      }),
    );

    // Secrets Manager: connector credentials under THIS environment's namespace only —
    // safe-agents/{env}/connectors/* (the drain's BROKER_SECRET_PREFIX below), so a development
    // drain can never read a production connector credential in a shared account.
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resources: [
          `arn:${Aws.PARTITION}:secretsmanager:${Aws.REGION}:${Aws.ACCOUNT_ID}:secret:safe-agents/${env}/connectors/*`,
        ],
      }),
    );
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['kms:Decrypt'],
        resources: [secretsKeyArn],
      }),
    );

    // Grant-integrity HMAC key — the SAME Secrets Manager secret the ComputeStack broker service
    // injects (safe-agents/{env}/broker-hmac-key, value seeded out of band): with
    // BROKER_GRANT_LOAD=read the grant store recomputes each grant's HMAC on load, and a drain
    // running the hardcoded dev fallback key would quarantine every production-seeded grant.
    // Lambda has no ECS-style secret injection, so the handler fetches the value itself at cold
    // start from the ARN in BROKER_HMAC_KEY_SECRET_ARN — the key plaintext never lands in the
    // function's env config, and a rotated key takes effect on the next cold start rather than
    // the next deploy. The secret uses the AWS-managed Secrets Manager key (the ECS injection
    // path grants GetSecretValue only and works, so no CMK Decrypt is needed here either).
    const hmacSecret = Secret.fromSecretNameV2(
      this,
      `${id}BrokerHmacKey`,
      `safe-agents/${env}/broker-hmac-key`,
    );
    drainRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        // fromSecretNameV2's ARN omits Secrets Manager's random 6-char suffix; the trailing
        // -?????? covers exactly that suffix while staying pinned to this one secret name.
        resources: [`${hmacSecret.secretArn}-??????`],
      }),
    );

    // ── Drain Lambda (container image) ────────────────────────────────────────────────────────────
    // Same posture as the airlock (no VPC, arm64) but 60 s: it builds a full broker runtime —
    // grant load, envelope-store load, audit-chain resume — per message before the receiver acts.
    const drainFn = new lambda.DockerImageFunction(this, `${id}Drain`, {
      functionName,
      code: lambda.DockerImageCode.fromEcr(drainRepo, { tagOrDigest: imageTag }),
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: Duration.seconds(60),
      role: drainRole,
      logGroup: drainLogGroup,
      // The S3 audit sink RESUMES its hash chain by listing the prefix and re-hashing the last
      // record — two concurrent drain runtimes resuming the same prefix would write colliding seq
      // keys and fork the tamper-evident chain. batchSize 1 bounds a single invocation to one
      // message; this bounds the FUNCTION to one concurrent invocation, so exactly one runtime
      // ever resumes the drain's chain at a time.
      reservedConcurrentExecutions: 1,
      environment: {
        // The image-baked drain contract (channels/DRAIN.md D6) — validated non-empty at synth.
        CHANNELS_DRAIN_MANIFEST: manifestPath,
        CHANNELS_DRAIN_RECEIVER: receiver,
        // build_runtime's backend env contract, the ComputeStack broker service's posture minus
        // the HTTP-surface knobs (no BROKER_HOST — the drain runs the runtime in-process).
        // AWS_DEFAULT_REGION is Lambda-reserved and provided by the runtime, so not set here.
        BROKER_HMAC_KEY_SECRET_ARN: hmacSecret.secretArn,
        BROKER_STORE: 'dynamo',
        BROKER_GRANTS_TABLE: grantsTableName,
        BROKER_COUNTERS_TABLE: countersTableName,
        BROKER_INTENTS_TABLE: intentsTableName,
        BROKER_AUDIT_BUCKET: auditBucketName,
        BROKER_SECRETS: 'secretsmanager',
        BROKER_SECRET_PREFIX: `safe-agents/${env}`,
        // This drain's audit chain lives under its OWN prefix, never the long-lived broker
        // service's default 'audit/' — two writers resuming one prefix would fork the chain.
        // Coordinated with build_runtime's BROKER_AUDIT_PREFIX handling on the Python side.
        BROKER_AUDIT_PREFIX: auditPrefix,
        // Read pre-seeded grants + the store-loaded envelope — the production broker posture;
        // a missing grant/envelope fails closed, never self-seeds from the worker.
        BROKER_GRANT_LOAD: 'read',
        BROKER_ENVELOPE_LOAD: 'store',
      },
    });

    // batchSize 1 + reportBatchItemFailures per channels/DRAIN.md §"Reference binding" (D7 is
    // batch-correct in the handler regardless).
    drainFn.addEventSource(
      new SqsEventSource(acceptedQueue, {
        batchSize: 1,
        reportBatchItemFailures: true,
      }),
    );

    publish(this, env, exportKey, drainFn.functionName);

    return drainFn;
  }
}

/**
 * Substrate shared by every drain consumer (sa#166): identical across drains — the isolation
 * between consumers is the queue passed to `addDrain` plus each call's own `auditPrefix`, not any
 * of these fields.
 */
interface DrainSharedProps {
  env: Environment;
  reuseArtifacts: boolean;
  drainRepo: ecr.IRepository;
  tablesKeyArn: string;
  grantsTableArn: string;
  grantsTableName: string;
  countersTableArn: string;
  countersTableName: string;
  intentsTableArn: string;
  intentsTableName: string;
  auditBucketArn: string;
  auditBucketName: string;
  auditKeyArn: string;
  ledgerBucketArn: string;
  ledgerKeyArn: string;
  secretsKeyArn: string;
}
