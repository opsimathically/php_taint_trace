# API and CLI Usage

## SDK Usage (TypeScript)
```ts
import { DbgpServer, PhpDebugInspector } from '@internal/nodejs-php-dbgp-client-sdk';

const server = new DbgpServer({ host: '127.0.0.1', port: 9003, strict: true });
await server.start();

const session = await server.waitForNextSession(30000);
await session.waitForInit(30000);

const inspector = new PhpDebugInspector(session, { commandTimeoutMs: 5000, strict: true });
const stack = await inspector.stackGet();
const locals = await inspector.contextGet(0, 0);
const value = await inspector.evaluate('$cmd');
```

## High-Level Debug Integration API
```ts
import { DbgpServer, DebugIntegrationService } from '@internal/nodejs-php-dbgp-client-sdk';

const server = new DbgpServer({ host: '127.0.0.1', port: 9003, strict: true });
await server.start();

const integration = new DebugIntegrationService(server, {
  commandTimeoutMs: 7000,
  sessionTimeoutMs: 30000,
  primeAction: 'step_into',
});

const capture = await integration.captureForTrigger(
  {
    trigger: {
      candidateId: 'cand-1',
      sinkCategory: 'rce',
      sinkName: 'system',
    },
    abortSignal: controller.signal,
    routing: {
      requireCorrelationMatch: true,
      allowUnmatchedFallback: false,
      maxRecoveryAttempts: 1,
    },
    evaluateExpressions: ['$cmd'],
    tracePlan: { steps: 2, action: 'step_over', watchExpressions: ['$cmd'] },
    includeTranscript: true,
  },
  async () => {
    // Trigger target request that causes inbound Xdebug session.
  }
);
```

Template-driven one-call capture:
```ts
const capture = await integration.captureWithReplayTemplate({
  trigger: {
    candidateId: 'cand-2',
    sinkCategory: 'file',
    sinkName: 'include',
    requestUri: '/index.php?page=home',
    metadata: {
      targetParam: 'page', // optional explicit mutation target hint
    },
  },
  includeTranscript: true,
});

console.log(capture.template.template.name); // file
console.log(capture.template.template.mutationTarget); // $_GET["page"]
console.log(capture.template.replayPlan.variations.length); // > 0
```

Bounded multi-attempt replay orchestration:
```ts
const attempts = await integration.runReplayAttempts(
  {
    trigger: {
      candidateId: 'cand-3',
      sinkCategory: 'rce',
    },
    attempts: 3,
    stopOnFirstSuccess: true,
    includeTranscript: true,
    artifactDir: './artifacts/replay-attempts',
    manifestSignature: {
      hmacSecret: process.env.REPLAY_MANIFEST_SECRET ?? 'dev-secret',
      keyId: 'local-dev',
    },
  },
  async (_trigger, attempt) => {
    // Trigger request for this attempt index.
  }
);

console.log(attempts.bundle.finalStatus); // succeeded|failed
console.log(attempts.bundle.attempts[0]?.failureCode); // taxonomy reason
console.log(attempts.artifactManifestPath); // optional manifest path when artifactDir is set
```

Verifier-facing decision adapter (php_taint_trace payload contract):
```ts
const decision = await integration.runReplayAttemptsAsVerifierDecision(
  {
    trigger: {
      candidateId: 'cand-4',
      sinkCategory: 'rce',
    },
    attempts: 3,
    stopOnFirstSuccess: true,
  },
  async (_trigger, attempt) => {
    // Trigger request for this attempt.
  }
);

console.log(decision.verificationResult.outcome); // confirmed|not_confirmed|...
console.log(decision.verificationResult.reason_codes);
console.log(decision.verificationResult.artifacts);
```

Verifier-facing decision CLI:
```bash
npx tsx src/cli.ts verifier-decision \
  --candidate-id cand-7 \
  --sink-category rce \
  --attempts 3 \
  --trigger-cmd 'curl -s "http://127.0.0.1:8080/?candidate=${candidateId}&attempt=${attempt}"' \
  --artifact-dir ./artifacts/replay-attempts \
  --manifest-path ./artifacts/replay-attempts/replay-attempts.manifest.json \
  --decision-output ./artifacts/verifier-decision.json \
  --decision-jsonl ./artifacts/verifier-decisions.jsonl \
  --fail-on-unconfirmed \
  --output json
```

Verifier-facing batch decision CLI:
```bash
npx tsx src/cli.ts verifier-decision-batch \
  --candidates-jsonl /path/to/candidates.jsonl \
  --trigger-cmd 'curl -s "http://127.0.0.1:8080/?candidate=${candidateId}&attempt=${attempt}"' \
  --decisions-jsonl ./artifacts/verifier-decisions.jsonl \
  --decision-dir ./artifacts/verifier-decisions \
  --attempts 3 \
  --fail-on-unconfirmed \
  --output json
```

Replay attempt failure taxonomy:
- `trigger_failed`
- `routing_aborted`
- `routing_timeout`
- `session_closed`
- `command_timeout`
- `protocol_error`
- `capture_failed`
- `replay_failed`
- `unknown`

Template resolution order:
1. Explicit `template` overrides on request.
2. Trigger metadata hints (`mutationTarget`, `replayPayloads`, `replayResetValue`, `targetParam`).
3. Candidate replay-plan hints (`target_query_param`, `target_body_param`, `target_param_location`) from `metadata`, `replay_plan`, or nested `candidate_snapshot.replay_plan`.
4. Candidate taint/sink evidence hints (source param names, sink argument roles such as `resource_id`) from nested metadata.
5. Sink-category template defaults (`rce/ssrf/sqli/file/xss/idor/default`).
6. Request URI query-param inference for mutation target when possible.

`php_taint_trace` candidate metadata fields recognized by template capture:
- `request_evidence.request_uri` (or `candidate_snapshot.request_evidence.request_uri`)
- `request_evidence.request_method` (or nested candidate snapshot equivalent)
- `replay_plan.target_query_param`
- `replay_plan.target_body_param`
- `replay_plan.target_param_location`
- `payload_plan.target_query_param`
- `sink_evidence.argument_roles` (including role maps serialized as objects)
- `taint_evidence.metadata.source_param_names` / `source_params` / `source_keys`

Routing behavior:
1. Correlation tokens (`correlationId`, `requestId`, `candidateId`, `findingId`, `traceId`) are matched against session init fields.
2. `requireCorrelationMatch=true` rejects non-matching sessions.
3. `abortSignal` cancels waiting/routing without blocking until full timeout.
4. `maxRecoveryAttempts` retries capture when the selected session closes unexpectedly.

## Snapshot Capture Workflow
```ts
const snapshot = await inspector.captureSnapshot([0, 1]);
```
`snapshot` returns:
- init metadata (app/file/session id)
- status response
- current stack frames
- per-context property captures

## CLI Examples
Listen and print first inbound session:
```bash
npx tsx src/cli.ts listen --host 127.0.0.1 --port 9003 --output human
```

JSON snapshot output:
```bash
npx tsx src/cli.ts snapshot --host 127.0.0.1 --port 9003 --output json
```

Optional config file defaults:
```json
{
  "host": "127.0.0.1",
  "port": 9003,
  "timeoutMs": 30000,
  "output": "json",
  "strict": true
}
```
```bash
npx tsx src/cli.ts snapshot --config ./dbgp.cli.json
```

Evaluate expression:
```bash
npx tsx src/cli.ts eval --expression '$userId' --output json
```

Set/get property:
```bash
npx tsx src/cli.ts property-get --name '$cmd' --output json
npx tsx src/cli.ts property-set --name '$cmd' --value 'id' --output json
```

Feature and source operations:
```bash
npx tsx src/cli.ts feature-get --name max_children --output json
npx tsx src/cli.ts source --file-uri file:///var/www/html/index.php --output json
```

Breakpoint introspection:
```bash
npx tsx src/cli.ts breakpoint-list --output json
npx tsx src/cli.ts breakpoint-update --id bp-1 --state disabled --output json
```

Replay plan execution:
```bash
npx tsx src/cli.ts replay \
  --plan ./replay.plan.json \
  --trigger-cmd 'curl -s http://127.0.0.1:8080/?v=${variationId}&round=${round}' \
  --rounds 3 \
  --output-results ./replay.results.json \
  --output-stability ./replay.stability.json \
  --output json
```

Replay matrix helper (validation + expansion):
```bash
npx tsx src/cli.ts replay-matrix \
  --plan ./replay.plan.json \
  --output-plan ./replay.expanded.json \
  --output json
```

Replay diff helper (structured baseline vs compare report):
```bash
npx tsx src/cli.ts replay-diff \
  --results ./replay.results.json \
  --compare-phase post_reset \
  --output-diff ./replay.diff.json \
  --fail-on-violations \
  --output json
```

Replay stability scoring helper:
```bash
npx tsx src/cli.ts replay-stability \
  --results ./replay.results.json \
  --min-overall-score 0.95 \
  --min-variation-score 0.90 \
  --fail-below-thresholds \
  --output json
```

Combined replay gate helper:
```bash
npx tsx src/cli.ts replay-gate \
  --results ./replay.results.json \
  --sink-category rce \
  --max-drift-detected 0 \
  --min-overall-score 0.95 \
  --min-variation-score 0.90 \
  --fail-on-gate \
  --output json
```

One-shot replay CI pipeline:
```bash
npx tsx src/cli.ts replay-ci \
  --results ./replay.results.json \
  --sink-category rce \
  --output-dir ./artifacts/replay-ci \
  --manifest-path ./artifacts/replay-ci/replay-ci.manifest.json \
  --manifest-hmac-secret "$REPLAY_MANIFEST_SECRET" \
  --fail-on-gate \
  --output json
```

Replay artifact verification:
```bash
npx tsx src/cli.ts artifact-verify \
  --manifest ./artifacts/replay-ci/replay-ci.manifest.json \
  --manifest-hmac-secret "$REPLAY_MANIFEST_SECRET" \
  --fail-on-invalid \
  --output json
```

Bridge + replay-ci chained workflow:
```bash
npx tsx src/cli.ts bridge-replay-ci \
  --candidates-jsonl ./runtime/candidates.jsonl \
  --trigger-cmd 'curl -s "http://127.0.0.1:8080/?candidate=${candidateId}"' \
  --replay-results ./replay.results.json \
  --replay-sink-category rce \
  --replay-output-dir ./artifacts/bridge-replay \
  --manifest-path ./artifacts/bridge-replay/bridge-replay.manifest.json \
  --manifest-hmac-secret "$REPLAY_MANIFEST_SECRET" \
  --fail-on-gate \
  --output json
```

Replay gate profile resolution order:
1. `--gate-profile <name>` explicit profile (`default|rce|ssrf|sqli|file|xss|idor`)
2. `--sink-category <category>` category-mapped profile fallback
3. `default` profile fallback

Execution tracing:
```bash
npx tsx src/cli.ts trace-exec \
  --steps 6 \
  --action step_over \
  --watch '$cmd' \
  --watch '$userId' \
  --output json
```

Transcript artifact export:
```bash
npx tsx src/cli.ts transcript-save \
  --artifact-path ./artifacts/session.transcript.json \
  --include-snapshot \
  --redaction-plugin ./examples/plugins/custom-redaction-plugin.ts \
  --output json
```

Break/exception watcher with conditional auto-capture:
```bash
npx tsx src/cli.ts watch-breaks \
  --max-events 3 \
  --auto-capture-exceptions \
  --watch '$cmd' \
  --output json
```

Candidate bridge workflow:
```bash
npx tsx src/cli.ts bridge-candidates \
  --candidates-jsonl ./runtime/findings.jsonl \
  --trigger-cmd 'curl -s http://127.0.0.1:8080/?candidate=${candidateId}' \
  --artifacts-dir ./.dbgp_bridge_artifacts \
  --capture-profile rce \
  --policy-pack default \
  --trace-steps 0 \
  --watch '$cmd' \
  --trigger-resolver-plugin ./examples/plugins/custom-trigger-resolver-plugin.ts \
  --redaction-plugin ./examples/plugins/custom-redaction-plugin.ts \
  --output json
```

Trigger template preview helper:
```bash
npx tsx src/cli.ts resolve-trigger \
  --template 'curl -s "http://127.0.0.1:8080/?id=${candidateId}&cat=${sinkCategory}&req=${requestId}"' \
  --candidate-id cand-123 \
  --sink-category rce \
  --request-id req-9
```

Policy-aware break watching:
```bash
npx tsx src/cli.ts watch-breaks \
  --capture-profile rce \
  --policy-pack rce \
  --auto-capture-exceptions \
  --output json
```

Replay plan with baseline reset + matrix expansion:
```json
{
  "variations": [
    { "id": "cmd-matrix", "evalExpressions": ["$cmd"] }
  ],
  "baselineMutations": [
    { "propertyName": "$baseline", "value": "stable" }
  ],
  "matrix": [
    { "propertyName": "$cmd", "values": ["id", "whoami"] }
  ],
  "captureBaseline": true,
  "continueAfterMutation": false,
  "deterministicChecks": {
    "enabled": true,
    "failOnDrift": true,
    "comparePhase": "post_reset",
    "driftExpressions": ["$cmd"],
    "thresholds": {
      "allowSnapshotDrift": false,
      "maxExpressionDriftCount": 0,
      "allowedExpressionDrift": []
    }
  }
}
```

## Replay Artifact Schemas
Replay artifact outputs are schema-validated before write:
- `schemas/replay-results.schema.json`
- `schemas/replay-diff.schema.json`
- `schemas/replay-stability.schema.json`
- `schemas/replay-manifest.schema.json`

Set line breakpoint:
```bash
npx tsx src/cli.ts breakpoint-set \
  --type line \
  --file-uri file:///var/www/html/index.php \
  --line 42 \
  --output json
```

Interactive mode:
```bash
npx tsx src/cli.ts listen --interactive
```

Interactive commands:
- `stack`
- `contexts`
- `context-get <id>`
- `eval <expression>`
- `run`
- `step-into`
- `step-over`
- `step-out`
- `snapshot`
- `transcript`
- `quit`

## Remote Container Validation
The SDK includes an end-to-end Xdebug smoke script using the parent repository container credentials/config.

Run from `subprojects/nodejs_php_dbgp_client_sdk`:
```bash
npm run test:remote:container
```

This validates:
- inbound DBGp connectivity from remote PHP/Xdebug runtime,
- stack/session control,
- runtime variable mutation,
- replay variation execution across fresh sessions,
- multi-step trace execution with watch values.

## Plugin Contracts
Two plugin interfaces are supported by CLI and SDK:
- `TranscriptRedactionPlugin`: custom transcript payload redaction.
- `CandidateTriggerResolverPlugin`: custom candidate trigger command resolution.

Supported export shapes per module:
- `export default plugin`
- `export const plugin = ...`
- `export const plugins = [ ... ]`

`bridge-candidates --trigger-cmd` placeholders:
- `${candidateId}`
- `${sinkCategory}`
- `${sinkName}`
- `${requestUri}`
- `${correlationId}`
- `${requestId}`
- `${findingId}`
