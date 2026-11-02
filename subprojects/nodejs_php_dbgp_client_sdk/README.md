# nodejs_php_dbgp_client_sdk
TypeScript/Node.js SDK for PHP Xdebug DBGp session intake, transport-level command control, and high-level debug-state inspection.

## Goals
- Accept inbound Xdebug DBGp connections reliably.
- Provide strict protocol handling (framing + XML response parsing).
- Support security-auditing workflows where suspicious sink activity triggers deep state capture.
- Offer both library APIs and CLI controls for automation and incident triage.

## Baseline Features
- DBGp transport listener with session management.
- Framed payload codec (`length\0xml\0`) with partial-chunk buffering.
- Command send/response correlation via transaction ids.
- Session transcript capture (`in/out` command and packet records).
- Transcript artifact persistence with redaction pipeline (`dbgp-transcript.v1`).
- High-level inspector API:
  - run control (`run`, `step_into`, `step_over`, `step_out`, `stop`, `detach`)
  - debugger feature read/write (`feature_get`, `feature_set`)
  - source retrieval (`source`)
  - output stream control (`stdout`, `stderr` forwarding modes)
  - stack/context/property introspection
  - property mutation (`property_set`) with fallback mutation flow via eval assignment
  - expression evaluation
  - breakpoint set/get/list/update/remove
  - snapshot capture
- Replay orchestration:
  - per-variation mutation plans
  - baseline/reset mutation controls
  - deterministic matrix expansion for mutation combinations
  - deterministic drift checks (snapshot hash + expression comparison)
  - expression allowlist/tolerance thresholds for drift gating
  - optional pre/post snapshot collection
  - multi-round stability scoring
  - multi-run replay control across fresh sessions
- Execution tracing:
  - deterministic stepping plan (`run/step_into/step_over/step_out`)
  - watch expression evaluation per step
  - optional per-step snapshot capture
- Event orchestration:
  - break-event callbacks (`onBreak`)
  - exception callbacks (`onException`)
  - conditional auto-capture rules with snapshots and watch values
- Candidate bridge for `php_taint_trace`:
  - consume candidate/envelope JSONL
  - carry correlation ids (`correlationId/requestId/findingId`) from envelope to artifact metadata
  - trigger target request per candidate
  - apply category policy packs (`rce/ssrf/sqli/file/xss/idor`) for trace/watch defaults
  - capture snapshot + trace + transcript artifact per candidate
  - optional plugin loading for trigger-template overrides and redaction rules
- Debug integration orchestration:
  - `DebugIntegrationService` high-level sink-driven capture workflow
  - `captureWithReplayTemplate()` single-call sink-class replay capture
  - `runReplayAttempts()` bounded multi-attempt replay orchestration with failure taxonomy
  - `runReplayAttemptsAsVerifierDecision()` adapter output matching `php_taint_trace` verifier payload contract
  - correlation-aware session routing (`DebugSessionRouter`)
  - routing cancellation via abort signals
  - dead-session recovery with configurable retry attempts
  - automatic replay mutation-target inference from `requestUri`/trigger metadata
  - candidate-aware replay targeting from `php_taint_trace` evidence (`request_evidence`, `replay_plan`, `sink_evidence`, `taint_evidence`)
  - optional deterministic attempt artifact bundle + replay manifest output
  - deterministic evidence contracts (normalized snapshot/trace/replay payloads)
- CLI with human or JSON output modes.
- Unit + integration tests (Vitest) with a fake Xdebug engine.
- Remote Xdebug container smoke validation script.
- Local lint, test and build commands; remote smoke requires an explicitly configured authorized lab.

## Quick Start
```bash
npm install
npm run lint
npm run test
npm run build
```

One-shot snapshot capture:
```bash
npx tsx examples/capture-snapshot.ts
```

Sink-driven debug integration capture (high-level SDK API):
```bash
npx tsx examples/debug-integration-capture.ts
```

Sink-template debug capture (auto replay plan + target inference):
```bash
npx tsx examples/debug-integration-template-capture.ts
```

Multi-attempt replay orchestration capture:
```bash
npx tsx examples/debug-integration-replay-attempts.ts
```

Verifier decision payload adaptation:
```bash
npx tsx examples/debug-integration-verifier-decision.ts
```

CLI listener:
```bash
npx tsx src/cli.ts listen --host 127.0.0.1 --port 9003 --output human
```

CLI stack query (waits for first inbound Xdebug session):
```bash
npx tsx src/cli.ts stack --host 127.0.0.1 --port 9003 --output json
```

Verifier decision CLI (php_taint_trace-compatible payload):
```bash
npx tsx src/cli.ts verifier-decision \
  --candidate-id cand-1 \
  --sink-category rce \
  --attempts 3 \
  --trigger-cmd 'curl -s "http://127.0.0.1:8080/?candidate=${candidateId}&attempt=${attempt}"' \
  --decision-output ./artifacts/verifier-decision.json \
  --decision-jsonl ./artifacts/verifier-decisions.jsonl \
  --fail-on-unconfirmed \
  --output json
```

Batch verifier decision CLI (candidate JSONL -> decisions JSONL):
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

Execution trace with watch values:
```bash
npx tsx src/cli.ts trace-exec --steps 5 --action step_over --watch '$cmd' --output json
```

Transcript artifact capture with plugin redaction:
```bash
npx tsx src/cli.ts transcript-save \
  --artifact-path ./artifacts/session.transcript.json \
  --redaction-plugin ./examples/plugins/custom-redaction-plugin.ts \
  --output json
```

Replay matrix validation/expansion:
```bash
npx tsx src/cli.ts replay-matrix \
  --plan ./replay.plan.json \
  --output-plan ./replay.expanded.json \
  --output json
```

Replay drift diff from saved results:
```bash
npx tsx src/cli.ts replay-diff \
  --results ./replay.results.json \
  --compare-phase post_reset \
  --output json
```

Replay stability scoring with threshold gate:
```bash
npx tsx src/cli.ts replay-stability \
  --results ./replay.results.json \
  --min-overall-score 0.95 \
  --min-variation-score 0.90 \
  --fail-below-thresholds \
  --output json
```

Combined replay gate (diff + stability in one decision):
```bash
npx tsx src/cli.ts replay-gate \
  --results ./replay.results.json \
  --max-drift-detected 0 \
  --min-overall-score 0.95 \
  --min-variation-score 0.90 \
  --fail-on-gate \
  --output json
```

One-shot replay CI pipeline (results + diff + stability + gate + artifacts):
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

Artifact integrity verification (sha256/size manifest check):
```bash
npx tsx src/cli.ts artifact-verify \
  --manifest ./artifacts/replay-ci/replay-ci.manifest.json \
  --manifest-hmac-secret "$REPLAY_MANIFEST_SECRET" \
  --fail-on-invalid \
  --output json
```

Chained candidate bridge + replay gate workflow:
```bash
npx tsx src/cli.ts bridge-replay-ci \
  --candidates-jsonl /path/to/candidates.jsonl \
  --trigger-cmd 'curl -s http://127.0.0.1:8080/?candidate=${candidateId}' \
  --replay-results ./replay.results.json \
  --replay-sink-category rce \
  --replay-output-dir ./artifacts/bridge-replay \
  --manifest-path ./artifacts/bridge-replay/bridge-replay.manifest.json \
  --manifest-hmac-secret "$REPLAY_MANIFEST_SECRET" \
  --fail-on-gate \
  --output json
```

Replay fixture gate check used by CI:
```bash
npm run gate:replay-fixtures
```

Candidate-driven bridge run:
```bash
npx tsx src/cli.ts bridge-candidates \
  --candidates-jsonl /path/to/candidates.jsonl \
  --trigger-cmd 'curl -s http://127.0.0.1:8080/?id=${candidateId}' \
  --capture-profile rce \
  --policy-pack default \
  --artifacts-dir ./.dbgp_bridge_artifacts \
  --trigger-resolver-plugin ./examples/plugins/custom-trigger-resolver-plugin.ts \
  --redaction-plugin ./examples/plugins/custom-redaction-plugin.ts \
  --output json
```

Resolve trigger template before running bridge jobs:
```bash
npx tsx src/cli.ts resolve-trigger \
  --template 'curl -s "http://127.0.0.1:8080/?id=${candidateId}&cat=${sinkCategory}"' \
  --candidate-id cand-123 \
  --sink-category rce
```

Remote container smoke test (uses repository container config):
```bash
npm run test:remote:container
```

## Documentation
- [Protocol architecture](docs/protocol.md)
- [API and CLI usage](docs/usage.md)
