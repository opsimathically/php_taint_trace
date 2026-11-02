import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const thisFile = fileURLToPath(import.meta.url);
const projectRoot = path.resolve(path.dirname(thisFile), '../..');
const tsxCliPath = path.resolve(projectRoot, 'node_modules/tsx/dist/cli.mjs');
const cliPath = path.resolve(projectRoot, 'src/cli.ts');

interface FixtureReplayResult {
  variation: { id: string };
  evalResults: Record<string, string | undefined>;
  errors: string[];
  driftDetected?: boolean;
  baselineSnapshotHash?: string;
  postResetSnapshotHash?: string;
  driftThresholds?: {
    allowSnapshotDrift: boolean;
    maxExpressionDriftCount: number;
    allowedExpressionDrift: string[];
  };
}

describe('CLI replay-diff and replay-stability', () => {
  const cleanup: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    for (const fn of cleanup.reverse()) {
      await fn();
    }
    cleanup.length = 0;
  });

  it('computes replay diff summary from saved replay results', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-replay-diff-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const resultsPath = path.join(dir, 'results.json');

    await writeFile(
      resultsPath,
      JSON.stringify(
        buildReplayResultsArtifact([
          {
            round: 1,
            results: [
              {
                variation: { id: 'v1' },
                baselineSnapshotHash: 'aaa',
                postResetSnapshotHash: 'bbb',
                evalResults: {},
                errors: [],
                driftDetected: true,
                driftThresholds: {
                  allowSnapshotDrift: false,
                  maxExpressionDriftCount: 0,
                  allowedExpressionDrift: [],
                },
              },
            ],
          },
        ]),
        null,
        2
      ),
      'utf8'
    );

    let threw = false;
    try {
      await execFileAsync(
        process.execPath,
        [
          tsxCliPath,
          cliPath,
          'replay-diff',
          '--results',
          resultsPath,
          '--fail-on-violations',
          '--output',
          'json',
        ],
        { cwd: projectRoot }
      );
    } catch (error) {
      threw = true;
      const output = error as { stdout?: string };
      const payload = JSON.parse(output.stdout ?? '{}') as { summary?: { driftDetected?: number } };
      expect(payload.summary?.driftDetected).toBe(1);
    }

    expect(threw).toBe(true);
  });

  it('computes stability scores and supports threshold failure gating', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-replay-stability-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const resultsPath = path.join(dir, 'results.json');

    await writeFile(
      resultsPath,
      JSON.stringify(
        buildReplayResultsArtifact([
          {
            round: 1,
            results: [
              { variation: { id: 'v1' }, evalResults: {}, errors: [], driftDetected: false },
              { variation: { id: 'v2' }, evalResults: {}, errors: ['x'], driftDetected: true },
            ],
          },
          {
            round: 2,
            results: [
              { variation: { id: 'v1' }, evalResults: {}, errors: [], driftDetected: false },
              { variation: { id: 'v2' }, evalResults: {}, errors: [], driftDetected: false },
            ],
          },
        ]),
        null,
        2
      ),
      'utf8'
    );

    let threw = false;
    try {
      await execFileAsync(
        process.execPath,
        [
          tsxCliPath,
          cliPath,
          'replay-stability',
          '--results',
          resultsPath,
          '--min-overall-score',
          '0.9',
          '--min-variation-score',
          '0.9',
          '--fail-below-thresholds',
          '--output',
          'json',
        ],
        { cwd: projectRoot }
      );
    } catch (error) {
      threw = true;
      const output = error as { stdout?: string };
      const payload = JSON.parse(output.stdout ?? '{}') as {
        thresholdsPassed?: boolean;
        report?: { overallStabilityScore?: number };
      };
      expect(payload.thresholdsPassed).toBe(false);
      expect(payload.report?.overallStabilityScore).toBe(0.75);
    }

    expect(threw).toBe(true);
  });

  it('runs combined replay-gate checks and fails when diff/stability thresholds are violated', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-replay-gate-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const resultsPath = path.join(dir, 'results.json');

    await writeFile(
      resultsPath,
      JSON.stringify(
        buildReplayResultsArtifact([
          {
            round: 1,
            results: [
              { variation: { id: 'v1' }, evalResults: {}, errors: [], driftDetected: false },
              {
                variation: { id: 'v2' },
                evalResults: {},
                errors: ['x'],
                driftDetected: true,
                baselineSnapshotHash: 'aaa',
                postResetSnapshotHash: 'bbb',
                driftThresholds: {
                  allowSnapshotDrift: false,
                  maxExpressionDriftCount: 0,
                  allowedExpressionDrift: [],
                },
              },
            ],
          },
          {
            round: 2,
            results: [
              { variation: { id: 'v1' }, evalResults: {}, errors: [], driftDetected: false },
              { variation: { id: 'v2' }, evalResults: {}, errors: [], driftDetected: false },
            ],
          },
        ]),
        null,
        2
      ),
      'utf8'
    );

    let threw = false;
    try {
      await execFileAsync(
        process.execPath,
        [
          tsxCliPath,
          cliPath,
          'replay-gate',
          '--results',
          resultsPath,
          '--max-drift-detected',
          '0',
          '--min-overall-score',
          '0.9',
          '--min-variation-score',
          '0.9',
          '--fail-on-gate',
          '--output',
          'json',
        ],
        { cwd: projectRoot }
      );
    } catch (error) {
      threw = true;
      const output = error as { stdout?: string };
      const payload = JSON.parse(output.stdout ?? '{}') as {
        gatePassed?: boolean;
        gate?: { diffPassed?: boolean; stabilityPassed?: boolean };
      };
      expect(payload.gatePassed).toBe(false);
      expect(payload.gate?.diffPassed).toBe(false);
      expect(payload.gate?.stabilityPassed).toBe(false);
    }

    expect(threw).toBe(true);
  });

  it('writes and verifies replay artifact manifests', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-replay-manifest-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const resultsPath = path.join(dir, 'results.json');
    const diffPath = path.join(dir, 'diff.json');
    const manifestPath = path.join(dir, 'manifest.json');

    await writeFile(
      resultsPath,
      JSON.stringify(
        buildReplayResultsArtifact([
          {
            round: 1,
            results: [{ variation: { id: 'v1' }, evalResults: {}, errors: [], driftDetected: false }],
          },
        ]),
        null,
        2
      ),
      'utf8'
    );

    const diffResult = await execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'replay-diff',
        '--results',
        resultsPath,
        '--output-diff',
        diffPath,
        '--manifest-path',
        manifestPath,
        '--manifest-hmac-secret',
        'sigsecret',
        '--manifest-hmac-key-id',
        'sig-key',
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );
    const diffPayload = JSON.parse(diffResult.stdout) as { manifestPath?: string };
    expect(diffPayload.manifestPath).toBe(path.resolve(manifestPath));

    const verifyOk = await execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'artifact-verify',
        '--manifest',
        manifestPath,
        '--manifest-hmac-secret',
        'sigsecret',
        '--fail-on-invalid',
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );
    const verifyPayload = JSON.parse(verifyOk.stdout) as {
      ok?: boolean;
      mismatches?: unknown[];
      signature?: { verified?: boolean };
    };
    expect(verifyPayload.ok).toBe(true);
    expect(verifyPayload.mismatches).toEqual([]);
    expect(verifyPayload.signature?.verified).toBe(true);

    await writeFile(diffPath, '{"tampered":true}\n', 'utf8');

    let threw = false;
    try {
      await execFileAsync(
        process.execPath,
        [tsxCliPath, cliPath, 'artifact-verify', '--manifest', manifestPath, '--fail-on-invalid', '--output', 'json'],
        { cwd: projectRoot }
      );
    } catch (error) {
      threw = true;
      const payload = JSON.parse((error as { stdout?: string }).stdout ?? '{}') as {
        ok?: boolean;
        mismatches?: Array<{ reason?: string }>;
      };
      expect(payload.ok).toBe(false);
      expect(payload.mismatches?.some((entry) => entry.reason === 'sha256_mismatch')).toBe(true);
    }

    expect(threw).toBe(true);
  });

  it('runs replay-ci on existing results and writes consolidated artifacts', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-replay-ci-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const outputDir = path.join(dir, 'out');
    const stableResultsPath = path.join(dir, 'stable.json');
    const driftResultsPath = path.join(dir, 'drift.json');

    await writeFile(
      stableResultsPath,
      JSON.stringify(
        buildReplayResultsArtifact([
          {
            round: 1,
            results: [{ variation: { id: 'v1' }, evalResults: {}, errors: [], driftDetected: false }],
          },
          {
            round: 2,
            results: [{ variation: { id: 'v1' }, evalResults: {}, errors: [], driftDetected: false }],
          },
        ]),
        null,
        2
      ),
      'utf8'
    );

    await writeFile(
      driftResultsPath,
      JSON.stringify(
        buildReplayResultsArtifact([
          {
            round: 1,
            results: [
              {
                variation: { id: 'v1' },
                evalResults: {},
                errors: [],
                driftDetected: true,
                baselineSnapshotHash: 'aaa',
                postResetSnapshotHash: 'bbb',
                driftThresholds: {
                  allowSnapshotDrift: false,
                  maxExpressionDriftCount: 0,
                  allowedExpressionDrift: [],
                },
              },
            ],
          },
          {
            round: 2,
            results: [{ variation: { id: 'v1' }, evalResults: {}, errors: [], driftDetected: false }],
          },
        ]),
        null,
        2
      ),
      'utf8'
    );

    const stableResult = await execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'replay-ci',
        '--results',
        stableResultsPath,
        '--sink-category',
        'rce',
        '--output-dir',
        outputDir,
        '--manifest-path',
        path.join(outputDir, 'replay-ci.manifest.json'),
        '--fail-on-gate',
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );
    const stablePayload = JSON.parse(stableResult.stdout) as {
      ok?: boolean;
      gateProfile?: string;
      gate?: { gatePassed?: boolean };
      outputDir?: string;
    };
    expect(stablePayload.ok).toBe(true);
    expect(stablePayload.gateProfile).toBe('rce');
    expect(stablePayload.gate?.gatePassed).toBe(true);
    expect(stablePayload.outputDir).toBe(path.resolve(outputDir));

    const reportBody = await readFile(path.join(outputDir, 'replay-ci.report.json'), 'utf8');
    const reportPayload = JSON.parse(reportBody) as { gateProfile?: string };
    expect(reportPayload.gateProfile).toBe('rce');

    let threw = false;
    try {
      await execFileAsync(
        process.execPath,
        [
          tsxCliPath,
          cliPath,
          'replay-ci',
          '--results',
          driftResultsPath,
          '--sink-category',
          'rce',
          '--fail-on-gate',
          '--output',
          'json',
        ],
        { cwd: projectRoot }
      );
    } catch (error) {
      threw = true;
      const payload = JSON.parse((error as { stdout?: string }).stdout ?? '{}') as {
        ok?: boolean;
        gate?: { gatePassed?: boolean };
      };
      expect(payload.ok).toBe(false);
      expect(payload.gate?.gatePassed).toBe(false);
    }

    expect(threw).toBe(true);
  });

  it('runs replay-ci with --plan using trigger command sessions', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-replay-ci-plan-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const outputDir = path.join(dir, 'out');
    const planPath = path.join(dir, 'replay.plan.json');
    const engineScriptPath = path.join(dir, 'fake_engine.mjs');
    const port = await getAvailablePort();

    await writeFile(
      planPath,
      JSON.stringify(
        {
          variations: [
            {
              id: 'var-one',
              mutations: [{ propertyName: '$cmd', value: 'id' }],
            },
            {
              id: 'var-two',
              mutations: [{ propertyName: '$cmd', value: 'whoami' }],
            },
          ],
          captureBefore: false,
          captureAfter: false,
          continueAfterMutation: false,
        },
        null,
        2
      ),
      'utf8'
    );

    await writeFile(
      engineScriptPath,
      `
import net from 'node:net';

const host = process.argv[2];
const port = Number(process.argv[3]);
if (!host || !Number.isFinite(port)) {
  process.exit(2);
}

const socket = net.createConnection({ host, port });
let pending = Buffer.alloc(0);
let closed = false;

function encode(xml) {
  return Buffer.concat([Buffer.from(String(Buffer.byteLength(xml, 'utf8'))), Buffer.from([0]), Buffer.from(xml), Buffer.from([0])]);
}

function send(xml) {
  if (closed) {
    return;
  }
  socket.write(encode(xml));
}

socket.on('connect', () => {
  send('<init appid="900" idekey="sdk-test" session="cli-plan" language="PHP" protocol_version="1.0" fileuri="file:///tmp/test.php"><engine version="3.3.0" name="Xdebug"></engine></init>');
});

socket.on('data', (chunk) => {
  pending = Buffer.concat([pending, chunk]);
  while (true) {
    const sep = pending.indexOf(0x00);
    if (sep === -1) {
      break;
    }
    const line = pending.subarray(0, sep).toString('utf8').trim();
    pending = pending.subarray(sep + 1);
    if (!line) {
      continue;
    }
    const command = line.split(/\\s+/u)[0];
    const txMatch = /-i\\s+(\\d+)/u.exec(line);
    const tx = txMatch ? Number(txMatch[1]) : 0;
    if (command === 'status') {
      send(\`<response command="status" transaction_id="\${tx}" status="break" reason="ok"></response>\`);
      continue;
    }
    if (command === 'property_set') {
      send(\`<response command="property_set" transaction_id="\${tx}" success="1"></response>\`);
      continue;
    }
    if (command === 'run') {
      send(\`<response command="run" transaction_id="\${tx}" status="stopping" reason="ok"></response>\`);
      continue;
    }
    send(\`<response command="\${command}" transaction_id="\${tx}" status="break" reason="ok"></response>\`);
  }
});

socket.on('error', () => {});
socket.on('close', () => {
  closed = true;
});
socket.on('end', () => {
  closed = true;
  process.exit(0);
});
setTimeout(() => {
  if (!closed) {
    socket.end();
  }
}, 10000);
      `.trim(),
      'utf8'
    );

    const result = await execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'replay-ci',
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
        '--plan',
        planPath,
        '--rounds',
        '1',
        '--trigger-cmd',
        `bash -lc '${process.execPath} ${engineScriptPath} 127.0.0.1 ${port} >/dev/null 2>&1 &'`,
        '--sink-category',
        'rce',
        '--output-dir',
        outputDir,
        '--manifest-path',
        path.join(outputDir, 'replay-ci.manifest.json'),
        '--manifest-hmac-secret',
        'plansecret',
        '--fail-on-gate',
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );

    const payload = JSON.parse(result.stdout) as {
      ok?: boolean;
      source?: string;
      gateProfile?: string;
      gate?: { gatePassed?: boolean };
      manifestPath?: string;
    };
    expect(payload.ok).toBe(true);
    expect(payload.source).toBe('plan');
    expect(payload.gateProfile).toBe('rce');
    expect(payload.gate?.gatePassed).toBe(true);
    expect(payload.manifestPath).toBe(path.resolve(outputDir, 'replay-ci.manifest.json'));

    const verify = await execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'artifact-verify',
        '--manifest',
        path.join(outputDir, 'replay-ci.manifest.json'),
        '--manifest-hmac-secret',
        'plansecret',
        '--fail-on-invalid',
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );
    const verifyPayload = JSON.parse(verify.stdout) as { ok?: boolean };
    expect(verifyPayload.ok).toBe(true);
  }, 20000);

  it('runs bridge-replay-ci as a chained workflow', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-bridge-replay-ci-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const candidatesPath = path.join(dir, 'candidates.jsonl');
    const engineScriptPath = path.join(dir, 'bridge_engine.mjs');
    const port = await getAvailablePort();
    const replayResultsPath = path.resolve(
      projectRoot,
      'tests/fixtures/replay_gate/replay.results.stable.json'
    );

    await writeFile(
      candidatesPath,
      `${JSON.stringify({
        request_id: 'req-1',
        finding_id: 'find-1',
        candidates: [
          {
            candidate_id: 'cand-1',
            sink_category: 'rce',
            sink_name: 'system',
            request_uri: '/?cmd=id',
            metadata: {},
          },
        ],
      })}\n`,
      'utf8'
    );

    await writeFile(
      engineScriptPath,
      `
import net from 'node:net';
const host = process.argv[2];
const port = Number(process.argv[3]);
const socket = net.createConnection({ host, port });
let pending = Buffer.alloc(0);

function encode(xml) {
  return Buffer.concat([Buffer.from(String(Buffer.byteLength(xml, 'utf8'))), Buffer.from([0]), Buffer.from(xml), Buffer.from([0])]);
}
function send(xml) {
  socket.write(encode(xml));
}

socket.on('connect', () => {
  send('<init appid="900" idekey="sdk-test" session="bridge-ci" language="PHP" protocol_version="1.0" fileuri="file:///tmp/test.php"><engine version="3.3.0" name="Xdebug"></engine></init>');
});

socket.on('data', (chunk) => {
  pending = Buffer.concat([pending, chunk]);
  while (true) {
    const sep = pending.indexOf(0x00);
    if (sep === -1) break;
    const line = pending.subarray(0, sep).toString('utf8').trim();
    pending = pending.subarray(sep + 1);
    if (!line) continue;
    const command = line.split(/\\s+/u)[0];
    const txMatch = /-i\\s+(\\d+)/u.exec(line);
    const tx = txMatch ? Number(txMatch[1]) : 0;
    if (command === 'status' || command === 'step_into' || command === 'step_over' || command === 'run') {
      send(\`<response command="\${command}" transaction_id="\${tx}" status="break" reason="ok"></response>\`);
      continue;
    }
    if (command === 'stack_get') {
      send(\`<response command="stack_get" transaction_id="\${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="12" where="{main}"/></response>\`);
      continue;
    }
    if (command === 'context_names') {
      send(\`<response command="context_names" transaction_id="\${tx}"><context name="Locals" id="0"/></response>\`);
      continue;
    }
    if (command === 'context_get') {
      send(\`<response command="context_get" transaction_id="\${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>\`);
      continue;
    }
    if (command === 'eval') {
      send(\`<response command="eval" transaction_id="\${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>\`);
      continue;
    }
    send(\`<response command="\${command}" transaction_id="\${tx}" status="break" reason="ok"></response>\`);
  }
});
socket.on('end', () => process.exit(0));
setTimeout(() => socket.end(), 10000);
      `.trim(),
      'utf8'
    );

    const outputDir = path.join(dir, 'replay-out');
    const result = await execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'bridge-replay-ci',
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
        '--candidates-jsonl',
        candidatesPath,
        '--trigger-cmd',
        `bash -lc '${process.execPath} ${engineScriptPath} 127.0.0.1 ${port} >/dev/null 2>&1 &'`,
        '--replay-results',
        replayResultsPath,
        '--replay-sink-category',
        'rce',
        '--replay-output-dir',
        outputDir,
        '--manifest-path',
        path.join(outputDir, 'bridge-replay.manifest.json'),
        '--manifest-hmac-secret',
        'bridge-secret',
        '--fail-on-gate',
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );

    const payload = JSON.parse(result.stdout) as {
      ok?: boolean;
      bridge?: { processed?: number };
      replayCi?: { ok?: boolean; gate?: { gatePassed?: boolean } };
    };
    expect(payload.ok).toBe(true);
    expect(payload.bridge?.processed).toBe(1);
    expect(payload.replayCi?.ok).toBe(true);
    expect(payload.replayCi?.gate?.gatePassed).toBe(true);
  }, 20000);
});

async function getAvailablePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (!Number.isFinite(port) || port <= 0) {
    throw new Error('Unable to reserve ephemeral port.');
  }
  return port;
}

function buildReplayResultsArtifact(roundResults: Array<{ round: number; results: FixtureReplayResult[] }>) {
  const data = roundResults.flatMap((round) =>
    round.results.map((result, index) => ({
      variation: result.variation,
      result,
      sessionId: `session-${round.round}-${index + 1}`,
    }))
  );
  const wrappedRoundResults = roundResults.map((round) => ({
    round: round.round,
    results: round.results.map((result, index) => ({
      variation: result.variation,
      result,
      sessionId: `session-${round.round}-${index + 1}`,
    })),
  }));
  const totalSamples = data.length;
  const stableSamples = roundResults
    .flatMap((round) => round.results)
    .filter((result) => !result.driftDetected && result.errors.length === 0).length;

  return {
    ok: true,
    rounds: roundResults.length,
    totalRuns: data.length,
    stabilityReport: {
      rounds: roundResults.length,
      totalSamples,
      overallStabilityScore: totalSamples === 0 ? 0 : stableSamples / totalSamples,
      variationScores: [
        {
          variationId: 'v1',
          samples: roundResults.length,
          stableSamples: roundResults.filter((round) =>
            round.results.find((result) => result.variation.id === 'v1' && !result.driftDetected && result.errors.length === 0)
          ).length,
          driftSamples: roundResults.filter((round) =>
            round.results.find((result) => result.variation.id === 'v1' && result.driftDetected)
          ).length,
          errorSamples: roundResults.filter((round) =>
            round.results.find((result) => result.variation.id === 'v1' && result.errors.length > 0)
          ).length,
          stabilityScore: roundResults.length === 0
            ? 0
            : roundResults.filter((round) =>
              round.results.find((result) => result.variation.id === 'v1' && !result.driftDetected && result.errors.length === 0)
            ).length / roundResults.length,
        },
        {
          variationId: 'v2',
          samples: roundResults.length,
          stableSamples: roundResults.filter((round) =>
            round.results.find((result) => result.variation.id === 'v2' && !result.driftDetected && result.errors.length === 0)
          ).length,
          driftSamples: roundResults.filter((round) =>
            round.results.find((result) => result.variation.id === 'v2' && result.driftDetected)
          ).length,
          errorSamples: roundResults.filter((round) =>
            round.results.find((result) => result.variation.id === 'v2' && result.errors.length > 0)
          ).length,
          stabilityScore: roundResults.length === 0
            ? 0
            : roundResults.filter((round) =>
              round.results.find((result) => result.variation.id === 'v2' && !result.driftDetected && result.errors.length === 0)
            ).length / roundResults.length,
        },
      ],
    },
    data,
    roundResults: wrappedRoundResults,
  };
}
