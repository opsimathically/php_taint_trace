import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const thisFile = fileURLToPath(import.meta.url);
const projectRoot = path.resolve(path.dirname(thisFile), '..');
const tsxCliPath = path.resolve(projectRoot, 'node_modules/tsx/dist/cli.mjs');
const cliPath = path.resolve(projectRoot, 'src/cli.ts');

async function main(): Promise<void> {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'dbgp-replay-fixture-gates-'));
  try {
    const matrixPlanPath = path.resolve(projectRoot, 'tests/fixtures/replay_gate/replay.plan.matrix.json');
    const stableResultsPath = path.resolve(
      projectRoot,
      'tests/fixtures/replay_gate/replay.results.stable.json'
    );
    const driftResultsPath = path.resolve(
      projectRoot,
      'tests/fixtures/replay_gate/replay.results.drift.json'
    );
    const expandedPlanPath = path.join(tempDir, 'replay.expanded.json');

    const matrix = await runCli(
      [
        'replay-matrix',
        '--plan',
        matrixPlanPath,
        '--output-plan',
        expandedPlanPath,
        '--output',
        'json',
      ],
      false
    );
    const matrixCount = Number((matrix as Record<string, unknown>).expandedVariationCount ?? -1);
    if (matrixCount !== 2) {
      throw new Error(`Expected replay-matrix to produce 2 variations; got ${matrixCount}.`);
    }
    await readFile(expandedPlanPath, 'utf8');

    const stableDiff = await runCli(
      [
        'replay-diff',
        '--results',
        stableResultsPath,
        '--fail-on-violations',
        '--output',
        'json',
      ],
      false
    );
    const stableDiffDetected = Number(
      ((stableDiff.summary as Record<string, unknown> | undefined)?.driftDetected as number | undefined) ?? -1
    );
    if (stableDiffDetected !== 0) {
      throw new Error('Expected stable replay-diff driftDetected=0.');
    }

    const driftDiff = await runCli(
      [
        'replay-diff',
        '--results',
        driftResultsPath,
        '--fail-on-violations',
        '--output',
        'json',
      ],
      true
    );
    const driftDiffDetected = Number(
      ((driftDiff.summary as Record<string, unknown> | undefined)?.driftDetected as number | undefined) ?? -1
    );
    if (driftDiffDetected !== 1) {
      throw new Error('Expected drift replay-diff driftDetected=1.');
    }

    const stableStability = await runCli(
      [
        'replay-stability',
        '--results',
        stableResultsPath,
        '--min-overall-score',
        '1',
        '--min-variation-score',
        '1',
        '--fail-below-thresholds',
        '--output',
        'json',
      ],
      false
    );
    const stableThresholdsPassed = stableStability.thresholdsPassed === true;
    if (!stableThresholdsPassed) {
      throw new Error('Expected stable replay-stability thresholdsPassed=true.');
    }

    const driftGate = await runCli(
      [
        'replay-gate',
        '--results',
        driftResultsPath,
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
      true
    );
    const driftGatePassed = driftGate.gatePassed === true;
    if (driftGatePassed) {
      throw new Error('Expected drift replay-gate gatePassed=false.');
    }

    const stableGate = await runCli(
      [
        'replay-gate',
        '--results',
        stableResultsPath,
        '--max-drift-detected',
        '0',
        '--min-overall-score',
        '1',
        '--min-variation-score',
        '1',
        '--fail-on-gate',
        '--output',
        'json',
      ],
      false
    );
    const stableGatePassed = stableGate.gatePassed === true;
    if (!stableGatePassed) {
      throw new Error('Expected stable replay-gate gatePassed=true.');
    }

    const replayCiStable = await runCli(
      [
        'replay-ci',
        '--results',
        stableResultsPath,
        '--sink-category',
        'rce',
        '--output-dir',
        path.join(tempDir, 'replay-ci-stable'),
        '--manifest-path',
        path.join(tempDir, 'replay-ci-stable', 'manifest.json'),
        '--fail-on-gate',
        '--output',
        'json',
      ],
      false
    );
    const replayCiStableOk = replayCiStable.ok === true;
    if (!replayCiStableOk) {
      throw new Error('Expected stable replay-ci ok=true.');
    }

    const replayCiDrift = await runCli(
      [
        'replay-ci',
        '--results',
        driftResultsPath,
        '--sink-category',
        'rce',
        '--fail-on-gate',
        '--output',
        'json',
      ],
      true
    );
    const replayCiDriftOk = replayCiDrift.ok === true;
    if (replayCiDriftOk) {
      throw new Error('Expected drift replay-ci ok=false.');
    }

    const stableScore = Number(
      ((stableStability.report as Record<string, unknown> | undefined)?.overallStabilityScore as number | undefined) ?? 0
    );

    process.stdout.write(
      `${JSON.stringify(
        {
          ok: true,
          checks: {
            replayMatrixExpandedVariationCount: matrixCount,
            stableDiffDriftDetected: stableDiffDetected,
            driftDiffDriftDetected: driftDiffDetected,
            stableStabilityScore: stableScore,
            driftGatePassed,
            stableGatePassed,
            replayCiStableOk,
            replayCiDriftOk,
          },
        },
        null,
        2
      )}\n`
    );
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function runCli(args: string[], expectFailure: boolean): Promise<Record<string, unknown>> {
  const command = [tsxCliPath, cliPath, ...args];
  if (!expectFailure) {
    const result = await execFileAsync(process.execPath, command, { cwd: projectRoot });
    return JSON.parse(result.stdout) as Record<string, unknown>;
  }

  try {
    await execFileAsync(process.execPath, command, { cwd: projectRoot });
    throw new Error(`Expected failure for command: ${args.join(' ')}`);
  } catch (error) {
    const output = error as { stdout?: string };
    return JSON.parse(output.stdout ?? '{}') as Record<string, unknown>;
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
