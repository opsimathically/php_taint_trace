import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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

describe('CLI replay-matrix helper', () => {
  const cleanup: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    for (const fn of cleanup.reverse()) {
      await fn();
    }
    cleanup.length = 0;
  });

  it('expands matrix plans and writes expanded output plan', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-replay-matrix-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const planPath = path.join(dir, 'plan.json');
    const outPath = path.join(dir, 'expanded.json');

    await writeFile(
      planPath,
      JSON.stringify(
        {
          variations: [{ id: 'base', evalExpressions: ['$cmd'] }],
          matrix: [{ propertyName: '$cmd', values: ['id', 'whoami'] }],
        },
        null,
        2
      ),
      'utf8'
    );

    const result = await execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'replay-matrix',
        '--plan',
        planPath,
        '--output-plan',
        outPath,
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );

    const payload = JSON.parse(result.stdout.trim()) as {
      ok: boolean;
      expandedVariationCount: number;
      expandedVariationIds: string[];
    };
    expect(payload.ok).toBe(true);
    expect(payload.expandedVariationCount).toBe(2);
    expect(payload.expandedVariationIds).toEqual(['base__$cmd:id', 'base__$cmd:whoami']);

    const expandedRaw = await readFile(outPath, 'utf8');
    const expanded = JSON.parse(expandedRaw) as { variations: Array<{ id: string }> };
    expect(expanded.variations.map((entry) => entry.id)).toEqual([
      'base__$cmd:id',
      'base__$cmd:whoami',
    ]);
  });

  it('fails replay-matrix validation for malformed plans', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-replay-matrix-invalid-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const planPath = path.join(dir, 'plan.invalid.json');
    await writeFile(
      planPath,
      JSON.stringify(
        {
          variations: [{ id: '' }],
          matrix: [{ propertyName: '', values: [] }],
        },
        null,
        2
      ),
      'utf8'
    );

    let threw = false;
    try {
      await execFileAsync(
        process.execPath,
        [tsxCliPath, cliPath, 'replay-matrix', '--plan', planPath, '--output', 'json'],
        { cwd: projectRoot }
      );
    } catch (error) {
      threw = true;
      const output = error as { stdout?: string };
      expect(output.stdout ?? '').toContain('Replay plan validation failed');
    }

    expect(threw).toBe(true);
  });
});
