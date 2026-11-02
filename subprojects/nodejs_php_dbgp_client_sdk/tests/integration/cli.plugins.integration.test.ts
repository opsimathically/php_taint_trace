import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const thisFile = fileURLToPath(import.meta.url);
const projectRoot = path.resolve(path.dirname(thisFile), '../..');
const tsxCliPath = path.resolve(projectRoot, 'node_modules/tsx/dist/cli.mjs');
const cliPath = path.resolve(projectRoot, 'src/cli.ts');

describe('CLI plugin loading', () => {
  it('loads trigger resolver plugin module for resolve-trigger command', async () => {
    const pluginPath = path.resolve(
      projectRoot,
      'tests/fixtures/plugins/valid-trigger-plugin.ts'
    );
    const result = await execFileAsync(
      process.execPath,
      [tsxCliPath, cliPath, 'resolve-trigger', '--template', 'curl ${candidateId}', '--candidate-id', 'cand-1', '--trigger-resolver-plugin', pluginPath],
      { cwd: projectRoot }
    );

    expect(result.stdout).toContain("plugin-resolved");
  });

  it('fails fast when plugin export contract is invalid', async () => {
    const pluginPath = path.resolve(projectRoot, 'tests/fixtures/plugins/invalid-plugin.ts');
    let threw = false;
    try {
      await execFileAsync(
        process.execPath,
        [tsxCliPath, cliPath, 'resolve-trigger', '--template', 'curl ${candidateId}', '--candidate-id', 'cand-1', '--trigger-resolver-plugin', pluginPath],
        { cwd: projectRoot }
      );
    } catch (error) {
      threw = true;
      const output = error as { stdout?: string; stderr?: string };
      expect(output.stdout ?? '').toContain('No CandidateTriggerResolverPlugin export found');
    }

    expect(threw).toBe(true);
  });
});
