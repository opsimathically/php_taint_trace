import { describe, expect, it } from 'vitest';
import { buildCommandLine } from '../../src/protocol/command.js';

describe('buildCommandLine', () => {
  it('builds deterministic command line with sorted options', () => {
    const command = buildCommandLine('stack_get', 9, { d: 0, m: 4096 });
    expect(command).toBe('stack_get -i 9 -d 0 -m 4096');
  });

  it('appends base64 encoded payload when data exists', () => {
    const command = buildCommandLine('eval', 4, {}, '$a + 1');
    expect(command).toMatch(/^eval -i 4 -- /u);
    expect(command.endsWith(Buffer.from('$a + 1', 'utf8').toString('base64'))).toBe(true);
  });
});
