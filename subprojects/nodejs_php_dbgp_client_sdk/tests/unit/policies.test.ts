import { describe, expect, it } from 'vitest';
import { getPolicyPackByName, getPolicyPackForCategory } from '../../src/policies/packs.js';

describe('policy packs', () => {
  it('resolves by explicit name', () => {
    const pack = getPolicyPackByName('rce');
    expect(pack.name).toBe('rce');
    expect(pack.watchExpressions).toContain('$cmd');
  });

  it('resolves by sink category with fallback', () => {
    const sqli = getPolicyPackForCategory('sqli');
    const unknown = getPolicyPackForCategory('nope');
    expect(sqli.name).toBe('sqli');
    expect(unknown.name).toBe('default');
  });
});
