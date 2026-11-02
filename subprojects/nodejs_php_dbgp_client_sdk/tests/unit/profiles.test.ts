import { describe, expect, it } from 'vitest';
import { getCaptureProfileByName, getCaptureProfileForCategory } from '../../src/profiles/packs.js';

describe('capture profiles', () => {
  it('resolves by explicit name', () => {
    const profile = getCaptureProfileByName('rce');
    expect(profile.name).toBe('rce');
    expect(profile.traceSteps).toBeGreaterThan(1);
  });

  it('resolves by sink category with fallback', () => {
    const ssrf = getCaptureProfileForCategory('ssrf');
    const unknown = getCaptureProfileForCategory('nope');
    expect(ssrf.name).toBe('ssrf');
    expect(unknown.name).toBe('default');
  });
});
