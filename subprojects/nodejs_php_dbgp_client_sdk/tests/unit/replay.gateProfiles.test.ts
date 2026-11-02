import { describe, expect, it } from 'vitest';
import {
  getReplayGateProfileByName,
  getReplayGateProfileForCategory,
} from '../../src/replay/gateProfiles.js';

describe('replay gate profiles', () => {
  it('resolves explicit profile by name', () => {
    const profile = getReplayGateProfileByName('rce');
    expect(profile.name).toBe('rce');
    expect(profile.minOverallScore).toBe(0.98);
  });

  it('resolves profile by sink category with fallback', () => {
    const sqli = getReplayGateProfileForCategory('sql_injection');
    const unknown = getReplayGateProfileForCategory('unknown_sink');
    expect(sqli.name).toBe('sqli');
    expect(unknown.name).toBe('default');
  });
});
