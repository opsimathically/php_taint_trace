import { describe, expect, it } from 'vitest';
import { buildDeterministicDebugEvidence, normalizeSnapshot } from '../../src/integration/evidence.js';
import type { SessionSnapshot } from '../../src/inspector/types.js';

function buildSnapshotWithOrder(reverse = false): SessionSnapshot {
  const baseProperties = [
    {
      name: '$z',
      fullName: '$z',
      type: 'string',
      value: 'zzz',
    },
    {
      name: '$a',
      fullName: '$a',
      type: 'string',
      value: 'aaaaaaaaaaaa',
    },
  ];
  const contexts = [
    {
      context: { id: 1, name: 'Superglobals' },
      properties: reverse ? [...baseProperties] : [...baseProperties].reverse(),
    },
    {
      context: { id: 0, name: 'Locals' },
      properties: reverse ? [...baseProperties].reverse() : [...baseProperties],
    },
  ];

  return {
    capturedAt: '2026-04-24T00:00:00Z',
    init: {
      appId: '900',
      language: 'PHP',
      protocolVersion: '1.0',
      fileUri: 'file:///tmp/demo.php',
      rawXml: '<init />',
      innerXml: '',
      attributes: {},
    },
    status: {
      transactionId: 1,
      status: 'break',
      reason: 'ok',
      rawXml: '<response />',
      innerXml: '',
      attributes: {},
    },
    stack: [
      { level: 1, fileUri: 'file:///tmp/demo.php', lineno: 20, where: 'foo' },
      { level: 0, fileUri: 'file:///tmp/demo.php', lineno: 10, where: 'main' },
    ],
    contexts,
  };
}

describe('integration evidence normalizer', () => {
  it('produces deterministic snapshot fingerprint independent of ordering', () => {
    const one = normalizeSnapshot(buildSnapshotWithOrder(false));
    const two = normalizeSnapshot(buildSnapshotWithOrder(true));

    expect(one.fingerprint).toBe(two.fingerprint);
    expect(one.contexts[0]?.id).toBe(0);
    expect(one.contexts[0]?.properties[0]?.fullName).toBe('$a');
    expect(one.frames[0]?.level).toBe(0);
  });

  it('applies truncation and redaction in deterministic evidence payload', () => {
    const evidence = buildDeterministicDebugEvidence({
      trigger: {
        candidateId: 'cand-1',
        sinkCategory: 'rce',
      },
      evaluations: {
        '$cmd': 'whoami',
      },
      snapshot: buildSnapshotWithOrder(false),
      normalization: {
        maxStringLength: 5,
        redactor: (path, value) => (path.includes('$cmd') ? '[REDACTED]' : value),
      },
    });

    expect(evidence.evaluations['$cmd']).toBe('[REDA...[truncated]');
    expect(evidence.snapshot?.contexts[0]?.properties[0]?.value).toBe('aaaaa...[truncated]');
    expect(typeof evidence.fingerprint).toBe('string');
    expect(evidence.fingerprint.length).toBe(64);
  });
});
