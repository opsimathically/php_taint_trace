import { describe, expect, it } from 'vitest';
import { buildReplayDiffEntry, summarizeReplayDiffs } from '../../src/replay/diff.js';
import type { ReplayResult } from '../../src/inspector/types.js';

function makeResult(overrides: Partial<ReplayResult> = {}): ReplayResult {
  return {
    variation: { id: 'v1' },
    baselineSnapshotHash: 'aaa',
    postResetSnapshotHash: 'bbb',
    baselineEvalResults: { $cmd: 'stable' },
    driftEvalResults: { $cmd: 'id' },
    driftDetected: true,
    driftReasons: ['x'],
    evalResults: {},
    errors: [],
    ...overrides,
  };
}

describe('replay diff', () => {
  it('builds structured diff entries from replay results', () => {
    const entry = buildReplayDiffEntry(
      makeResult({
        observedExpressionDrifts: [
          { expression: '$cmd', baseline: 'stable', current: 'id', allowed: false },
        ],
        driftThresholds: {
          allowSnapshotDrift: false,
          maxExpressionDriftCount: 0,
          allowedExpressionDrift: [],
        },
      }),
      'post_reset'
    );

    expect(entry.snapshot.drifted).toBe(true);
    expect(entry.expressions).toHaveLength(1);
    expect(entry.violations).toContain('snapshot');
    expect(entry.violations).toContain('expression:$cmd');
  });

  it('summarizes total/stable/drift counts', () => {
    const summary = summarizeReplayDiffs(
      [
        makeResult({ variation: { id: 'a' }, driftDetected: false }),
        makeResult({ variation: { id: 'b' }, driftDetected: true }),
      ],
      'post_reset'
    );

    expect(summary.total).toBe(2);
    expect(summary.driftDetected).toBe(1);
    expect(summary.stable).toBe(1);
  });
});
