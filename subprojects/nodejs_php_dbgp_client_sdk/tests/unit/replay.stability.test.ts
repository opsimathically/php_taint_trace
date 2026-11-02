import { describe, expect, it } from 'vitest';
import { buildReplayStabilityReport } from '../../src/replay/stability.js';

describe('replay stability report', () => {
  it('computes overall and per-variation stability scores', () => {
    const report = buildReplayStabilityReport([
      {
        round: 1,
        results: [
          {
            variation: { id: 'a' },
            evalResults: {},
            errors: [],
            driftDetected: false,
          },
          {
            variation: { id: 'b' },
            evalResults: {},
            errors: ['x'],
            driftDetected: true,
          },
        ],
      },
      {
        round: 2,
        results: [
          {
            variation: { id: 'a' },
            evalResults: {},
            errors: [],
            driftDetected: false,
          },
          {
            variation: { id: 'b' },
            evalResults: {},
            errors: [],
            driftDetected: false,
          },
        ],
      },
    ]);

    expect(report.rounds).toBe(2);
    expect(report.totalSamples).toBe(4);
    const a = report.variationScores.find((item) => item.variationId === 'a');
    const b = report.variationScores.find((item) => item.variationId === 'b');
    expect(a?.stabilityScore).toBe(1);
    expect(b?.stabilityScore).toBe(0.5);
    expect(report.overallStabilityScore).toBe(0.75);
  });
});
