import type { ReplayResult } from '../inspector/types.js';

export interface ReplayStabilitySample {
  round: number;
  variationId: string;
  driftDetected: boolean;
  errorCount: number;
  resetErrorCount: number;
}

export interface ReplayVariationStability {
  variationId: string;
  samples: number;
  stableSamples: number;
  driftSamples: number;
  errorSamples: number;
  stabilityScore: number;
}

export interface ReplayStabilityReport {
  rounds: number;
  totalSamples: number;
  overallStabilityScore: number;
  variationScores: ReplayVariationStability[];
}

export function buildReplayStabilityReport(
  rounds: Array<{
    round: number;
    results: ReplayResult[];
  }>
): ReplayStabilityReport {
  const samples: ReplayStabilitySample[] = [];
  for (const round of rounds) {
    for (const result of round.results) {
      samples.push({
        round: round.round,
        variationId: result.variation.id,
        driftDetected: Boolean(result.driftDetected),
        errorCount: result.errors.length,
        resetErrorCount: result.resetErrors?.length ?? 0,
      });
    }
  }

  const byVariation = new Map<string, ReplayStabilitySample[]>();
  for (const sample of samples) {
    const list = byVariation.get(sample.variationId) ?? [];
    list.push(sample);
    byVariation.set(sample.variationId, list);
  }

  const variationScores: ReplayVariationStability[] = [];
  for (const [variationId, entries] of byVariation.entries()) {
    const stableSamples = entries.filter(
      (entry) => !entry.driftDetected && entry.errorCount === 0 && entry.resetErrorCount === 0
    ).length;
    const driftSamples = entries.filter((entry) => entry.driftDetected).length;
    const errorSamples = entries.filter(
      (entry) => entry.errorCount > 0 || entry.resetErrorCount > 0
    ).length;
    const samplesCount = entries.length;

    variationScores.push({
      variationId,
      samples: samplesCount,
      stableSamples,
      driftSamples,
      errorSamples,
      stabilityScore: samplesCount === 0 ? 0 : stableSamples / samplesCount,
    });
  }

  variationScores.sort((left, right) => left.variationId.localeCompare(right.variationId));

  const totalSamples = samples.length;
  const stableSamples = variationScores.reduce((carry, item) => carry + item.stableSamples, 0);
  return {
    rounds: rounds.length,
    totalSamples,
    overallStabilityScore: totalSamples === 0 ? 0 : stableSamples / totalSamples,
    variationScores,
  };
}
