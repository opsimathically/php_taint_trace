import type { ReplayResult } from '../inspector/types.js';

export interface ReplayDiffExpression {
  expression: string;
  baseline?: string;
  current?: string;
  drifted: boolean;
  allowed: boolean;
}

export interface ReplayDiffEntry {
  variationId: string;
  comparePhase: 'pre' | 'post' | 'post_reset';
  runStatus?: string;
  snapshot: {
    baselineHash?: string;
    compareHash?: string;
    drifted: boolean;
    allowed: boolean;
  };
  expressions: ReplayDiffExpression[];
  violations: string[];
  driftDetected: boolean;
}

export interface ReplayDiffSummary {
  total: number;
  driftDetected: number;
  stable: number;
  entries: ReplayDiffEntry[];
}

export function buildReplayDiffEntry(
  result: ReplayResult,
  comparePhase: 'pre' | 'post' | 'post_reset' = 'post_reset'
): ReplayDiffEntry {
  const compareHash = selectCompareHash(result, comparePhase);
  const baselineHash = result.baselineSnapshotHash;
  const snapshotDrift = Boolean(baselineHash && compareHash && baselineHash !== compareHash);
  const snapshotAllowed = result.driftThresholds?.allowSnapshotDrift ?? false;

  const expressions = buildExpressionDiff(result);
  const violations: string[] = [];

  if (snapshotDrift && !snapshotAllowed) {
    violations.push('snapshot');
  }
  for (const expression of expressions) {
    if (expression.drifted && !expression.allowed) {
      violations.push(`expression:${expression.expression}`);
    }
  }

  const maxExpressionDriftCount = result.driftThresholds?.maxExpressionDriftCount ?? 0;
  const violatingExpressionCount = expressions.filter(
    (expression) => expression.drifted && !expression.allowed
  ).length;
  const thresholdViolation = violatingExpressionCount > maxExpressionDriftCount;
  const detected = result.driftDetected ?? (thresholdViolation || (snapshotDrift && !snapshotAllowed));

  const snapshotPayload: {
    baselineHash?: string;
    compareHash?: string;
    drifted: boolean;
    allowed: boolean;
  } = {
    drifted: snapshotDrift,
    allowed: snapshotAllowed,
  };
  if (typeof baselineHash === 'string') {
    snapshotPayload.baselineHash = baselineHash;
  }
  if (typeof compareHash === 'string') {
    snapshotPayload.compareHash = compareHash;
  }

  return {
    variationId: result.variation.id,
    comparePhase,
    runStatus: result.runStatus,
    snapshot: snapshotPayload,
    expressions,
    violations: thresholdViolation ? violations : violations.filter((item) => item === 'snapshot'),
    driftDetected: detected,
  };
}

export function summarizeReplayDiffs(
  results: ReadonlyArray<ReplayResult>,
  comparePhase: 'pre' | 'post' | 'post_reset' = 'post_reset'
): ReplayDiffSummary {
  const entries = results.map((result) => buildReplayDiffEntry(result, comparePhase));
  const driftDetected = entries.filter((entry) => entry.driftDetected).length;
  return {
    total: entries.length,
    driftDetected,
    stable: entries.length - driftDetected,
    entries,
  };
}

function selectCompareHash(
  result: ReplayResult,
  comparePhase: 'pre' | 'post' | 'post_reset'
): string | undefined {
  if (comparePhase === 'pre') {
    return result.preSnapshotHash ?? result.baselineSnapshotHash;
  }
  if (comparePhase === 'post') {
    return result.postSnapshotHash ?? result.preSnapshotHash ?? result.baselineSnapshotHash;
  }
  return (
    result.postResetSnapshotHash ??
    result.postSnapshotHash ??
    result.preSnapshotHash ??
    result.baselineSnapshotHash
  );
}

function buildExpressionDiff(result: ReplayResult): ReplayDiffExpression[] {
  if (result.observedExpressionDrifts && result.observedExpressionDrifts.length > 0) {
    return result.observedExpressionDrifts.map((entry) => ({
      expression: entry.expression,
      ...(entry.baseline !== undefined ? { baseline: entry.baseline } : {}),
      ...(entry.current !== undefined ? { current: entry.current } : {}),
      drifted: entry.baseline !== entry.current,
      allowed: entry.allowed,
    }));
  }

  const expressions = new Set<string>([
    ...Object.keys(result.baselineEvalResults ?? {}),
    ...Object.keys(result.driftEvalResults ?? {}),
  ]);
  return [...expressions].map((expression) => {
    const baseline = result.baselineEvalResults?.[expression];
    const current = result.driftEvalResults?.[expression];
    return {
      expression,
      ...(baseline !== undefined ? { baseline } : {}),
      ...(current !== undefined ? { current } : {}),
      drifted: baseline !== current,
      allowed: false,
    };
  });
}
