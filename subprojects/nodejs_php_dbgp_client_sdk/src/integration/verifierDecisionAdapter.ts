import { createHash } from 'node:crypto';
import type {
  DebugReplayAttemptFailureCode,
  DebugReplayAttemptRecord,
  DebugReplayAttemptRunResult,
  DebugReplayVerifierDecisionResult,
  NormalizedDebugFrame,
  PhpTaintTraceOracleArtifactRef,
  PhpTaintTraceReplayTranscriptRef,
  PhpTaintTraceVerificationOutcome,
  PhpTaintTraceVerificationResultPayload,
  VerifierDecisionAdapterOptions,
} from './types.js';

const ADAPTER_VERSION = 'debug_verifier_adapter.v1';

export function buildPhpTaintTraceVerificationResultFromReplayAttempts(
  replay: DebugReplayAttemptRunResult,
  options: VerifierDecisionAdapterOptions = {}
): PhpTaintTraceVerificationResultPayload {
  const bundle = replay.bundle;
  const attempts = bundle.attempts;
  const candidateId = bundle.trigger.candidateId ?? 'unknown_candidate';
  const createdAt = options.createdAt ?? new Date().toISOString();
  const jobId =
    options.jobId ??
    hashJobId(
      candidateId,
      bundle.createdAt,
      bundle.template.template.name,
      bundle.trigger.correlationId ?? bundle.trigger.requestId ?? ''
    );

  const outcome = determineOutcome(attempts, bundle.finalStatus);
  const reasonCodes = buildReasonCodes(bundle, attempts, outcome);
  const artifacts = collectArtifacts(replay);
  const replayTranscripts = attempts.map((attempt) => {
    const transcript: PhpTaintTraceReplayTranscriptRef = {
      attempt: attempt.attempt,
      status: attempt.status,
      failure_code: attempt.failureCode,
      replay_variation_count: attempt.replayVariationCount,
      replay_error_count: attempt.replayErrorCount,
    };
    if (attempt.failureMessage !== undefined) {
      transcript.failure_message = attempt.failureMessage;
    }
    if (attempt.sessionId !== undefined) {
      transcript.session_id = attempt.sessionId;
    }
    if (attempt.artifacts !== undefined) {
      transcript.artifacts = attempt.artifacts;
    }
    return transcript;
  });
  const reproduction = buildReproductionContext(replay);
  const stackEvidence = buildStackEvidence(replay);

  const metadata: Record<string, unknown> = {
    adapter_version: ADAPTER_VERSION,
    trigger: bundle.trigger,
    sink_category: bundle.trigger.sinkCategory ?? null,
    sink_name: bundle.trigger.sinkName ?? null,
    request_uri: reproduction.request_uri ?? null,
    request_method: reproduction.request_method ?? null,
    template_name: bundle.template.template.name,
    template_category: bundle.template.template.categories[0] ?? 'default',
    attempts_total: attempts.length,
    max_attempts: bundle.maxAttempts,
    stop_on_first_success: bundle.stopOnFirstSuccess,
    require_replay_evidence: bundle.requireReplayEvidence,
    successful_attempt: bundle.successfulAttempt ?? null,
    final_status: bundle.finalStatus,
    failure_counts: countFailureCodes(attempts),
    replay_capture_count: replay.captures.length,
    artifact_manifest_path: replay.artifactManifestPath ?? null,
    artifact_manifest_signed: Boolean(replay.artifactManifest?.signature),
    reproduction,
    stacktrace: stackEvidence.stacktrace,
    top_frame: stackEvidence.topFrame,
    stacktrace_source: stackEvidence.source,
  };

  return {
    job_id: jobId,
    candidate_id: candidateId,
    outcome,
    reason_codes: reasonCodes,
    summary: buildSummary(candidateId, bundle, attempts, outcome),
    artifacts,
    replay_transcripts: replayTranscripts,
    created_at: createdAt,
    metadata,
  };
}

export function buildDebugReplayVerifierDecision(
  replay: DebugReplayAttemptRunResult,
  options: VerifierDecisionAdapterOptions = {}
): DebugReplayVerifierDecisionResult {
  return {
    replay,
    verificationResult: buildPhpTaintTraceVerificationResultFromReplayAttempts(
      replay,
      options
    ),
  };
}

function determineOutcome(
  attempts: DebugReplayAttemptRecord[],
  finalStatus: 'succeeded' | 'failed'
): PhpTaintTraceVerificationOutcome {
  if (finalStatus === 'succeeded' && attempts.some((entry) => entry.status === 'succeeded')) {
    return 'confirmed';
  }

  const hasBlockedAttempt = attempts.some((entry) => entry.failureCode === 'routing_aborted');
  if (hasBlockedAttempt) {
    return 'blocked_by_policy';
  }

  const hasReplayFailure = attempts.some((entry) => entry.failureCode === 'replay_failed');
  if (hasReplayFailure) {
    return 'not_confirmed';
  }

  if (attempts.length > 0 && attempts.every((entry) => isInfrastructureFailure(entry.failureCode))) {
    return 'replay_failed';
  }

  return 'inconclusive';
}

function buildReasonCodes(
  bundle: DebugReplayAttemptRunResult['bundle'],
  attempts: DebugReplayAttemptRecord[],
  outcome: PhpTaintTraceVerificationOutcome
): string[] {
  const reasonCodes = new Set<string>();
  reasonCodes.add('VERIFIER_DEBUG_REPLAY_ADAPTER_USED');
  reasonCodes.add(`VERIFIER_DEBUG_OUTCOME_${outcome.toUpperCase()}`);

  const categoryReasonCode = toCategoryReasonCode(bundle.trigger.sinkCategory);
  if (categoryReasonCode) {
    reasonCodes.add(categoryReasonCode);
  }

  if (bundle.successfulAttempt) {
    reasonCodes.add('VERIFIER_DEBUG_REPLAY_ATTEMPT_CONFIRMED');
    reasonCodes.add(`VERIFIER_DEBUG_SUCCESSFUL_ATTEMPT_${bundle.successfulAttempt}`);
  }

  for (const attempt of attempts) {
    reasonCodes.add(failureCodeToReasonCode(attempt.failureCode));
  }

  return [...reasonCodes].sort((left, right) => left.localeCompare(right));
}

function collectArtifacts(
  replay: DebugReplayAttemptRunResult
): PhpTaintTraceOracleArtifactRef[] {
  const artifacts: PhpTaintTraceOracleArtifactRef[] = [];
  const seen = new Set<string>();

  const pushArtifact = (
    type: string,
    entryPath: string | undefined,
    metadata: Record<string, unknown>
  ): void => {
    if (!entryPath) {
      return;
    }
    const key = `${type}:${entryPath}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    artifacts.push({
      type,
      path: entryPath,
      metadata,
    });
  };

  for (const attempt of replay.bundle.attempts) {
    pushArtifact('debug_evidence', attempt.artifacts?.evidencePath, { attempt: attempt.attempt });
    pushArtifact('debug_replay_results', attempt.artifacts?.replayResultsPath, {
      attempt: attempt.attempt,
    });
    pushArtifact('debug_transcript', attempt.artifacts?.transcriptPath, {
      attempt: attempt.attempt,
    });
  }

  pushArtifact('debug_attempt_manifest', replay.artifactManifestPath, {
    signed: Boolean(replay.artifactManifest?.signature),
  });

  return artifacts;
}

function buildSummary(
  candidateId: string,
  bundle: DebugReplayAttemptRunResult['bundle'],
  attempts: DebugReplayAttemptRecord[],
  outcome: PhpTaintTraceVerificationOutcome
): string {
  const failureCounts = countFailureCodes(attempts);
  const failureSummary = Object.entries(failureCounts)
    .map(([key, count]) => `${key}:${count}`)
    .join(',');
  const successfulAttempt = bundle.successfulAttempt ?? 'none';
  return [
    `DBGp verifier adapter outcome=${outcome}`,
    `candidate=${candidateId}`,
    `template=${bundle.template.template.name}`,
    `attempts=${attempts.length}/${bundle.maxAttempts}`,
    `successful_attempt=${successfulAttempt}`,
    `failure_counts=${failureSummary || 'none'}`,
  ].join('; ');
}

function countFailureCodes(
  attempts: DebugReplayAttemptRecord[]
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const attempt of attempts) {
    counts[attempt.failureCode] = (counts[attempt.failureCode] ?? 0) + 1;
  }
  return counts;
}

function hashJobId(
  candidateId: string,
  bundleCreatedAt: string,
  templateName: string,
  correlationToken: string
): string {
  return createHash('sha256')
    .update([candidateId, bundleCreatedAt, templateName, correlationToken].join('|'), 'utf8')
    .digest('hex');
}

function isInfrastructureFailure(code: DebugReplayAttemptFailureCode): boolean {
  return (
    code === 'trigger_failed' ||
    code === 'routing_timeout' ||
    code === 'session_closed' ||
    code === 'command_timeout' ||
    code === 'protocol_error' ||
    code === 'capture_failed' ||
    code === 'unknown'
  );
}

function failureCodeToReasonCode(code: DebugReplayAttemptFailureCode): string {
  return `VERIFIER_DEBUG_FAILURE_${code.toUpperCase()}`;
}

function toCategoryReasonCode(sinkCategory: string | undefined): string | undefined {
  const normalized = (sinkCategory ?? '').trim().toLowerCase();
  if (normalized === '') {
    return undefined;
  }

  return matchCategoryReasonCode(normalized);
}

function matchCategoryReasonCode(category: string): string | undefined {
  switch (category) {
    case 'rce':
      return 'CATEGORY_RCE';
    case 'sqli':
      return 'CATEGORY_SQLI';
    case 'ssrf':
      return 'CATEGORY_SSRF';
    case 'file':
      return 'CATEGORY_FILE';
    case 'xss':
      return 'CATEGORY_XSS';
    case 'idor':
      return 'CATEGORY_IDOR';
    case 'xxe':
      return 'CATEGORY_XXE';
    default:
      return undefined;
  }
}

function buildReproductionContext(
  replay: DebugReplayAttemptRunResult
): Record<string, unknown> {
  const trigger = replay.bundle.trigger;
  const triggerMetadata = asRecord(trigger.metadata);
  const requestEvidence =
    nestedRecord(triggerMetadata, ['request_evidence']) ??
    nestedRecord(triggerMetadata, ['candidate_snapshot', 'request_evidence']);
  const replayPlan =
    nestedRecord(triggerMetadata, ['replay_plan']) ??
    nestedRecord(triggerMetadata, ['candidate_snapshot', 'replay_plan']) ??
    nestedRecord(triggerMetadata, ['payload_plan']) ??
    nestedRecord(triggerMetadata, ['candidate_snapshot', 'payload_plan']);

  const payloads = replay.bundle.template.template.payloads.slice(0, 20);
  return {
    candidate_id: trigger.candidateId ?? null,
    sink_category: trigger.sinkCategory ?? null,
    sink_name: trigger.sinkName ?? null,
    request_uri:
      trigger.requestUri ??
      readString(triggerMetadata, ['request_uri']) ??
      readString(requestEvidence, ['request_uri']) ??
      null,
    request_method:
      readString(triggerMetadata, ['request_method']) ??
      readString(requestEvidence, ['request_method']) ??
      null,
    correlation_id: trigger.correlationId ?? null,
    request_id: trigger.requestId ?? null,
    finding_id: trigger.findingId ?? null,
    trace_id: trigger.traceId ?? null,
    template_name: replay.bundle.template.template.name,
    template_category: replay.bundle.template.template.categories[0] ?? null,
    mutation_target: replay.bundle.template.template.mutationTarget,
    reset_value: replay.bundle.template.template.resetValue,
    payloads,
    replay_variation_count: replay.bundle.template.replayPlan.variations.length,
    target_query_param: readString(replayPlan, ['target_query_param']) ?? null,
    target_body_param: readString(replayPlan, ['target_body_param']) ?? null,
    target_param_location: readString(replayPlan, ['target_param_location']) ?? null,
  };
}

function buildStackEvidence(
  replay: DebugReplayAttemptRunResult
): {
  stacktrace: Array<Record<string, unknown>>;
  topFrame: Record<string, unknown> | null;
  source: Record<string, unknown> | null;
} {
  const capturesWithFrames = replay.captures.filter((capture) => {
    const frames = capture.evidence.snapshot?.frames;
    return Array.isArray(frames) && frames.length > 0;
  });
  const selectedCapture = capturesWithFrames[0] ?? replay.captures[0];
  if (!selectedCapture) {
    return {
      stacktrace: [],
      topFrame: null,
      source: null,
    };
  }

  const snapshot = selectedCapture.evidence.snapshot;
  const normalizedFrames = (snapshot?.frames ?? [])
    .slice(0, 25)
    .map((frame) => normalizeFrame(frame))
    .filter((frame): frame is Record<string, unknown> => frame !== undefined);
  const topFrame = normalizeFrame(snapshot?.topFrame);
  const attemptRecord = replay.bundle.attempts.find(
    (attempt) => attempt.sessionId && attempt.sessionId === selectedCapture.sessionId
  );

  return {
    stacktrace: normalizedFrames,
    topFrame: topFrame ?? normalizedFrames[0] ?? null,
    source: {
      session_id: selectedCapture.sessionId,
      attempt: attemptRecord?.attempt ?? null,
      evidence_fingerprint: selectedCapture.evidence.fingerprint,
      snapshot_captured_at: snapshot?.capturedAt ?? null,
    },
  };
}

function normalizeFrame(frame: NormalizedDebugFrame | undefined): Record<string, unknown> | undefined {
  if (!frame) {
    return undefined;
  }

  return {
    level: frame.level,
    type: frame.type ?? null,
    file_uri: frame.fileUri ?? null,
    lineno: frame.lineno ?? null,
    where: frame.where ?? null,
  };
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function nestedRecord(
  source: Record<string, unknown> | undefined,
  path: string[]
): Record<string, unknown> | undefined {
  let cursor: unknown = source;
  for (const segment of path) {
    if (!cursor || typeof cursor !== 'object' || Array.isArray(cursor)) {
      return undefined;
    }
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return asRecord(cursor);
}

function readString(
  source: Record<string, unknown> | undefined,
  path: string[]
): string | undefined {
  let cursor: unknown = source;
  for (const segment of path) {
    if (!cursor || typeof cursor !== 'object' || Array.isArray(cursor)) {
      return undefined;
    }
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return typeof cursor === 'string' && cursor.trim() !== '' ? cursor : undefined;
}
