import { createHash } from 'node:crypto';
import type {
  DebugProperty,
  DebugStackFrame,
  ReplayResult,
  SessionSnapshot,
  TraceResult,
  TraceStepAction,
} from '../inspector/types.js';
import type {
  DeterministicDebugEvidence,
  EvidenceNormalizationOptions,
  NormalizedDebugContext,
  NormalizedDebugFrame,
  NormalizedDebugProperty,
  NormalizedDebugSnapshot,
  NormalizedDebugTrace,
  NormalizedDebugTraceStep,
  NormalizedReplayResult,
  SinkTriggerContext,
} from './types.js';

const DEFAULT_NORMALIZATION: Required<
  Omit<EvidenceNormalizationOptions, 'redactor'>
> = {
  maxStringLength: 1024,
  maxPropertyDepth: 4,
  maxPropertiesPerContext: 128,
  includeValues: true,
};

export function buildDeterministicDebugEvidence(input: {
  trigger: SinkTriggerContext;
  init?: {
    fileUri: string;
    language: string;
    protocolVersion: string;
    engineName?: string;
    engineVersion?: string;
  };
  evaluations?: Record<string, string | undefined>;
  snapshot?: SessionSnapshot;
  trace?: TraceResult;
  replayResults?: ReplayResult[];
  normalization?: EvidenceNormalizationOptions;
}): DeterministicDebugEvidence {
  const evaluations = normalizeRecord(input.evaluations ?? {}, input.normalization, 'evaluations');
  const snapshot = input.snapshot
    ? normalizeSnapshot(input.snapshot, input.normalization)
    : undefined;
  const trace = input.trace ? normalizeTrace(input.trace, input.normalization) : undefined;
  const replay = normalizeReplayResults(input.replayResults ?? [], input.normalization);

  const payload: Omit<DeterministicDebugEvidence, 'fingerprint'> = {
    trigger: normalizeTrigger(input.trigger),
    init: input.init,
    evaluations,
    snapshot,
    trace,
    replay,
  };

  return {
    ...payload,
    fingerprint: computeFingerprint(payload),
  };
}

export function normalizeSnapshot(
  snapshot: SessionSnapshot,
  options?: EvidenceNormalizationOptions
): NormalizedDebugSnapshot {
  const normalizedFrames = normalizeFrames(snapshot.stack);
  const contexts: NormalizedDebugContext[] = [...snapshot.contexts]
    .map((entry) => ({
      id: entry.context.id,
      name: entry.context.name,
      propertyCount: (entry.properties ?? []).length,
      properties: normalizePropertyList(
        entry.properties ?? [],
        options,
        `contexts.${entry.context.id}.properties`
      ),
    }))
    .sort((left, right) => left.id - right.id);

  const output: Omit<NormalizedDebugSnapshot, 'fingerprint'> = {
    capturedAt: snapshot.capturedAt,
    status: snapshot.status.status,
    reason: snapshot.status.reason,
    topFrame: normalizedFrames[0],
    frames: normalizedFrames,
    contexts,
  };

  return {
    ...output,
    fingerprint: computeFingerprint(output),
  };
}

export function normalizeTrace(
  trace: TraceResult,
  options?: EvidenceNormalizationOptions
): NormalizedDebugTrace {
  const steps: NormalizedDebugTraceStep[] = trace.steps.map((step) => ({
    step: step.step,
    action: step.action as TraceStepAction,
    status: step.status,
    reason: step.reason,
    topFrame: step.topFrame ? normalizeFrame(step.topFrame) : undefined,
    watchValues: normalizeRecord(step.watchValues ?? {}, options, `trace.step.${step.step}.watchValues`),
    error: step.error,
  }));

  return {
    startedAt: trace.startedAt,
    finishedAt: trace.finishedAt,
    steps,
  };
}

export function normalizeReplayResults(
  results: ReplayResult[],
  options?: EvidenceNormalizationOptions
): NormalizedReplayResult[] {
  return [...results]
    .map((entry) => ({
      variationId: entry.variation.id,
      runStatus: entry.runStatus,
      driftDetected: entry.driftDetected === true,
      errors: [...entry.errors],
      resetErrors: [...(entry.resetErrors ?? [])],
      evalResults: normalizeRecord(entry.evalResults ?? {}, options, `replay.${entry.variation.id}.eval`),
    }))
    .sort((left, right) => left.variationId.localeCompare(right.variationId));
}

function normalizeFrames(frames: DebugStackFrame[]): NormalizedDebugFrame[] {
  return [...frames]
    .map((frame) => normalizeFrame(frame))
    .sort((left, right) => left.level - right.level);
}

function normalizeFrame(frame: DebugStackFrame): NormalizedDebugFrame {
  return {
    level: frame.level,
    type: frame.type,
    fileUri: frame.fileUri,
    lineno: frame.lineno,
    where: frame.where,
  };
}

function normalizePropertyList(
  properties: DebugProperty[],
  options: EvidenceNormalizationOptions | undefined,
  basePath: string,
  depth = 0
): NormalizedDebugProperty[] {
  const config = normalizeOptions(options);
  if (depth >= config.maxPropertyDepth) {
    return [];
  }

  const sorted = [...properties].sort((left, right) => {
    const leftKey = `${left.fullName ?? ''}:${left.name ?? ''}:${left.key ?? ''}`;
    const rightKey = `${right.fullName ?? ''}:${right.name ?? ''}:${right.key ?? ''}`;
    return leftKey.localeCompare(rightKey);
  });

  const limited = sorted.slice(0, config.maxPropertiesPerContext);
  return limited.map((property, index) => {
    const path = `${basePath}[${index}]`;
    const value = config.includeValues
      ? normalizeString(property.value ?? '', options, `${path}.value`)
      : undefined;
    return {
      name: property.name ?? '',
      fullName: property.fullName ?? '',
      type: property.type ?? '',
      value,
      key: property.key ?? '',
      children: normalizePropertyList(
        property.properties ?? [],
        options,
        `${path}.children`,
        depth + 1
      ),
    };
  });
}

function normalizeRecord(
  values: Record<string, string | undefined>,
  options: EvidenceNormalizationOptions | undefined,
  basePath: string
): Record<string, string | undefined> {
  const orderedEntries = Object.entries(values).sort(([left], [right]) =>
    left.localeCompare(right)
  );
  const output: Record<string, string | undefined> = {};
  for (const [key, value] of orderedEntries) {
    output[key] =
      value === undefined ? undefined : normalizeString(value, options, `${basePath}.${key}`);
  }
  return output;
}

function normalizeString(
  value: string,
  options: EvidenceNormalizationOptions | undefined,
  path: string
): string {
  const config = normalizeOptions(options);
  const redacted = options?.redactor ? options.redactor(path, value) : value;
  if (redacted.length <= config.maxStringLength) {
    return redacted;
  }
  return `${redacted.slice(0, config.maxStringLength)}...[truncated]`;
}

function normalizeTrigger(trigger: SinkTriggerContext): SinkTriggerContext {
  return {
    candidateId: trigger.candidateId,
    sinkCategory: trigger.sinkCategory,
    sinkName: trigger.sinkName,
    requestUri: trigger.requestUri,
    correlationId: trigger.correlationId,
    requestId: trigger.requestId,
    findingId: trigger.findingId,
    traceId: trigger.traceId,
    metadata: normalizeUnknownRecord(trigger.metadata ?? {}),
  };
}

function normalizeUnknownRecord(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, normalizeUnknown(entry)])
  );
}

function normalizeUnknown(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeUnknown(entry));
  }
  if (value && typeof value === 'object') {
    return normalizeUnknownRecord(value as Record<string, unknown>);
  }
  return value;
}

function normalizeOptions(
  options?: EvidenceNormalizationOptions
): Required<Omit<EvidenceNormalizationOptions, 'redactor'>> {
  return {
    maxStringLength: options?.maxStringLength ?? DEFAULT_NORMALIZATION.maxStringLength,
    maxPropertyDepth: options?.maxPropertyDepth ?? DEFAULT_NORMALIZATION.maxPropertyDepth,
    maxPropertiesPerContext:
      options?.maxPropertiesPerContext ?? DEFAULT_NORMALIZATION.maxPropertiesPerContext,
    includeValues: options?.includeValues ?? DEFAULT_NORMALIZATION.includeValues,
  };
}

function computeFingerprint(input: unknown): string {
  const hash = createHash('sha256');
  hash.update(JSON.stringify(input));
  return hash.digest('hex');
}
