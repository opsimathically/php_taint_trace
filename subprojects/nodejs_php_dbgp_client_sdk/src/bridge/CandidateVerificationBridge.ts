import path from 'node:path';
import { mkdir, readFile } from 'node:fs/promises';
import { PhpDebugInspector } from '../inspector/PhpDebugInspector.js';
import { getPolicyPackByName, getPolicyPackForCategory } from '../policies/packs.js';
import { resolveCandidateTriggerCommand } from '../plugins/triggerResolver.js';
import { getCaptureProfileByName, getCaptureProfileForCategory } from '../profiles/packs.js';
import type { DbgpServer } from '../server/DbgpServer.js';
import { TranscriptArtifactStore } from '../transcript/TranscriptArtifactStore.js';
import type {
  CandidateBridgeOptions,
  CandidateBridgeRunResult,
  CandidateRecord,
  CandidateTrigger,
} from './types.js';

export class CandidateVerificationBridge {
  private readonly server: DbgpServer;
  private readonly options: Omit<Required<CandidateBridgeOptions>, 'transcriptRedaction'> & {
    transcriptRedaction?: CandidateBridgeOptions['transcriptRedaction'];
  };
  private readonly transcriptStore = new TranscriptArtifactStore();

  constructor(server: DbgpServer, options: CandidateBridgeOptions) {
    this.server = server;
    this.options = {
      commandTimeoutMs: options.commandTimeoutMs ?? 7000,
      strict: options.strict ?? true,
      maxChildren: options.maxChildren ?? 64,
      maxData: options.maxData ?? 8192,
      sessionTimeoutMs: options.sessionTimeoutMs ?? 30000,
      artifactsDir: options.artifactsDir,
      traceSteps: options.traceSteps ?? 0,
      watchExpressions: options.watchExpressions ?? [],
      snapshotContextIds: options.snapshotContextIds ?? [],
      policyPackName: options.policyPackName ?? 'default',
      policyPackByCategory: options.policyPackByCategory ?? true,
      captureProfileName: options.captureProfileName ?? 'default',
      captureProfileByCategory: options.captureProfileByCategory ?? true,
      transcriptRedaction: options.transcriptRedaction,
      triggerResolverPlugins: options.triggerResolverPlugins ?? [],
    };
  }

  static async loadCandidatesFromJsonl(candidateJsonlPath: string): Promise<CandidateRecord[]> {
    const raw = await readFile(candidateJsonlPath, 'utf8');
    const records: CandidateRecord[] = [];
    const lines = raw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '');

    for (const line of lines) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line) as unknown;
      } catch {
        continue;
      }

      const flattened = flattenCandidateObjects(parsed);
      for (const value of flattened) {
        const normalized = normalizeCandidate(value);
        if (normalized) {
          records.push(normalized);
        }
      }
    }

    return records;
  }

  async runCandidates(
    candidates: CandidateRecord[],
    trigger: CandidateTrigger
  ): Promise<CandidateBridgeRunResult[]> {
    await mkdir(this.options.artifactsDir, { recursive: true });
    const results: CandidateBridgeRunResult[] = [];

    for (const [index, candidate] of candidates.entries()) {
      const correlationId = candidate.correlationId ?? candidate.candidateId;
      const requestId = candidate.requestId;
      const findingId = candidate.findingId;
      const policy = this.resolvePolicyForCandidate(candidate);
      const captureProfile = this.resolveCaptureProfileForCandidate(candidate);
      const traceSteps =
        this.options.traceSteps > 0
          ? this.options.traceSteps
          : (captureProfile.traceSteps > 0 ? captureProfile.traceSteps : policy.traceSteps);
      const watchExpressions =
        this.options.watchExpressions.length > 0
          ? this.options.watchExpressions
          : (captureProfile.watchExpressions.length > 0
            ? captureProfile.watchExpressions
            : policy.watchExpressions);
      const snapshotContextIds =
        this.options.snapshotContextIds.length > 0
          ? this.options.snapshotContextIds
          : (captureProfile.snapshotContextIds.length > 0
            ? captureProfile.snapshotContextIds
            : policy.snapshotContextIds);

      const waitSession = this.server.waitForNextSession(this.options.sessionTimeoutMs);
      await trigger(candidate, index);
      const session = await waitSession;
      await session.waitForInit(this.options.commandTimeoutMs);
      const inspector = new PhpDebugInspector(session, this.options);

      const errors: string[] = [];
      let snapshot = undefined;
      let trace = undefined;

      try {
        const status = await inspector.status();
        if (status.status === 'starting') {
          await inspector.stepInto();
        }

        snapshot = await inspector.captureSnapshot(snapshotContextIds);
        trace = await inspector.traceExecution({
          steps: traceSteps,
          action: captureProfile.traceAction,
          watchExpressions,
          stopOnStatuses: captureProfile.stopOnStatuses,
        });
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
      }

      const correlationSafe = (correlationId ?? requestId ?? findingId ?? candidate.candidateId).replace(
          /[^A-Za-z0-9._-]/gu,
          '_'
        );
      const safeId = candidate.candidateId.replace(/[^A-Za-z0-9._-]/gu, '_');
      const artifactPath = path.join(
        this.options.artifactsDir,
        `${safeId}.${correlationSafe}.${session.id}.transcript.json`
      );
      await this.transcriptStore.persistSession(session, artifactPath, {
        redaction: this.options.transcriptRedaction,
        metadata: {
          candidateId: candidate.candidateId,
          correlationId: correlationId ?? '',
          requestId: requestId ?? '',
          findingId: findingId ?? '',
          traceId: candidate.traceId ?? '',
          sinkCategory: candidate.sinkCategory ?? '',
          sinkName: candidate.sinkName ?? '',
          requestUri: candidate.requestUri ?? '',
          policyPack: policy.name,
          captureProfile: captureProfile.name,
        },
      });

      results.push({
        candidateId: candidate.candidateId,
        correlationId,
        requestId,
        findingId,
        appliedPolicyPack: policy,
        appliedCaptureProfile: captureProfile,
        sessionId: session.id,
        artifactPath,
        snapshot,
        trace,
        errors,
      });

      session.close();
      await waitForNoSessions(this.server, this.options.sessionTimeoutMs);
    }

    return results;
  }

  async runCandidatesWithTemplateTrigger(
    candidates: CandidateRecord[],
    template: string,
    executeCommand: (command: string, candidate: CandidateRecord, index: number) => Promise<void> | void
  ): Promise<CandidateBridgeRunResult[]> {
    return this.runCandidates(candidates, async (candidate, index) => {
      const command = resolveCandidateTriggerCommand(
        template,
        candidate,
        this.options.triggerResolverPlugins
      );
      await executeCommand(command, candidate, index);
    });
  }

  private resolvePolicyForCandidate(candidate: CandidateRecord) {
    if (this.options.policyPackByCategory) {
      return getPolicyPackForCategory(candidate.sinkCategory);
    }

    return getPolicyPackByName(this.options.policyPackName);
  }

  private resolveCaptureProfileForCandidate(candidate: CandidateRecord) {
    if (this.options.captureProfileByCategory) {
      return getCaptureProfileForCategory(candidate.sinkCategory);
    }

    return getCaptureProfileByName(this.options.captureProfileName);
  }
}

function flattenCandidateObjects(input: unknown): Record<string, unknown>[] {
  if (!input || typeof input !== 'object') {
    return [];
  }

  const object = input as Record<string, unknown>;
  const output: Record<string, unknown>[] = [];
  const envelope = extractEnvelopeCorrelation(object);

  if (Array.isArray(object.candidates)) {
    for (const candidate of object.candidates) {
      if (candidate && typeof candidate === 'object') {
        output.push({
          ...envelope,
          ...(candidate as Record<string, unknown>),
        });
      }
    }
  }

  if (object.candidate && typeof object.candidate === 'object') {
    output.push({
      ...envelope,
      ...(object.candidate as Record<string, unknown>),
    });
  }

  if (isLikelyCandidateObject(object)) {
    output.push(object);
  }

  return output;
}

function extractEnvelopeCorrelation(object: Record<string, unknown>): Record<string, unknown> {
  const envelope: Record<string, unknown> = {};
  for (const key of [
    'request_uri',
    'requestUri',
    'request_method',
    'requestMethod',
    'request_id',
    'requestId',
    'finding_id',
    'findingId',
    'trace_id',
    'traceId',
    'correlation_id',
    'correlationId',
  ]) {
    if (Object.prototype.hasOwnProperty.call(object, key)) {
      envelope[key] = object[key];
    }
  }

  return envelope;
}

function normalizeCandidate(input: Record<string, unknown>): CandidateRecord | undefined {
  const candidateId =
    stringOrUndefined(input.candidate_id) ??
    stringOrUndefined(input.candidateId) ??
    stringOrUndefined(input.id);
  if (!candidateId) {
    return undefined;
  }

  return {
    candidateId,
    sinkCategory:
      stringOrUndefined(input.sink_category) ??
      stringOrUndefined(input.sinkCategory) ??
      stringOrUndefined(input.category) ??
      nestedString(input, [['sink_evidence', 'sink_category'], ['candidate_snapshot', 'sink_category']]),
    sinkName:
      stringOrUndefined(input.sink_name) ??
      stringOrUndefined(input.sinkName) ??
      nestedString(input, [['sink_evidence', 'sink_name'], ['candidate_snapshot', 'sink_name']]),
    requestUri:
      stringOrUndefined(input.request_uri) ??
      stringOrUndefined(input.requestUri) ??
      nestedString(input, [
        ['request_evidence', 'request_uri'],
        ['candidate_snapshot', 'request_evidence', 'request_uri'],
      ]),
    detector: stringOrUndefined(input.detector),
    correlationId:
      stringOrUndefined(input.correlation_id) ??
      stringOrUndefined(input.correlationId) ??
      stringOrUndefined(input.trace_id) ??
      stringOrUndefined(input.traceId) ??
      candidateId,
    requestId: stringOrUndefined(input.request_id) ?? stringOrUndefined(input.requestId),
    findingId: stringOrUndefined(input.finding_id) ?? stringOrUndefined(input.findingId),
    traceId: stringOrUndefined(input.trace_id) ?? stringOrUndefined(input.traceId),
    metadata: input,
  };
}

function isLikelyCandidateObject(value: Record<string, unknown>): boolean {
  return Boolean(value.candidate_id || value.candidateId || value.id) && Boolean(value.sink_category || value.sinkCategory || value.category || value.sink_name || value.sinkName);
}

function stringOrUndefined(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

function nestedString(
  source: Record<string, unknown>,
  paths: string[][]
): string | undefined {
  for (const path of paths) {
    const value = readAtPath(source, path);
    const normalized = stringOrUndefined(value);
    if (normalized) {
      return normalized;
    }
  }
  return undefined;
}

function readAtPath(source: Record<string, unknown>, path: string[]): unknown {
  let cursor: unknown = source;
  for (const key of path) {
    if (!cursor || typeof cursor !== 'object') {
      return undefined;
    }
    cursor = (cursor as Record<string, unknown>)[key];
  }
  return cursor;
}

async function waitForNoSessions(server: DbgpServer, timeoutMs: number): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (server.getSessions().length === 0) {
      return;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
  }
}
