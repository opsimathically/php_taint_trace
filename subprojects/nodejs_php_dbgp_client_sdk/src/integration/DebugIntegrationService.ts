import { DbgpProtocolError } from '../core/DbgpProtocolError.js';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { PhpDebugInspector } from '../inspector/PhpDebugInspector.js';
import type { ReplayResult, TraceStepAction } from '../inspector/types.js';
import {
  createReplayArtifactManifest,
  type ReplayArtifactManifest,
  type ReplayManifestEntryInput,
} from '../replay/manifest.js';
import type { DbgpServer } from '../server/DbgpServer.js';
import { buildDeterministicDebugEvidence } from './evidence.js';
import { DebugSessionRouter } from './DebugSessionRouter.js';
import { resolveDebugReplayTemplate } from './replayTemplates.js';
import { buildDebugReplayVerifierDecision } from './verifierDecisionAdapter.js';
import type {
  DebugIntegrationCaptureRequest,
  DebugIntegrationCaptureResult,
  DebugReplayAttemptBundle,
  DebugReplayAttemptFailureCode,
  DebugReplayAttemptRecord,
  DebugReplayAttemptRunRequest,
  DebugReplayAttemptRunResult,
  DebugReplayAttemptTrigger,
  DebugReplayVerifierDecisionResult,
  DebugIntegrationServiceOptions,
  DebugIntegrationTemplateCaptureRequest,
  DebugIntegrationTemplateCaptureResult,
  DebugIntegrationTrigger,
  DebugSessionLease,
} from './types.js';

export class DebugIntegrationService {
  private readonly server: DbgpServer;
  private readonly options: Required<DebugIntegrationServiceOptions>;
  private readonly sessionRouter: DebugSessionRouter;

  constructor(server: DbgpServer, options: DebugIntegrationServiceOptions = {}) {
    this.server = server;
    this.options = {
      commandTimeoutMs: options.commandTimeoutMs ?? 5000,
      strict: options.strict ?? true,
      maxChildren: options.maxChildren ?? 64,
      maxData: options.maxData ?? 8192,
      sessionTimeoutMs: options.sessionTimeoutMs ?? 30000,
      primeAction: options.primeAction ?? 'step_into',
      snapshotContextIds: options.snapshotContextIds ?? [0],
      normalization: options.normalization ?? {},
      routing: options.routing ?? {},
    };
    this.sessionRouter = new DebugSessionRouter(server, this.options.routing);
  }

  async runReplayAttemptsAsVerifierDecision(
    request: DebugReplayAttemptRunRequest,
    trigger?: DebugReplayAttemptTrigger
  ): Promise<DebugReplayVerifierDecisionResult> {
    const replay = await this.runReplayAttempts(request, trigger);
    return buildDebugReplayVerifierDecision(replay);
  }

  async captureForTrigger(
    request: DebugIntegrationCaptureRequest,
    trigger?: DebugIntegrationTrigger
  ): Promise<DebugIntegrationCaptureResult> {
    const sessionTimeoutMs = request.sessionTimeoutMs ?? this.options.sessionTimeoutMs;
    const routingOptions = request.routing ?? this.options.routing;
    const maxRecoveryAttempts = routingOptions.maxRecoveryAttempts ?? 1;
    const leasePromise = this.sessionRouter.acquire({
      trigger: request.trigger,
      timeoutMs: sessionTimeoutMs,
      commandTimeoutMs: request.commandTimeoutMs ?? this.options.commandTimeoutMs,
      abortSignal: request.abortSignal,
      ...routingOptions,
    });
    if (trigger) {
      await trigger(request.trigger);
    }

    const errors: string[] = [];
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= maxRecoveryAttempts; attempt += 1) {
      let lease: DebugSessionLease | undefined;
      try {
        lease = attempt === 0
          ? await leasePromise
          : await this.sessionRouter.acquire({
              trigger: request.trigger,
              timeoutMs: sessionTimeoutMs,
              commandTimeoutMs: request.commandTimeoutMs ?? this.options.commandTimeoutMs,
              abortSignal: request.abortSignal,
              ...routingOptions,
            });
        return await this.captureWithSessionLease(request, lease, errors);
      } catch (error) {
        const normalized = error instanceof Error ? error : new Error(String(error));
        lastError = normalized;
        errors.push(normalized.message);
        if (!this.isRecoverableSessionError(normalized) || attempt >= maxRecoveryAttempts) {
          break;
        }
      } finally {
        if (lease) {
          lease.release();
          if (request.closeSession ?? true) {
            lease.session.close();
            await this.waitForSessionDrain(sessionTimeoutMs);
          }
        }
      }
    }

    throw lastError ?? new Error('Debug integration capture failed.');
  }

  async captureWithReplayTemplate(
    request: DebugIntegrationTemplateCaptureRequest,
    trigger?: DebugIntegrationTrigger
  ): Promise<DebugIntegrationTemplateCaptureResult> {
    const resolved = resolveDebugReplayTemplate(request.trigger, request.template);
    const capture = await this.captureForTrigger(
      {
        ...request,
        primeAction: request.primeAction ?? resolved.primeAction,
        snapshotContextIds: request.snapshotContextIds ?? resolved.snapshotContextIds,
        evaluateExpressions:
          request.evaluateExpressions && request.evaluateExpressions.length > 0
            ? request.evaluateExpressions
            : resolved.evaluateExpressions,
        tracePlan: request.tracePlan ?? resolved.tracePlan,
        replayPlan: request.replayPlan ?? resolved.replayPlan,
      },
      trigger
    );

    return {
      ...capture,
      template: resolved,
    };
  }

  async runReplayAttempts(
    request: DebugReplayAttemptRunRequest,
    trigger?: DebugReplayAttemptTrigger
  ): Promise<DebugReplayAttemptRunResult> {
    const maxAttempts = Math.max(1, Math.floor(request.attempts ?? 3));
    const stopOnFirstSuccess = request.stopOnFirstSuccess ?? true;
    const requireReplayEvidence = request.requireReplayEvidence ?? true;
    const resolvedTemplate = resolveDebugReplayTemplate(request.trigger, request.template);
    const createdAt = new Date().toISOString();
    const captures: DebugIntegrationTemplateCaptureResult[] = [];
    const attempts: DebugReplayAttemptRecord[] = [];
    const emittedArtifacts: ReplayManifestEntryInput[] = [];

    if (request.artifactDir) {
      await mkdir(request.artifactDir, { recursive: true });
    }

    for (let index = 0; index < maxAttempts; index += 1) {
      const attemptNumber = index + 1;
      const startedAt = new Date().toISOString();
      let finishedAt = startedAt;

      try {
        const capture = await this.captureForTrigger({
          ...request,
          primeAction: request.primeAction ?? resolvedTemplate.primeAction,
          snapshotContextIds: request.snapshotContextIds ?? resolvedTemplate.snapshotContextIds,
          evaluateExpressions:
            request.evaluateExpressions && request.evaluateExpressions.length > 0
              ? request.evaluateExpressions
              : resolvedTemplate.evaluateExpressions,
          tracePlan: request.tracePlan ?? resolvedTemplate.tracePlan,
          replayPlan: request.replayPlan ?? resolvedTemplate.replayPlan,
        },
        trigger
          ? async (resolvedTrigger) => {
              try {
                await trigger(resolvedTrigger, index);
              } catch (error) {
                throw new DebugTriggerError(
                  error instanceof Error ? error.message : String(error)
                );
              }
            }
          : undefined);
        finishedAt = new Date().toISOString();
        const replayErrorCount = countReplayErrors(capture.raw.replayResults);
        const replayVariationCount = capture.raw.replayResults.length;
        const hasReplayEvidence = replayVariationCount > 0;
        const hasReplayErrors = replayErrorCount > 0;
        const attemptSucceeded =
          (!requireReplayEvidence || hasReplayEvidence) &&
          !hasReplayErrors;

        const typedCapture: DebugIntegrationTemplateCaptureResult = {
          ...capture,
          template: resolvedTemplate,
        };
        captures.push(typedCapture);

        const artifacts = await this.persistAttemptArtifacts(
          request,
          typedCapture,
          attemptNumber,
          emittedArtifacts
        );

        attempts.push({
          attempt: attemptNumber,
          startedAt,
          finishedAt,
          status: attemptSucceeded ? 'succeeded' : 'failed',
          failureCode: attemptSucceeded ? 'none' : 'replay_failed',
          failureMessage: attemptSucceeded
            ? undefined
            : (hasReplayEvidence
                ? 'Replay evidence contains errors.'
                : 'Replay evidence was not produced.'),
          sessionId: typedCapture.sessionId,
          evidenceFingerprint: typedCapture.evidence.fingerprint,
          replayVariationCount,
          replayErrorCount,
          artifacts,
        });

        if (attemptSucceeded && stopOnFirstSuccess) {
          break;
        }
      } catch (error) {
        finishedAt = new Date().toISOString();
        const normalized = error instanceof Error ? error : new Error(String(error));
        const failureCode = classifyAttemptFailure(normalized);
        attempts.push({
          attempt: attemptNumber,
          startedAt,
          finishedAt,
          status: 'failed',
          failureCode,
          failureMessage: normalized.message,
          replayVariationCount: 0,
          replayErrorCount: 0,
        });
        if (failureCode === 'routing_aborted') {
          break;
        }
      }
    }

    const successfulAttempt = attempts.find((entry) => entry.status === 'succeeded')?.attempt;
    const finalStatus = successfulAttempt ? 'succeeded' : 'failed';
    const bundle: DebugReplayAttemptBundle = {
      schemaVersion: 'dbgp-replay-attempts.v1',
      createdAt,
      trigger: request.trigger,
      template: resolvedTemplate,
      maxAttempts,
      stopOnFirstSuccess,
      requireReplayEvidence,
      attempts,
      finalStatus,
      successfulAttempt,
    };

    let artifactManifestPath: string | undefined;
    let artifactManifest: ReplayArtifactManifest | undefined;
    if (request.artifactDir) {
      const bundlePath = path.join(request.artifactDir, 'replay-attempts.bundle.json');
      await writeJsonFile(bundlePath, bundle);
      emittedArtifacts.push({ kind: 'replay_attempt_bundle', path: bundlePath });

      artifactManifestPath =
        request.artifactManifestPath ??
        path.join(request.artifactDir, 'replay-attempts.manifest.json');
      artifactManifest = createReplayArtifactManifest(emittedArtifacts, {
        baseDir: path.dirname(path.resolve(artifactManifestPath)),
        signature: request.manifestSignature,
      });
      await writeJsonFile(artifactManifestPath, artifactManifest);
    }

    return {
      bundle,
      captures,
      artifactManifestPath: artifactManifestPath ? path.resolve(artifactManifestPath) : undefined,
      artifactManifest,
    };
  }

  private async applyPrimeAction(
    inspector: PhpDebugInspector,
    action: TraceStepAction
  ): Promise<void> {
    switch (action) {
      case 'run':
        await inspector.run();
        break;
      case 'step_out':
        await inspector.stepOut();
        break;
      case 'step_over':
        await inspector.stepOver();
        break;
      case 'step_into':
      default:
        await inspector.stepInto();
        break;
    }
  }

  private async waitForSessionDrain(timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.server.getSessions().length === 0) {
        return;
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 25));
    }
  }

  private async captureWithSessionLease(
    request: DebugIntegrationCaptureRequest,
    lease: DebugSessionLease,
    errors: string[]
  ): Promise<DebugIntegrationCaptureResult> {
    const session = lease.session;
    const init = lease.init ?? await session.waitForInit(this.options.commandTimeoutMs);
    const inspector = new PhpDebugInspector(session, {
      commandTimeoutMs: request.commandTimeoutMs ?? this.options.commandTimeoutMs,
      strict: request.strict ?? this.options.strict,
      maxChildren: request.maxChildren ?? this.options.maxChildren,
      maxData: request.maxData ?? this.options.maxData,
    });

    const status = await inspector.status();
    const primeAction = request.primeAction ?? this.options.primeAction;
    if (status.status === 'starting' && primeAction !== 'none') {
      await this.applyPrimeAction(inspector, primeAction);
    }

    let topFrame = undefined;
    try {
      topFrame = (await inspector.stackGet())[0];
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }

    let snapshot = undefined;
    if (request.captureSnapshot ?? true) {
      try {
        snapshot = await inspector.captureSnapshot(
          request.snapshotContextIds ?? this.options.snapshotContextIds
        );
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
      }
    }

    const evaluations: Record<string, string | undefined> = {};
    for (const expression of request.evaluateExpressions ?? []) {
      try {
        evaluations[expression] = await inspector.evaluate(expression);
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
        evaluations[expression] = undefined;
      }
    }

    let trace = undefined;
    if (request.tracePlan) {
      try {
        trace = await inspector.traceExecution(request.tracePlan);
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
      }
    }

    let replayResults: ReplayResult[] = [];
    if (request.replayPlan) {
      try {
        replayResults = await inspector.replayWithMutations(request.replayPlan);
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
      }
    }

    const transcript = request.includeTranscript ? session.getTranscript() : undefined;
    const evidence = buildDeterministicDebugEvidence({
      trigger: request.trigger,
      init: {
        fileUri: init.fileUri,
        language: init.language,
        protocolVersion: init.protocolVersion,
        engineName: init.engineName,
        engineVersion: init.engineVersion,
      },
      evaluations,
      snapshot,
      trace,
      replayResults,
      normalization: request.normalization ?? this.options.normalization,
    });

    return {
      trigger: request.trigger,
      sessionId: session.id,
      init,
      errors,
      raw: {
        snapshot,
        trace,
        replayResults,
        evaluations,
        transcript,
        topFrame,
      },
      evidence,
    };
  }

  private isRecoverableSessionError(error: Error): boolean {
    if (error instanceof DbgpProtocolError) {
      return error.code === 'SESSION_CLOSED' || error.code === 'COMMAND_TIMEOUT';
    }

    const message = error.message.toLowerCase();
    return (
      message.includes('closed dbgp session') ||
      message.includes('timed out waiting for dbgp init packet') ||
      message.includes('session socket closed')
    );
  }

  private async persistAttemptArtifacts(
    request: DebugReplayAttemptRunRequest,
    capture: DebugIntegrationTemplateCaptureResult,
    attempt: number,
    emittedArtifacts: ReplayManifestEntryInput[]
  ): Promise<DebugReplayAttemptRecord['artifacts']> {
    if (!request.artifactDir) {
      return undefined;
    }

    const attemptPrefix = `attempt-${String(attempt).padStart(2, '0')}`;
    const evidencePath = path.join(request.artifactDir, `${attemptPrefix}.evidence.json`);
    await writeJsonFile(evidencePath, {
      schemaVersion: 'dbgp-evidence.v1',
      attempt,
      capture: {
        trigger: capture.trigger,
        sessionId: capture.sessionId,
        init: capture.init,
        errors: capture.errors,
        evidence: capture.evidence,
      },
      template: capture.template,
    });
    emittedArtifacts.push({ kind: 'attempt_evidence', path: evidencePath });

    const replayResultsPath = path.join(request.artifactDir, `${attemptPrefix}.replay-results.json`);
    await writeJsonFile(replayResultsPath, {
      schemaVersion: 'dbgp-replay-results.v1',
      attempt,
      sessionId: capture.sessionId,
      replayResults: capture.raw.replayResults,
    });
    emittedArtifacts.push({ kind: 'attempt_replay_results', path: replayResultsPath });

    let transcriptPath: string | undefined;
    if (capture.raw.transcript && capture.raw.transcript.length > 0) {
      transcriptPath = path.join(request.artifactDir, `${attemptPrefix}.transcript.json`);
      await writeJsonFile(transcriptPath, {
        schemaVersion: 'dbgp-transcript.v1',
        createdAt: new Date().toISOString(),
        sessionId: capture.sessionId,
        metadata: {
          attempt,
          candidateId: capture.trigger.candidateId ?? '',
          correlationId: capture.trigger.correlationId ?? '',
          requestId: capture.trigger.requestId ?? '',
          sinkCategory: capture.trigger.sinkCategory ?? '',
          sinkName: capture.trigger.sinkName ?? '',
        },
        entries: capture.raw.transcript,
      });
      emittedArtifacts.push({ kind: 'attempt_transcript', path: transcriptPath });
    }

    return {
      evidencePath,
      replayResultsPath,
      transcriptPath,
    };
  }
}

function countReplayErrors(results: ReplayResult[]): number {
  return results.reduce((count, entry) => {
    const replayErrors = entry.errors.length;
    const resetErrors = entry.resetErrors?.length ?? 0;
    return count + replayErrors + resetErrors;
  }, 0);
}

function classifyAttemptFailure(error: Error): DebugReplayAttemptFailureCode {
  if (error instanceof DebugTriggerError) {
    return 'trigger_failed';
  }

  if (error instanceof DbgpProtocolError) {
    if (error.code === 'SESSION_CLOSED') {
      return 'session_closed';
    }
    if (error.code === 'COMMAND_TIMEOUT') {
      return 'command_timeout';
    }
    return 'protocol_error';
  }

  const message = error.message.trim().toLowerCase();
  if (message.includes('aborted')) {
    return 'routing_aborted';
  }
  if (message.includes('timed out waiting for routed dbgp session')) {
    return 'routing_timeout';
  }
  if (message.includes('timed out waiting for dbgp init packet')) {
    return 'routing_timeout';
  }
  if (message.includes('session socket closed') || message.includes('closed dbgp session')) {
    return 'session_closed';
  }
  if (message.includes('command timeout')) {
    return 'command_timeout';
  }
  if (message.includes('capture failed')) {
    return 'capture_failed';
  }
  return 'unknown';
}

class DebugTriggerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DebugTriggerError';
  }
}

async function writeJsonFile(filePath: string, payload: unknown): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}
