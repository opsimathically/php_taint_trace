import { DbgpProtocolError } from '../core/DbgpProtocolError.js';
import type { DbgpInitPacket } from '../protocol/types.js';
import type { DbgpServer } from '../server/DbgpServer.js';
import type { DbgpSession } from '../server/DbgpSession.js';
import type {
  DebugSessionAcquireRequest,
  DebugSessionLease,
  DebugSessionRoutingOptions,
  SinkTriggerContext,
} from './types.js';

interface SessionEvaluation {
  session: DbgpSession;
  init?: DbgpInitPacket;
  score: number;
}

interface NormalizedSessionAcquireRequest extends Omit<DebugSessionAcquireRequest, 'abortSignal'> {
  abortSignal?: AbortSignal;
  requireCorrelationMatch: boolean;
  allowUnmatchedFallback: boolean;
  matcher: NonNullable<DebugSessionRoutingOptions['matcher']>;
  maxRecoveryAttempts: number;
  initWaitTimeoutMs: number;
}

export class DebugSessionRouter {
  private readonly server: DbgpServer;
  private readonly defaults: Required<DebugSessionRoutingOptions>;
  private readonly claimed = new Set<string>();

  constructor(server: DbgpServer, options: DebugSessionRoutingOptions = {}) {
    this.server = server;
    this.defaults = {
      requireCorrelationMatch: options.requireCorrelationMatch ?? false,
      allowUnmatchedFallback: options.allowUnmatchedFallback ?? true,
      matcher: options.matcher ?? (() => true),
      maxRecoveryAttempts: options.maxRecoveryAttempts ?? 1,
      initWaitTimeoutMs: options.initWaitTimeoutMs ?? 2000,
    };
  }

  async acquire(request: DebugSessionAcquireRequest): Promise<DebugSessionLease> {
    if (request.abortSignal?.aborted) {
      throw new Error('Debug session routing aborted.');
    }

    const startedAt = Date.now();
    const deadline = startedAt + request.timeoutMs;
    const normalized = this.normalizeRequest(request);

    while (Date.now() < deadline) {
      const fromExisting = await this.tryFindFromExistingSessions(normalized, deadline);
      if (fromExisting) {
        return this.toLease(fromExisting);
      }

      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        break;
      }

      const candidate = await this.waitForNewSession(remaining, request.abortSignal);
      const evaluated = await this.evaluateSession(candidate, normalized, deadline);
      if (evaluated && evaluated.score > 0) {
        return this.toLease(evaluated);
      }
    }

    throw new DbgpProtocolError(
      'COMMAND_TIMEOUT',
      'Timed out waiting for routed DBGp session.'
    );
  }

  private normalizeRequest(
    request: DebugSessionAcquireRequest
  ): NormalizedSessionAcquireRequest {
    return {
      trigger: request.trigger,
      timeoutMs: request.timeoutMs,
      commandTimeoutMs: request.commandTimeoutMs,
      abortSignal: request.abortSignal,
      requireCorrelationMatch:
        request.requireCorrelationMatch ?? this.defaults.requireCorrelationMatch,
      allowUnmatchedFallback:
        request.allowUnmatchedFallback ?? this.defaults.allowUnmatchedFallback,
      matcher: request.matcher ?? this.defaults.matcher,
      maxRecoveryAttempts: request.maxRecoveryAttempts ?? this.defaults.maxRecoveryAttempts,
      initWaitTimeoutMs: request.initWaitTimeoutMs ?? this.defaults.initWaitTimeoutMs,
    };
  }

  private async tryFindFromExistingSessions(
    request: NormalizedSessionAcquireRequest,
    deadline: number
  ): Promise<SessionEvaluation | undefined> {
    let fallback: SessionEvaluation | undefined;
    for (const session of this.server.getSessions()) {
      const evaluated = await this.evaluateSession(session, request, deadline);
      if (!evaluated || evaluated.score <= 0) {
        continue;
      }
      if (evaluated.score >= 2) {
        return evaluated;
      }
      if (!fallback) {
        fallback = evaluated;
      }
    }
    return fallback;
  }

  private async evaluateSession(
    session: DbgpSession,
    request: NormalizedSessionAcquireRequest,
    deadline: number
  ): Promise<SessionEvaluation | undefined> {
    if (this.claimed.has(session.id)) {
      return undefined;
    }

    const state = session.getState();
    if (state === 'closed' || state === 'detached' || state === 'error') {
      return undefined;
    }

    this.claimed.add(session.id);
    let keepClaim = false;
    try {
      const init = await this.waitForInitWithinDeadline(session, request, deadline);
      const correlationScore = this.evaluateCorrelationScore(init, request.trigger);
      if (request.requireCorrelationMatch && correlationScore < 2) {
        return undefined;
      }

      const customMatch = await request.matcher({
        session,
        init,
        trigger: request.trigger,
      });
      if (!customMatch) {
        return undefined;
      }

      const score =
        correlationScore >= 2
          ? 2
          : (request.allowUnmatchedFallback ? 1 : 0);
      if (score <= 0) {
        return undefined;
      }

      keepClaim = true;
      return { session, init, score };
    } catch {
      return undefined;
    } finally {
      if (!keepClaim || !this.isSessionUsable(session)) {
        this.claimed.delete(session.id);
      }
    }
  }

  private async waitForInitWithinDeadline(
    session: DbgpSession,
    request: NormalizedSessionAcquireRequest,
    deadline: number
  ): Promise<DbgpInitPacket | undefined> {
    const existing = session.getInitPacket();
    if (existing) {
      return existing;
    }

    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      return undefined;
    }

    const initWait = Math.min(request.initWaitTimeoutMs, remaining, request.commandTimeoutMs);
    if (initWait <= 0) {
      return undefined;
    }

    return session.waitForInit(initWait);
  }

  private evaluateCorrelationScore(
    init: DbgpInitPacket | undefined,
    trigger: SinkTriggerContext
  ): number {
    const tokens = this.extractCorrelationTokens(trigger);
    if (tokens.length === 0) {
      return 2;
    }
    if (!init) {
      return 0;
    }

    const values = [
      init.appId,
      init.ideKey ?? '',
      init.session ?? '',
      init.thread ?? '',
      init.parent ?? '',
      init.fileUri,
      init.engineName ?? '',
    ]
      .map((entry) => entry.toLowerCase())
      .filter((entry) => entry !== '');

    for (const token of tokens) {
      if (values.some((entry) => entry.includes(token))) {
        return 2;
      }
    }

    return 0;
  }

  private extractCorrelationTokens(trigger: SinkTriggerContext): string[] {
    const keys = [
      trigger.correlationId,
      trigger.requestId,
      trigger.candidateId,
      trigger.findingId,
      trigger.traceId,
    ];
    return keys
      .filter((entry): entry is string => typeof entry === 'string')
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry) => entry !== '');
  }

  private waitForNewSession(timeoutMs: number, abortSignal?: AbortSignal): Promise<DbgpSession> {
    return new Promise<DbgpSession>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(
          new DbgpProtocolError(
            'COMMAND_TIMEOUT',
            'Timed out waiting for a new DBGp session for routing.'
          )
        );
      }, timeoutMs);

      const onAbort = () => {
        cleanup();
        reject(new Error('Debug session routing aborted.'));
      };

      const onSession = (session: DbgpSession) => {
        cleanup();
        resolve(session);
      };

      const cleanup = () => {
        clearTimeout(timer);
        this.server.off('session', onSession);
        abortSignal?.removeEventListener('abort', onAbort);
      };

      this.server.on('session', onSession);
      if (abortSignal) {
        abortSignal.addEventListener('abort', onAbort, { once: true });
      }
    });
  }

  private toLease(evaluation: SessionEvaluation): DebugSessionLease {
    let released = false;
    const release = () => {
      if (released) {
        return;
      }
      released = true;
      this.claimed.delete(evaluation.session.id);
    };

    evaluation.session.once('close', release);
    return {
      session: evaluation.session,
      init: evaluation.init,
      release,
    };
  }

  private isSessionUsable(session: DbgpSession): boolean {
    const state = session.getState();
    return state !== 'closed' && state !== 'detached' && state !== 'error';
  }
}
