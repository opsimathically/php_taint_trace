import type { DbgpCommandOptions } from '../protocol/command.js';
import type { DbgpResponsePacket } from '../protocol/types.js';
import type { DbgpSession } from '../server/DbgpSession.js';
import { createHash } from 'node:crypto';
import {
  parseBreakpoints,
  parseContextNames,
  parseEvalValue,
  parseFeatureInfo,
  parseProperties,
  parseSourceContent,
  parseStackFrames,
} from './parsers.js';
import { expandReplayVariations } from '../replay/matrix.js';
import type {
  BreakpointUpdateOptions,
  BreakpointSetOptions,
  DebugBreakpointInfo,
  DebugContextDescriptor,
  DebugFeatureInfo,
  DebugProperty,
  DebugStdIoChannel,
  DebugStdIoMode,
  DebugStackFrame,
  InspectorOptions,
  PropertyGetOptions,
  PropertySetOptions,
  ReplayMutation,
  ReplayPlan,
  ReplayResult,
  SessionSnapshot,
  SourceOptions,
  TracePlan,
  TraceResult,
  TraceStep,
  TraceStepAction,
} from './types.js';

interface NormalizedDebugProperty {
  name: string;
  fullName: string;
  type: string;
  value: string;
  key: string;
  children: NormalizedDebugProperty[];
}

export class PhpDebugInspector {
  private readonly session: DbgpSession;
  private readonly options: Required<InspectorOptions>;

  constructor(session: DbgpSession, options: InspectorOptions = {}) {
    this.session = session;
    this.options = {
      commandTimeoutMs: options.commandTimeoutMs ?? 5000,
      strict: options.strict ?? true,
      maxChildren: options.maxChildren ?? 64,
      maxData: options.maxData ?? 8192,
    };
  }

  async run(): Promise<DbgpResponsePacket> {
    return this.command('run');
  }

  async stepInto(): Promise<DbgpResponsePacket> {
    return this.command('step_into');
  }

  async stepOver(): Promise<DbgpResponsePacket> {
    return this.command('step_over');
  }

  async stepOut(): Promise<DbgpResponsePacket> {
    return this.command('step_out');
  }

  async stop(): Promise<DbgpResponsePacket> {
    return this.command('stop');
  }

  async detach(): Promise<DbgpResponsePacket> {
    return this.command('detach');
  }

  async status(): Promise<DbgpResponsePacket> {
    return this.command('status');
  }

  async featureGet(name: string): Promise<DebugFeatureInfo | undefined> {
    const response = await this.command('feature_get', { n: name });
    return parseFeatureInfo(response.rawXml);
  }

  async featureSet(name: string, value: string | number | boolean): Promise<DbgpResponsePacket> {
    const normalized = typeof value === 'boolean' ? (value ? 1 : 0) : value;
    return this.command('feature_set', { n: name, v: normalized });
  }

  async source(options: SourceOptions = {}): Promise<string | undefined> {
    const response = await this.command('source', {
      f: options.fileUri,
      b: options.beginLine,
      e: options.endLine,
    });
    return parseSourceContent(response.rawXml);
  }

  async setStdIo(channel: DebugStdIoChannel, mode: DebugStdIoMode): Promise<DbgpResponsePacket> {
    const command = channel === 'stdout' ? 'stdout' : 'stderr';
    return this.command(command, { c: mode });
  }

  async stackGet(depth?: number): Promise<DebugStackFrame[]> {
    const options: DbgpCommandOptions = {};
    if (typeof depth === 'number') {
      options.d = depth;
    }
    const response = await this.command('stack_get', options);
    return parseStackFrames(response.rawXml);
  }

  async contextNames(stackDepth = 0): Promise<DebugContextDescriptor[]> {
    const response = await this.command('context_names', { d: stackDepth });
    return parseContextNames(response.rawXml);
  }

  async contextGet(contextId = 0, stackDepth = 0): Promise<DebugProperty[]> {
    const response = await this.command('context_get', {
      c: contextId,
      d: stackDepth,
      m: this.options.maxData,
      n: this.options.maxChildren,
    });
    return parseProperties(response.rawXml);
  }

  async propertyGet(
    name: string,
    optionsOrContextId: PropertyGetOptions | number = {},
    stackDepthArg?: number
  ): Promise<DebugProperty | undefined> {
    const options =
      typeof optionsOrContextId === 'number'
        ? { contextId: optionsOrContextId, stackDepth: stackDepthArg ?? 0 }
        : optionsOrContextId;
    const contextId = options.contextId ?? 0;
    const stackDepth = options.stackDepth ?? 0;
    const response = await this.command('property_get', {
      n: name,
      c: contextId,
      d: stackDepth,
      m: this.options.maxData,
      k: this.options.maxChildren,
    });

    const properties = parseProperties(response.rawXml);
    return properties[0];
  }

  async propertyValue(
    name: string,
    optionsOrContextId: PropertyGetOptions | number = {},
    stackDepthArg?: number
  ): Promise<string | undefined> {
    const options =
      typeof optionsOrContextId === 'number'
        ? { contextId: optionsOrContextId, stackDepth: stackDepthArg ?? 0 }
        : optionsOrContextId;
    const contextId = options.contextId ?? 0;
    const stackDepth = options.stackDepth ?? 0;
    const response = await this.command('property_value', {
      n: name,
      c: contextId,
      d: stackDepth,
      m: this.options.maxData,
    });
    return parseSourceContent(response.rawXml);
  }

  async propertySet(
    name: string,
    value: string,
    optionsOrContextId: PropertySetOptions | number = {},
    stackDepthArg?: number
  ): Promise<DbgpResponsePacket> {
    const options =
      typeof optionsOrContextId === 'number'
        ? { contextId: optionsOrContextId, stackDepth: stackDepthArg ?? 0 }
        : optionsOrContextId;
    const contextId = options.contextId ?? 0;
    const stackDepth = options.stackDepth ?? 0;
    const byteLength = Buffer.byteLength(value, 'utf8');
    return this.command(
      'property_set',
      {
        n: name,
        c: contextId,
        d: stackDepth,
        t: options.type,
        a: options.address,
        l: byteLength,
      },
      value
    );
  }

  async evaluate(expression: string): Promise<string | undefined> {
    const response = await this.command('eval', {}, expression);
    return parseEvalValue(response.rawXml);
  }

  async breakpointSet(options: BreakpointSetOptions): Promise<string | undefined> {
    const commandOptions: DbgpCommandOptions = {
      t: options.type ?? 'line',
      f: options.fileUri,
      n: options.line,
      m: options.functionName,
      x: options.exception,
      s: options.disabled ? 'disabled' : 'enabled',
      r: options.temporary ? 1 : undefined,
      h: options.hitValue,
      o: options.hitCondition,
    };

    const response = await this.command('breakpoint_set', commandOptions, options.expression);
    return response.attributes.id;
  }

  async breakpointRemove(id: string): Promise<DbgpResponsePacket> {
    return this.command('breakpoint_remove', { d: id });
  }

  async breakpointGet(id: string): Promise<DebugBreakpointInfo | undefined> {
    const response = await this.command('breakpoint_get', { d: id });
    const parsed = parseBreakpoints(response.rawXml);
    return parsed[0];
  }

  async breakpointList(): Promise<DebugBreakpointInfo[]> {
    const response = await this.command('breakpoint_list');
    return parseBreakpoints(response.rawXml);
  }

  async breakpointUpdate(options: BreakpointUpdateOptions): Promise<DbgpResponsePacket> {
    return this.command('breakpoint_update', {
      d: options.id,
      s: options.state,
      n: options.line,
      h: options.hitValue,
      o: options.hitCondition,
    });
  }

  async captureSnapshot(contextIds: number[] = [0]): Promise<SessionSnapshot> {
    const init = await this.session.waitForInit(this.options.commandTimeoutMs);
    const status = await this.status();
    const stack = await this.stackGet();
    const topStackDepth = stack[0]?.level ?? 0;
    let contextNameMap = new Map<number, string>();

    try {
      const contextNames = await this.contextNames(topStackDepth);
      contextNameMap = new Map(contextNames.map((entry) => [entry.id, entry.name]));
    } catch {
      // Some DBGp backends do not allow context_names in all break states.
    }

    const contexts: Array<{ context: DebugContextDescriptor; properties: DebugProperty[] }> = [];

    for (const contextId of contextIds) {
      let properties: DebugProperty[] = [];
      try {
        properties = await this.contextGet(contextId, topStackDepth);
      } catch {
        // Preserve partial snapshot semantics even when one context is not available.
      }

      contexts.push({
        context: {
          id: contextId,
          name: contextNameMap.get(contextId) ?? (contextId === 0 ? 'Locals' : `Context-${contextId}`),
        },
        properties,
      });
    }

    return {
      capturedAt: new Date().toISOString(),
      init,
      status,
      stack,
      contexts,
    };
  }

  async replayWithMutations(plan: ReplayPlan): Promise<ReplayResult[]> {
    const results: ReplayResult[] = [];
    const replayVariations = expandReplayVariations(plan);
    const deterministic = plan.deterministicChecks?.enabled ?? false;
    const comparePhase = plan.deterministicChecks?.comparePhase ?? 'post_reset';
    const failOnDrift = plan.deterministicChecks?.failOnDrift ?? false;
    const driftExpressions = plan.deterministicChecks?.driftExpressions ?? [];
    const thresholds = {
      allowSnapshotDrift: plan.deterministicChecks?.thresholds?.allowSnapshotDrift ?? false,
      maxExpressionDriftCount: plan.deterministicChecks?.thresholds?.maxExpressionDriftCount ?? 0,
      allowedExpressionDrift: plan.deterministicChecks?.thresholds?.allowedExpressionDrift ?? [],
    };
    const allowedExpressionSet = new Set(thresholds.allowedExpressionDrift);

    const breakpointIds: string[] = [];
    try {
      for (const breakpoint of plan.breakpoints ?? []) {
        const id = await this.breakpointSet(breakpoint);
        if (id) {
          breakpointIds.push(id);
        }
      }

      for (const variation of replayVariations) {
        const evalResults: Record<string, string | undefined> = {};
        let baselineEvalResults: Record<string, string | undefined> | undefined;
        let driftEvalResults: Record<string, string | undefined> | undefined;
        const errors: string[] = [];
        const resetErrors: string[] = [];
        let baselineSnapshot: SessionSnapshot | undefined;
        let baselineSnapshotHash: string | undefined;
        let preSnapshot: SessionSnapshot | undefined;
        let preSnapshotHash: string | undefined;
        let postSnapshot: SessionSnapshot | undefined;
        let postSnapshotHash: string | undefined;
        let postResetSnapshot: SessionSnapshot | undefined;
        let postResetSnapshotHash: string | undefined;
        let observedSnapshotDrift = false;
        const observedExpressionDrifts: Array<{
          expression: string;
          baseline?: string;
          current?: string;
          allowed: boolean;
        }> = [];
        let driftDetected = false;
        const driftReasons: string[] = [];
        let runStatus: string | undefined;

        try {
          const initialStatus = await this.status();
          const hasBreakpoints = (plan.breakpoints?.length ?? 0) > 0;
          if (initialStatus.status === 'starting') {
            const breakResponse = hasBreakpoints ? await this.run() : await this.stepInto();
            runStatus = breakResponse.status;
          } else if (initialStatus.status === 'running') {
            const breakResponse = await this.run();
            runStatus = breakResponse.status;
          } else {
            runStatus = initialStatus.status;
          }

          if ((plan.baselineMutations?.length ?? 0) > 0) {
            await this.applyMutations(plan.baselineMutations ?? []);
          }

          if (plan.captureBaseline) {
            baselineSnapshot = await this.captureSnapshot(plan.snapshotContextIds ?? [0]);
            baselineSnapshotHash = this.snapshotFingerprint(baselineSnapshot);
          }

          if (deterministic && driftExpressions.length > 0) {
            baselineEvalResults = await this.evaluateExpressions(driftExpressions);
          }

          if (plan.captureBefore) {
            preSnapshot = await this.captureSnapshot(plan.snapshotContextIds ?? [0]);
            preSnapshotHash = this.snapshotFingerprint(preSnapshot);
            if (deterministic && comparePhase === 'pre' && driftExpressions.length > 0) {
              driftEvalResults = await this.evaluateExpressions(driftExpressions);
            }
          }

          await this.applyMutations(variation.mutations ?? []);

          for (const expression of variation.evalExpressions ?? []) {
            evalResults[expression] = await this.evaluate(expression);
          }

          if (plan.continueAfterMutation ?? true) {
            const response = await this.run();
            runStatus = response.status;
          }

          if (plan.captureAfter) {
            postSnapshot = await this.captureSnapshot(plan.snapshotContextIds ?? [0]);
            postSnapshotHash = this.snapshotFingerprint(postSnapshot);
          }

          if (deterministic && comparePhase === 'post' && driftExpressions.length > 0) {
            driftEvalResults = await this.evaluateExpressions(driftExpressions);
          }

          if ((variation.resetMutations?.length ?? 0) > 0) {
            try {
              await this.applyMutations(variation.resetMutations ?? []);
              if (plan.continueAfterReset ?? false) {
                const response = await this.run();
                runStatus = response.status;
              }
              if (plan.capturePostReset || (deterministic && comparePhase === 'post_reset')) {
                postResetSnapshot = await this.captureSnapshot(plan.snapshotContextIds ?? [0]);
                postResetSnapshotHash = this.snapshotFingerprint(postResetSnapshot);
              }
              if (deterministic && comparePhase === 'post_reset' && driftExpressions.length > 0) {
                driftEvalResults = await this.evaluateExpressions(driftExpressions);
              }
            } catch (error) {
              const message = error instanceof Error ? error.message : String(error);
              resetErrors.push(message);
              if (plan.failOnResetError) {
                throw error;
              }
            }
          }

          if (deterministic) {
            const compareHash = this.selectDeterministicHash(comparePhase, {
              baselineSnapshotHash,
              preSnapshotHash,
              postSnapshotHash,
              postResetSnapshotHash,
            });
            if (baselineSnapshotHash && compareHash) {
              observedSnapshotDrift = baselineSnapshotHash !== compareHash;
              if (observedSnapshotDrift && !thresholds.allowSnapshotDrift) {
                driftDetected = true;
                driftReasons.push(
                  `Snapshot drift (${comparePhase}): baseline hash '${baselineSnapshotHash}' differs from '${compareHash}'.`
                );
              }
            }

            if (driftExpressions.length > 0 && baselineEvalResults && driftEvalResults) {
              let violatingExpressionDrifts = 0;
              for (const expression of driftExpressions) {
                const baseline = baselineEvalResults[expression];
                const current = driftEvalResults[expression];
                if (baseline !== current) {
                  const allowed = allowedExpressionSet.has(expression);
                  observedExpressionDrifts.push({
                    expression,
                    baseline,
                    current,
                    allowed,
                  });
                  if (!allowed) {
                    violatingExpressionDrifts += 1;
                    driftReasons.push(
                      `Expression drift (${comparePhase}) for '${expression}': baseline='${baseline ?? ''}' current='${current ?? ''}'.`
                    );
                  }
                }
              }
              if (violatingExpressionDrifts > thresholds.maxExpressionDriftCount) {
                driftDetected = true;
              }
            }

            if (failOnDrift && driftDetected) {
              throw new Error(`Determinism drift detected: ${driftReasons.join(' | ')}`);
            }
          }
        } catch (error) {
          errors.push(error instanceof Error ? error.message : String(error));
        }

        results.push({
          variation,
          baselineSnapshot,
          baselineSnapshotHash,
          preSnapshot,
          preSnapshotHash,
          postSnapshot,
          postSnapshotHash,
          postResetSnapshot,
          postResetSnapshotHash,
          baselineEvalResults,
          driftEvalResults,
          observedSnapshotDrift,
          observedExpressionDrifts,
          driftThresholds: thresholds,
          driftDetected,
          driftReasons,
          runStatus,
          evalResults,
          errors,
          resetErrors,
        });
      }
    } finally {
      for (const id of breakpointIds) {
        try {
          await this.breakpointRemove(id);
        } catch {
          // Ignore cleanup errors so replay callers can inspect primary results.
        }
      }
    }

    return results;
  }

  private async applyMutations(mutations: ReadonlyArray<ReplayMutation>): Promise<void> {
    for (const mutation of mutations) {
      const setResponse = await this.propertySet(
        mutation.propertyName,
        mutation.value,
        mutation.options
      );
      if (
        typeof setResponse.attributes.success === 'string' &&
        setResponse.attributes.success !== '1'
      ) {
        await this.evaluate(
          `${mutation.propertyName} = ${this.toPhpSingleQuotedString(mutation.value)}`
        );
      }
    }
  }

  private async evaluateExpressions(
    expressions: ReadonlyArray<string>
  ): Promise<Record<string, string | undefined>> {
    const values: Record<string, string | undefined> = {};
    for (const expression of expressions) {
      values[expression] = await this.evaluate(expression);
    }
    return values;
  }

  private selectDeterministicHash(
    comparePhase: 'pre' | 'post' | 'post_reset',
    hashes: {
      baselineSnapshotHash?: string;
      preSnapshotHash?: string;
      postSnapshotHash?: string;
      postResetSnapshotHash?: string;
    }
  ): string | undefined {
    if (comparePhase === 'pre') {
      return hashes.preSnapshotHash ?? hashes.baselineSnapshotHash;
    }
    if (comparePhase === 'post') {
      return hashes.postSnapshotHash ?? hashes.preSnapshotHash ?? hashes.baselineSnapshotHash;
    }
    return (
      hashes.postResetSnapshotHash ??
      hashes.postSnapshotHash ??
      hashes.preSnapshotHash ??
      hashes.baselineSnapshotHash
    );
  }

  private snapshotFingerprint(snapshot: SessionSnapshot): string {
    const normalized = {
      init: {
        language: snapshot.init.language,
        protocolVersion: snapshot.init.protocolVersion,
        fileUri: snapshot.init.fileUri,
        engineName: snapshot.init.engineName ?? '',
        engineVersion: snapshot.init.engineVersion ?? '',
      },
      status: {
        status: snapshot.status.status ?? '',
        reason: snapshot.status.reason ?? '',
      },
      stack: snapshot.stack
        .map((frame) => ({
          level: frame.level,
          type: frame.type ?? '',
          fileUri: frame.fileUri ?? '',
          lineno: frame.lineno ?? 0,
          where: frame.where ?? '',
          command: frame.command ?? '',
        }))
        .sort((left, right) => left.level - right.level),
      contexts: snapshot.contexts
        .map((entry) => ({
          id: entry.context.id,
          name: entry.context.name,
          properties: this.normalizeProperties(entry.properties),
        }))
        .sort((left, right) => left.id - right.id),
    };

    const digest = createHash('sha256');
    digest.update(JSON.stringify(normalized));
    return digest.digest('hex');
  }

  private normalizeProperties(
    properties: ReadonlyArray<DebugProperty>
  ): NormalizedDebugProperty[] {
    const normalized: NormalizedDebugProperty[] = properties.map((property) => ({
      name: property.name ?? '',
      fullName: property.fullName ?? '',
      type: property.type ?? '',
      value: property.value ?? '',
      key: property.key ?? '',
      children: this.normalizeProperties(property.properties ?? []),
    }));

    normalized.sort((left, right) =>
      `${left.fullName}:${left.name}:${left.key}`.localeCompare(
        `${right.fullName}:${right.name}:${right.key}`
      )
    );
    return normalized;
  }

  async traceExecution(plan: TracePlan): Promise<TraceResult> {
    if (!Number.isInteger(plan.steps) || plan.steps <= 0) {
      throw new Error('Trace plan requires steps > 0.');
    }

    const action: TraceStepAction = plan.action ?? 'step_over';
    const watchExpressions = plan.watchExpressions ?? [];
    const stopOn = new Set<string>(
      plan.stopOnStatuses ?? ['stopping', 'stopped', 'detached', 'error']
    );
    const startedAt = new Date().toISOString();
    const tracedSteps: TraceStep[] = [];

    for (let index = 0; index < plan.steps; index += 1) {
      const traceStep: TraceStep = {
        step: index + 1,
        action,
        watchValues: {},
      };

      try {
        const response = await this.executeAction(action);
        traceStep.status = response.status;
        traceStep.reason = response.reason;

        const stack = await this.stackGet();
        traceStep.topFrame = stack[0];

        for (const expression of watchExpressions) {
          traceStep.watchValues[expression] = await this.evaluate(expression);
        }

        if (plan.captureSnapshots) {
          traceStep.snapshot = await this.captureSnapshot(plan.snapshotContextIds ?? [0]);
        }
      } catch (error) {
        traceStep.error = error instanceof Error ? error.message : String(error);
      }

      tracedSteps.push(traceStep);

      if (traceStep.error) {
        break;
      }
      if (traceStep.status && stopOn.has(traceStep.status)) {
        break;
      }
    }

    return {
      startedAt,
      finishedAt: new Date().toISOString(),
      steps: tracedSteps,
    };
  }

  private async command(
    command: string,
    options: DbgpCommandOptions = {},
    data?: string
  ): Promise<DbgpResponsePacket> {
    const response = await this.session.sendCommand(
      command,
      options,
      data,
      this.options.commandTimeoutMs
    );

    if (this.options.strict && response.error) {
      throw new Error(
        `DBGp command ${command} failed: ${response.error.code ?? 'unknown'} ${response.error.message ?? ''}`.trim()
      );
    }

    return response;
  }

  private async executeAction(action: TraceStepAction): Promise<DbgpResponsePacket> {
    switch (action) {
      case 'run':
        return this.run();
      case 'step_into':
        return this.stepInto();
      case 'step_out':
        return this.stepOut();
      case 'step_over':
      default:
        return this.stepOver();
    }
  }

  private toPhpSingleQuotedString(value: string): string {
    const escaped = value.replaceAll('\\', '\\\\').replaceAll("'", "\\'");
    return `'${escaped}'`;
  }
}
