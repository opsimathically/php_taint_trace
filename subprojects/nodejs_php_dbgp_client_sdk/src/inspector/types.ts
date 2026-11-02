import type { DbgpInitPacket, DbgpResponsePacket } from '../protocol/types.js';

export interface InspectorOptions {
  commandTimeoutMs?: number;
  strict?: boolean;
  maxChildren?: number;
  maxData?: number;
}

export type DebugStdIoChannel = 'stdout' | 'stderr';
export type DebugStdIoMode = 0 | 1 | 2;

export interface DebugStackFrame {
  level: number;
  type?: string;
  fileUri?: string;
  lineno?: number;
  where?: string;
  command?: string;
}

export interface DebugContextDescriptor {
  id: number;
  name: string;
}

export interface DebugProperty {
  name?: string;
  fullName?: string;
  type?: string;
  className?: string;
  encoding?: string;
  facet?: string;
  size?: number;
  children?: number;
  numChildren?: number;
  page?: number;
  pagesize?: number;
  key?: string;
  address?: string;
  value?: string;
  properties?: DebugProperty[];
}

export interface DebugFeatureInfo {
  name: string;
  supported: boolean;
  value?: string;
}

export interface DebugBreakpointInfo {
  id?: string;
  type?: string;
  state?: string;
  fileUri?: string;
  line?: number;
  functionName?: string;
  exception?: string;
  expression?: string;
  hitValue?: number;
  hitCondition?: string;
  hitCount?: number;
}

export interface PropertyGetOptions {
  contextId?: number;
  stackDepth?: number;
}

export interface PropertySetOptions extends PropertyGetOptions {
  type?: string;
  address?: string;
}

export interface SourceOptions {
  fileUri?: string;
  beginLine?: number;
  endLine?: number;
}

export interface BreakpointUpdateOptions {
  id: string;
  state?: 'enabled' | 'disabled';
  line?: number;
  hitValue?: number;
  hitCondition?: '>=' | '==' | '%';
}

export interface SessionSnapshot {
  capturedAt: string;
  init: DbgpInitPacket;
  status: DbgpResponsePacket;
  stack: DebugStackFrame[];
  contexts: Array<{
    context: DebugContextDescriptor;
    properties: DebugProperty[];
  }>;
}

export interface BreakpointSetOptions {
  type?: 'line' | 'call' | 'return' | 'exception' | 'conditional' | 'watch';
  fileUri?: string;
  line?: number;
  functionName?: string;
  exception?: string;
  expression?: string;
  temporary?: boolean;
  disabled?: boolean;
  hitValue?: number;
  hitCondition?: '>=' | '==' | '%';
}

export interface ReplayMutation {
  propertyName: string;
  value: string;
  options?: PropertySetOptions;
}

export interface ReplayVariation {
  id: string;
  description?: string;
  mutations?: ReplayMutation[];
  evalExpressions?: string[];
  metadata?: Record<string, string>;
  resetMutations?: ReplayMutation[];
}

export interface ReplayPlan {
  breakpoints?: BreakpointSetOptions[];
  variations: ReplayVariation[];
  baselineMutations?: ReplayMutation[];
  matrix?: Array<{
    propertyName: string;
    values: string[];
    options?: PropertySetOptions;
  }>;
  captureBefore?: boolean;
  captureAfter?: boolean;
  captureBaseline?: boolean;
  snapshotContextIds?: number[];
  continueAfterMutation?: boolean;
  continueAfterReset?: boolean;
  failOnResetError?: boolean;
  capturePostReset?: boolean;
  deterministicChecks?: {
    enabled?: boolean;
    failOnDrift?: boolean;
    comparePhase?: 'pre' | 'post' | 'post_reset';
    driftExpressions?: string[];
    thresholds?: {
      allowSnapshotDrift?: boolean;
      maxExpressionDriftCount?: number;
      allowedExpressionDrift?: string[];
    };
  };
}

export interface ReplayResult {
  variation: ReplayVariation;
  baselineSnapshot?: SessionSnapshot;
  baselineSnapshotHash?: string;
  preSnapshot?: SessionSnapshot;
  preSnapshotHash?: string;
  postSnapshot?: SessionSnapshot;
  postSnapshotHash?: string;
  postResetSnapshot?: SessionSnapshot;
  postResetSnapshotHash?: string;
  baselineEvalResults?: Record<string, string | undefined>;
  driftEvalResults?: Record<string, string | undefined>;
  observedSnapshotDrift?: boolean;
  observedExpressionDrifts?: Array<{
    expression: string;
    baseline?: string;
    current?: string;
    allowed: boolean;
  }>;
  driftThresholds?: {
    allowSnapshotDrift: boolean;
    maxExpressionDriftCount: number;
    allowedExpressionDrift: string[];
  };
  driftDetected?: boolean;
  driftReasons?: string[];
  runStatus?: string;
  evalResults: Record<string, string | undefined>;
  errors: string[];
  resetErrors?: string[];
}

export type TraceStepAction = 'run' | 'step_into' | 'step_over' | 'step_out';

export interface TracePlan {
  steps: number;
  action?: TraceStepAction;
  watchExpressions?: string[];
  captureSnapshots?: boolean;
  snapshotContextIds?: number[];
  stopOnStatuses?: Array<'break' | 'stopping' | 'stopped' | 'detached' | 'error'>;
}

export interface TraceStep {
  step: number;
  action: TraceStepAction;
  status?: string;
  reason?: string;
  watchValues: Record<string, string | undefined>;
  topFrame?: DebugStackFrame;
  snapshot?: SessionSnapshot;
  error?: string;
}

export interface TraceResult {
  startedAt: string;
  finishedAt: string;
  steps: TraceStep[];
}
