import type { DbgpInitPacket } from '../protocol/types.js';
import type { DbgpSession } from '../server/DbgpSession.js';
import type { DbgpTranscriptEntry } from '../server/DbgpSession.js';
import type {
  DebugStackFrame,
  InspectorOptions,
  ReplayPlan,
  ReplayResult,
  SessionSnapshot,
  TracePlan,
  TraceResult,
  TraceStepAction,
} from '../inspector/types.js';
import type { ReplayArtifactManifest } from '../replay/manifest.js';

export interface SinkTriggerContext {
  candidateId?: string;
  sinkCategory?: string;
  sinkName?: string;
  requestUri?: string;
  correlationId?: string;
  requestId?: string;
  findingId?: string;
  traceId?: string;
  metadata?: Record<string, unknown>;
}

export interface EvidenceNormalizationOptions {
  maxStringLength?: number;
  maxPropertyDepth?: number;
  maxPropertiesPerContext?: number;
  includeValues?: boolean;
  redactor?: (path: string, value: string) => string;
}

export interface NormalizedDebugFrame {
  level: number;
  type?: string;
  fileUri?: string;
  lineno?: number;
  where?: string;
}

export interface NormalizedDebugProperty {
  name: string;
  fullName: string;
  type: string;
  value?: string;
  key: string;
  children: NormalizedDebugProperty[];
}

export interface NormalizedDebugContext {
  id: number;
  name: string;
  propertyCount: number;
  properties: NormalizedDebugProperty[];
}

export interface NormalizedDebugSnapshot {
  capturedAt: string;
  status?: string;
  reason?: string;
  topFrame?: NormalizedDebugFrame;
  frames: NormalizedDebugFrame[];
  contexts: NormalizedDebugContext[];
  fingerprint: string;
}

export interface NormalizedDebugTraceStep {
  step: number;
  action: TraceStepAction;
  status?: string;
  reason?: string;
  topFrame?: NormalizedDebugFrame;
  watchValues: Record<string, string | undefined>;
  error?: string;
}

export interface NormalizedDebugTrace {
  startedAt: string;
  finishedAt: string;
  steps: NormalizedDebugTraceStep[];
}

export interface NormalizedReplayResult {
  variationId: string;
  runStatus?: string;
  driftDetected: boolean;
  errors: string[];
  resetErrors: string[];
  evalResults: Record<string, string | undefined>;
}

export interface DeterministicDebugEvidence {
  trigger: SinkTriggerContext;
  init?: {
    fileUri: string;
    language: string;
    protocolVersion: string;
    engineName?: string;
    engineVersion?: string;
  };
  evaluations: Record<string, string | undefined>;
  snapshot?: NormalizedDebugSnapshot;
  trace?: NormalizedDebugTrace;
  replay: NormalizedReplayResult[];
  fingerprint: string;
}

export interface DebugIntegrationCaptureRequest extends InspectorOptions {
  trigger: SinkTriggerContext;
  sessionTimeoutMs?: number;
  abortSignal?: AbortSignal;
  primeAction?: TraceStepAction | 'none';
  captureSnapshot?: boolean;
  snapshotContextIds?: number[];
  evaluateExpressions?: string[];
  tracePlan?: TracePlan;
  replayPlan?: ReplayPlan;
  includeTranscript?: boolean;
  closeSession?: boolean;
  normalization?: EvidenceNormalizationOptions;
  routing?: DebugSessionRoutingOptions;
}

export type DebugIntegrationTrigger = (
  trigger: SinkTriggerContext
) => Promise<void> | void;

export interface DebugIntegrationCaptureResult {
  trigger: SinkTriggerContext;
  sessionId: string;
  init?: DbgpInitPacket;
  errors: string[];
  raw: {
    snapshot?: SessionSnapshot;
    trace?: TraceResult;
    replayResults: ReplayResult[];
    evaluations: Record<string, string | undefined>;
    transcript?: ReadonlyArray<DbgpTranscriptEntry>;
    topFrame?: DebugStackFrame;
  };
  evidence: DeterministicDebugEvidence;
}

export interface DebugReplayTemplateSelection {
  name?: string;
  category?: string;
  mutationTarget?: string;
  payloads?: string[];
  resetValue?: string;
  driftExpressions?: string[];
  comparePhase?: 'pre' | 'post' | 'post_reset';
  failOnDrift?: boolean;
  allowSnapshotDrift?: boolean;
  maxExpressionDriftCount?: number;
  allowedExpressionDrift?: string[];
}

export interface DebugReplayTemplate {
  name: string;
  categories: string[];
  description: string;
  captureProfile: string;
  mutationTarget: string;
  payloads: string[];
  resetValue: string;
  driftExpressions: string[];
  comparePhase: 'pre' | 'post' | 'post_reset';
  failOnDrift: boolean;
  allowSnapshotDrift: boolean;
  maxExpressionDriftCount: number;
  allowedExpressionDrift: string[];
}

export interface ResolvedDebugReplayTemplate {
  template: DebugReplayTemplate;
  replayPlan: ReplayPlan;
  tracePlan: TracePlan;
  evaluateExpressions: string[];
  snapshotContextIds: number[];
  primeAction: TraceStepAction | 'none';
}

export interface DebugIntegrationTemplateCaptureRequest
  extends DebugIntegrationCaptureRequest {
  template?: DebugReplayTemplateSelection;
}

export interface DebugIntegrationTemplateCaptureResult
  extends DebugIntegrationCaptureResult {
  template: ResolvedDebugReplayTemplate;
}

export type DebugReplayAttemptStatus = 'succeeded' | 'failed';

export type DebugReplayAttemptFailureCode =
  | 'none'
  | 'trigger_failed'
  | 'routing_aborted'
  | 'routing_timeout'
  | 'session_closed'
  | 'command_timeout'
  | 'protocol_error'
  | 'capture_failed'
  | 'replay_failed'
  | 'unknown';

export interface DebugReplayAttemptArtifacts {
  evidencePath?: string;
  replayResultsPath?: string;
  transcriptPath?: string;
}

export interface DebugReplayAttemptRecord {
  attempt: number;
  startedAt: string;
  finishedAt: string;
  status: DebugReplayAttemptStatus;
  failureCode: DebugReplayAttemptFailureCode;
  failureMessage?: string;
  sessionId?: string;
  evidenceFingerprint?: string;
  replayVariationCount: number;
  replayErrorCount: number;
  artifacts?: DebugReplayAttemptArtifacts;
}

export interface DebugReplayAttemptBundle {
  schemaVersion: 'dbgp-replay-attempts.v1';
  createdAt: string;
  trigger: SinkTriggerContext;
  template: ResolvedDebugReplayTemplate;
  maxAttempts: number;
  stopOnFirstSuccess: boolean;
  requireReplayEvidence: boolean;
  attempts: DebugReplayAttemptRecord[];
  finalStatus: DebugReplayAttemptStatus;
  successfulAttempt?: number;
}

export interface DebugReplayAttemptRunRequest
  extends DebugIntegrationTemplateCaptureRequest {
  attempts?: number;
  stopOnFirstSuccess?: boolean;
  requireReplayEvidence?: boolean;
  artifactDir?: string;
  artifactManifestPath?: string;
  manifestSignature?: {
    hmacSecret: string;
    keyId?: string;
  };
}

export type DebugReplayAttemptTrigger = (
  trigger: SinkTriggerContext,
  attempt: number
) => Promise<void> | void;

export interface DebugReplayAttemptRunResult {
  bundle: DebugReplayAttemptBundle;
  captures: DebugIntegrationTemplateCaptureResult[];
  artifactManifestPath?: string;
  artifactManifest?: ReplayArtifactManifest;
}

export type PhpTaintTraceVerificationOutcome =
  | 'confirmed'
  | 'not_confirmed'
  | 'inconclusive'
  | 'blocked_by_policy'
  | 'replay_failed';

export interface PhpTaintTraceOracleArtifactRef {
  type: string;
  path: string;
  metadata: Record<string, unknown>;
}

export interface PhpTaintTraceReplayTranscriptRef {
  attempt: number;
  status: DebugReplayAttemptStatus;
  failure_code: DebugReplayAttemptFailureCode;
  failure_message?: string;
  session_id?: string;
  replay_variation_count: number;
  replay_error_count: number;
  artifacts?: DebugReplayAttemptArtifacts;
}

export interface PhpTaintTraceVerificationResultPayload {
  job_id: string;
  candidate_id: string;
  outcome: PhpTaintTraceVerificationOutcome;
  reason_codes: string[];
  summary: string;
  artifacts: PhpTaintTraceOracleArtifactRef[];
  replay_transcripts: PhpTaintTraceReplayTranscriptRef[];
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface VerifierDecisionAdapterOptions {
  jobId?: string;
  createdAt?: string;
}

export interface DebugReplayVerifierDecisionResult {
  replay: DebugReplayAttemptRunResult;
  verificationResult: PhpTaintTraceVerificationResultPayload;
}

export interface DebugIntegrationServiceOptions extends InspectorOptions {
  sessionTimeoutMs?: number;
  primeAction?: TraceStepAction | 'none';
  snapshotContextIds?: number[];
  normalization?: EvidenceNormalizationOptions;
  routing?: DebugSessionRoutingOptions;
}

export interface DebugSessionMatchContext {
  session: DbgpSession;
  init?: DbgpInitPacket;
  trigger: SinkTriggerContext;
}

export type DebugSessionMatcher = (
  context: DebugSessionMatchContext
) => boolean | Promise<boolean>;

export interface DebugSessionRoutingOptions {
  requireCorrelationMatch?: boolean;
  allowUnmatchedFallback?: boolean;
  matcher?: DebugSessionMatcher;
  maxRecoveryAttempts?: number;
  initWaitTimeoutMs?: number;
}

export interface DebugSessionLease {
  session: DbgpSession;
  init?: DbgpInitPacket;
  release: () => void;
}

export interface DebugSessionAcquireRequest extends DebugSessionRoutingOptions {
  trigger: SinkTriggerContext;
  timeoutMs: number;
  commandTimeoutMs: number;
  abortSignal?: AbortSignal;
}
