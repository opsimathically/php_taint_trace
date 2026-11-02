export { DbgpProtocolError, type DbgpProtocolErrorCode } from './core/DbgpProtocolError.js';
export { DbgpFrameCodec } from './protocol/DbgpFrameCodec.js';
export { buildCommandLine, type DbgpCommandOptions } from './protocol/command.js';
export {
  parseDbgpPacket,
  parseRootNode,
  parseAttributes,
} from './protocol/xml.js';
export type {
  DbgpErrorPayload,
  DbgpInitPacket,
  DbgpNotifyPacket,
  DbgpParsedPacket,
  DbgpResponsePacket,
  DbgpSessionState,
  DbgpStreamPacket,
} from './protocol/types.js';
export { DbgpSession, type DbgpSessionOptions, type DbgpTranscriptEntry } from './server/DbgpSession.js';
export { DbgpServer, type DbgpServerOptions } from './server/DbgpServer.js';
export { PhpDebugInspector } from './inspector/PhpDebugInspector.js';
export { DebugIntegrationService } from './integration/DebugIntegrationService.js';
export { DebugSessionRouter } from './integration/DebugSessionRouter.js';
export {
  getDebugReplayTemplateByName,
  getDebugReplayTemplateForCategory,
  resolveDebugReplayTemplate,
} from './integration/replayTemplates.js';
export {
  buildDeterministicDebugEvidence,
  normalizeSnapshot,
  normalizeTrace,
  normalizeReplayResults,
} from './integration/evidence.js';
export {
  buildPhpTaintTraceVerificationResultFromReplayAttempts,
  buildDebugReplayVerifierDecision,
} from './integration/verifierDecisionAdapter.js';
export { ReplayController, type ReplayControllerOptions, type ReplayRunResult, type ReplayTrigger } from './replay/ReplayController.js';
export { buildExpandedReplayPlan, expandReplayVariations, validateReplayPlan } from './replay/matrix.js';
export { buildReplayDiffEntry, summarizeReplayDiffs } from './replay/diff.js';
export { buildReplayStabilityReport } from './replay/stability.js';
export {
  createReplayArtifactManifest,
  signReplayArtifactManifest,
  verifyReplayArtifactManifest,
  type ReplayManifestEntryInput,
  type ReplayManifestEntry,
  type ReplayArtifactManifest,
  type ReplayArtifactManifestSignature,
  type ReplayArtifactManifestVerificationMismatch,
  type ReplayArtifactManifestVerificationResult,
} from './replay/manifest.js';
export {
  getReplayGateProfileByName,
  getReplayGateProfileForCategory,
  type ReplayGateProfile,
} from './replay/gateProfiles.js';
export type { ReplayDiffExpression, ReplayDiffEntry, ReplayDiffSummary } from './replay/diff.js';
export type {
  ReplayStabilitySample,
  ReplayVariationStability,
  ReplayStabilityReport,
} from './replay/stability.js';
export { DebugEventOrchestrator, type BreakHandler, type ExceptionHandler, type AutoCaptureHandler } from './orchestration/DebugEventOrchestrator.js';
export { TranscriptArtifactStore } from './transcript/TranscriptArtifactStore.js';
export { redactTranscriptEntries } from './transcript/redaction.js';
export { CandidateVerificationBridge } from './bridge/CandidateVerificationBridge.js';
export { getPolicyPackByName, getPolicyPackForCategory } from './policies/packs.js';
export { getCaptureProfileByName, getCaptureProfileForCategory } from './profiles/packs.js';
export { resolveCandidateTriggerCommand, shellEscape } from './plugins/triggerResolver.js';
export type {
  BreakpointSetOptions,
  BreakpointUpdateOptions,
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
  ReplayVariation,
  SessionSnapshot,
  SourceOptions,
  TracePlan,
  TraceResult,
  TraceStep,
  TraceStepAction,
} from './inspector/types.js';
export type {
  SinkTriggerContext,
  EvidenceNormalizationOptions,
  NormalizedDebugFrame,
  NormalizedDebugProperty,
  NormalizedDebugContext,
  NormalizedDebugSnapshot,
  NormalizedDebugTraceStep,
  NormalizedDebugTrace,
  NormalizedReplayResult,
  DeterministicDebugEvidence,
  DebugReplayTemplateSelection,
  DebugReplayTemplate,
  ResolvedDebugReplayTemplate,
  DebugIntegrationCaptureRequest,
  DebugIntegrationTrigger,
  DebugIntegrationCaptureResult,
  DebugIntegrationTemplateCaptureRequest,
  DebugIntegrationTemplateCaptureResult,
  DebugReplayAttemptStatus,
  DebugReplayAttemptFailureCode,
  DebugReplayAttemptArtifacts,
  DebugReplayAttemptRecord,
  DebugReplayAttemptBundle,
  DebugReplayAttemptRunRequest,
  DebugReplayAttemptTrigger,
  DebugReplayAttemptRunResult,
  PhpTaintTraceVerificationOutcome,
  PhpTaintTraceOracleArtifactRef,
  PhpTaintTraceReplayTranscriptRef,
  PhpTaintTraceVerificationResultPayload,
  VerifierDecisionAdapterOptions,
  DebugReplayVerifierDecisionResult,
  DebugIntegrationServiceOptions,
  DebugSessionMatcher,
  DebugSessionMatchContext,
  DebugSessionRoutingOptions,
  DebugSessionAcquireRequest,
  DebugSessionLease,
} from './integration/types.js';
export type { BreakEvent, AutoCaptureRule, AutoCaptureRecord, OrchestratorOptions } from './orchestration/types.js';
export type { TranscriptArtifactV1, TranscriptRedactionOptions, TranscriptStoreOptions } from './transcript/types.js';
export type { CandidateRecord, CandidateBridgeOptions, CandidateBridgeRunResult, CandidateTrigger } from './bridge/types.js';
export type { DebugPolicyPack } from './policies/types.js';
export type { CaptureProfile } from './profiles/types.js';
export type {
  TranscriptRedactionPluginContext,
  TranscriptRedactionPlugin,
  CandidateTriggerResolverPluginContext,
  CandidateTriggerResolverPlugin,
} from './plugins/types.js';
