import type { InspectorOptions, TraceResult, SessionSnapshot } from '../inspector/types.js';
import type { DebugPolicyPack } from '../policies/types.js';
import type { CandidateTriggerResolverPlugin } from '../plugins/types.js';
import type { CaptureProfile } from '../profiles/types.js';
import type { TranscriptRedactionOptions } from '../transcript/types.js';

export interface CandidateRecord {
  candidateId: string;
  sinkCategory?: string;
  sinkName?: string;
  requestUri?: string;
  detector?: string;
  correlationId?: string;
  requestId?: string;
  findingId?: string;
  traceId?: string;
  metadata: Record<string, unknown>;
}

export interface CandidateBridgeOptions extends InspectorOptions {
  sessionTimeoutMs?: number;
  artifactsDir: string;
  traceSteps?: number;
  watchExpressions?: string[];
  snapshotContextIds?: number[];
  policyPackName?: string;
  policyPackByCategory?: boolean;
  captureProfileName?: string;
  captureProfileByCategory?: boolean;
  transcriptRedaction?: TranscriptRedactionOptions;
  triggerResolverPlugins?: CandidateTriggerResolverPlugin[];
}

export interface CandidateBridgeRunResult {
  candidateId: string;
  correlationId?: string;
  requestId?: string;
  findingId?: string;
  appliedPolicyPack: DebugPolicyPack;
  appliedCaptureProfile: CaptureProfile;
  sessionId: string;
  artifactPath: string;
  snapshot?: SessionSnapshot;
  trace?: TraceResult;
  errors: string[];
}

export type CandidateTrigger = (
  candidate: CandidateRecord,
  index: number
) => Promise<void> | void;
