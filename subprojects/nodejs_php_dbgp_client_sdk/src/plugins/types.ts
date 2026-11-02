import type { CandidateRecord } from '../bridge/types.js';

export interface TranscriptRedactionPluginContext {
  path: string;
  key?: string;
  value: unknown;
  replacement: string;
}

export interface TranscriptRedactionPlugin {
  name: string;
  redact(
    context: TranscriptRedactionPluginContext
  ): { handled: boolean; value: unknown } | undefined;
}

export interface CandidateTriggerResolverPluginContext {
  template: string;
  candidate: CandidateRecord;
}

export interface CandidateTriggerResolverPlugin {
  name: string;
  resolve(context: CandidateTriggerResolverPluginContext): string | undefined;
}
