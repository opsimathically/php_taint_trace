import type { DbgpTranscriptEntry } from '../server/DbgpSession.js';
import type { TranscriptRedactionPlugin } from '../plugins/types.js';

export interface TranscriptArtifactV1 {
  schemaVersion: 'dbgp-transcript.v1';
  createdAt: string;
  sessionId: string;
  metadata?: Record<string, string | number | boolean>;
  entries: DbgpTranscriptEntry[];
}

export interface TranscriptRedactionOptions {
  replacement?: string;
  sensitiveKeys?: string[];
  sensitiveValuePatterns?: RegExp[];
  plugins?: TranscriptRedactionPlugin[];
}

export interface TranscriptStoreOptions {
  redaction?: TranscriptRedactionOptions;
  metadata?: Record<string, string | number | boolean>;
}
