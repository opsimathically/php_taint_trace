import type { SessionSnapshot } from '../inspector/types.js';
import type { DbgpResponsePacket } from '../protocol/types.js';

export interface BreakEvent {
  timestamp: string;
  sessionId: string;
  command?: string;
  reason?: string;
  status?: string;
  transactionId: number;
  response: DbgpResponsePacket;
  exceptionName?: string;
  exceptionMessage?: string;
  exceptionFile?: string;
  exceptionLine?: number;
}

export interface AutoCaptureRule {
  id: string;
  when: (event: BreakEvent) => boolean;
  maxTriggers?: number;
  snapshotContextIds?: number[];
  watchExpressions?: string[];
}

export interface AutoCaptureRecord {
  ruleId: string;
  event: BreakEvent;
  snapshot?: SessionSnapshot;
  watchValues: Record<string, string | undefined>;
  errors: string[];
}

export interface OrchestratorOptions {
  enableExceptionExtraction?: boolean;
}
