import type { TraceStepAction } from '../inspector/types.js';

export interface CaptureProfile {
  name: string;
  categories: string[];
  description: string;
  traceAction: TraceStepAction;
  traceSteps: number;
  watchExpressions: string[];
  snapshotContextIds: number[];
  stopOnStatuses: Array<'break' | 'stopping' | 'stopped' | 'detached' | 'error'>;
  autoCaptureExceptions: boolean;
}
