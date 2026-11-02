export interface DebugPolicyPack {
  name: string;
  categories: string[];
  traceSteps: number;
  watchExpressions: string[];
  snapshotContextIds: number[];
  autoCaptureExceptions: boolean;
}
