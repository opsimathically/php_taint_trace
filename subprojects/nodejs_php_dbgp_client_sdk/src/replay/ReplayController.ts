import { PhpDebugInspector } from '../inspector/PhpDebugInspector.js';
import type { InspectorOptions, ReplayPlan, ReplayResult, ReplayVariation } from '../inspector/types.js';
import type { DbgpServer } from '../server/DbgpServer.js';

export interface ReplayControllerOptions extends InspectorOptions {
  sessionTimeoutMs?: number;
}

export interface ReplayRunResult {
  variation: ReplayVariation;
  result: ReplayResult;
  sessionId: string;
}

export type ReplayTrigger = (
  variation: ReplayVariation,
  index: number
) => Promise<void> | void;

export class ReplayController {
  private readonly server: DbgpServer;
  private readonly options: Required<ReplayControllerOptions>;

  constructor(server: DbgpServer, options: ReplayControllerOptions = {}) {
    this.server = server;
    this.options = {
      commandTimeoutMs: options.commandTimeoutMs ?? 5000,
      strict: options.strict ?? true,
      maxChildren: options.maxChildren ?? 64,
      maxData: options.maxData ?? 8192,
      sessionTimeoutMs: options.sessionTimeoutMs ?? 30000,
    };
  }

  async run(plan: ReplayPlan, trigger: ReplayTrigger): Promise<ReplayRunResult[]> {
    const results: ReplayRunResult[] = [];

    for (const [index, variation] of plan.variations.entries()) {
      const waitSession = this.server.waitForNextSession(this.options.sessionTimeoutMs);
      await trigger(variation, index);
      const session = await waitSession;
      await session.waitForInit(this.options.commandTimeoutMs);

      const inspector = new PhpDebugInspector(session, this.options);
      const variationResults = await inspector.replayWithMutations({
        ...plan,
        variations: [variation],
      });

      for (const result of variationResults) {
        results.push({
          variation: result.variation,
          result,
          sessionId: session.id,
        });
      }

      session.close();
      await this.waitForSessionDrain();
    }

    return results;
  }

  private async waitForSessionDrain(): Promise<void> {
    const deadline = Date.now() + this.options.sessionTimeoutMs;
    while (Date.now() < deadline) {
      if (this.server.getSessions().length === 0) {
        return;
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 25));
    }
  }
}
