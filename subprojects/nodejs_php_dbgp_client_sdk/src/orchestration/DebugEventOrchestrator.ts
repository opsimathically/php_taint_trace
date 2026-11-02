import type { PhpDebugInspector } from '../inspector/PhpDebugInspector.js';
import { parseAttributes } from '../protocol/xml.js';
import type { DbgpResponsePacket } from '../protocol/types.js';
import type { DbgpSession } from '../server/DbgpSession.js';
import type {
  AutoCaptureRecord,
  AutoCaptureRule,
  BreakEvent,
  OrchestratorOptions,
} from './types.js';

export type BreakHandler = (event: BreakEvent) => void | Promise<void>;
export type ExceptionHandler = (event: BreakEvent) => void | Promise<void>;
export type AutoCaptureHandler = (record: AutoCaptureRecord) => void | Promise<void>;

export class DebugEventOrchestrator {
  private readonly session: DbgpSession;
  private readonly inspector: PhpDebugInspector;
  private readonly options: Required<OrchestratorOptions>;
  private running = false;
  private queue: Promise<void> = Promise.resolve();
  private readonly breakHandlers = new Set<BreakHandler>();
  private readonly exceptionHandlers = new Set<ExceptionHandler>();
  private readonly autoCaptureHandlers = new Set<AutoCaptureHandler>();
  private readonly autoRules: AutoCaptureRule[] = [];
  private readonly triggerCounts = new Map<string, number>();
  private readonly responseListener: (packet: DbgpResponsePacket) => void;

  constructor(session: DbgpSession, inspector: PhpDebugInspector, options: OrchestratorOptions = {}) {
    this.session = session;
    this.inspector = inspector;
    this.options = {
      enableExceptionExtraction: options.enableExceptionExtraction ?? true,
    };
    this.responseListener = (packet) => {
      this.enqueue(packet);
    };
  }

  start(): void {
    if (this.running) {
      return;
    }
    this.running = true;
    this.session.on('response', this.responseListener);
  }

  stop(): void {
    if (!this.running) {
      return;
    }
    this.running = false;
    this.session.off('response', this.responseListener);
  }

  onBreak(handler: BreakHandler): () => void {
    this.breakHandlers.add(handler);
    return () => {
      this.breakHandlers.delete(handler);
    };
  }

  onException(handler: ExceptionHandler): () => void {
    this.exceptionHandlers.add(handler);
    return () => {
      this.exceptionHandlers.delete(handler);
    };
  }

  onAutoCapture(handler: AutoCaptureHandler): () => void {
    this.autoCaptureHandlers.add(handler);
    return () => {
      this.autoCaptureHandlers.delete(handler);
    };
  }

  addAutoCaptureRule(rule: AutoCaptureRule): () => void {
    this.autoRules.push(rule);
    return () => {
      const index = this.autoRules.findIndex((value) => value.id === rule.id);
      if (index >= 0) {
        this.autoRules.splice(index, 1);
      }
    };
  }

  async flush(): Promise<void> {
    await this.queue;
  }

  private enqueue(packet: DbgpResponsePacket): void {
    this.queue = this.queue.then(async () => this.handleResponse(packet));
  }

  private async handleResponse(packet: DbgpResponsePacket): Promise<void> {
    if (packet.status !== 'break') {
      return;
    }
    if (packet.command && !BREAK_EVENT_COMMANDS.has(packet.command)) {
      return;
    }

    const event = this.toBreakEvent(packet);
    for (const handler of this.breakHandlers) {
      await handler(event);
    }

    if (event.exceptionName) {
      for (const handler of this.exceptionHandlers) {
        await handler(event);
      }
    }

    for (const rule of this.autoRules) {
      if (!rule.when(event)) {
        continue;
      }

      const count = this.triggerCounts.get(rule.id) ?? 0;
      if (typeof rule.maxTriggers === 'number' && count >= rule.maxTriggers) {
        continue;
      }

      this.triggerCounts.set(rule.id, count + 1);
      const record: AutoCaptureRecord = {
        ruleId: rule.id,
        event,
        watchValues: {},
        errors: [],
      };

      try {
        record.snapshot = await this.inspector.captureSnapshot(rule.snapshotContextIds ?? [0]);
      } catch (error) {
        record.errors.push(error instanceof Error ? error.message : String(error));
      }

      for (const expression of rule.watchExpressions ?? []) {
        try {
          record.watchValues[expression] = await this.inspector.evaluate(expression);
        } catch (error) {
          record.errors.push(error instanceof Error ? error.message : String(error));
        }
      }

      for (const handler of this.autoCaptureHandlers) {
        await handler(record);
      }
    }
  }

  private toBreakEvent(packet: DbgpResponsePacket): BreakEvent {
    const exception = this.options.enableExceptionExtraction
      ? extractExceptionDetails(packet.rawXml)
      : {};

    return {
      timestamp: new Date().toISOString(),
      sessionId: this.session.id,
      command: packet.command,
      reason: packet.reason,
      status: packet.status,
      transactionId: packet.transactionId,
      response: packet,
      exceptionName: exception.exceptionName,
      exceptionMessage: exception.exceptionMessage,
      exceptionFile: exception.exceptionFile,
      exceptionLine: exception.exceptionLine,
    };
  }
}

const BREAK_EVENT_COMMANDS = new Set([
  'run',
  'step_into',
  'step_over',
  'step_out',
  'breakpoint_set',
  'breakpoint_update',
  'breakpoint_remove',
]);

function extractExceptionDetails(xml: string): {
  exceptionName?: string;
  exceptionMessage?: string;
  exceptionFile?: string;
  exceptionLine?: number;
} {
  const match = /<xdebug:message\b([^>]*?)\/?>/u.exec(xml);
  if (!match) {
    return {};
  }

  const attributes = parseAttributes(match[1] ?? '');
  const line = attributes.lineno && /^\d+$/u.test(attributes.lineno) ? Number(attributes.lineno) : undefined;

  return {
    exceptionName: attributes.exception,
    exceptionMessage: attributes.message,
    exceptionFile: attributes.filename ?? attributes.fileuri,
    exceptionLine: line,
  };
}
