import { mkdtemp, readFile, rm } from 'node:fs/promises';
import * as net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { DbgpFrameCodec } from '../../src/protocol/DbgpFrameCodec.js';
import { DbgpServer } from '../../src/server/DbgpServer.js';
import { DebugIntegrationService } from '../../src/integration/DebugIntegrationService.js';

type CommandHandler = (command: string, transactionId: number, rawLine: string) => string;

class FakeXdebugEngine {
  private readonly host: string;
  private readonly port: number;
  private readonly handler: CommandHandler;
  private readonly initXml: string;
  private readonly closeAfterConnectMs?: number;
  private readonly closeOnFirstCommand: boolean;
  private firstCommandReceived = false;
  private socket?: net.Socket;
  private pending = Buffer.alloc(0);

  constructor(
    host: string,
    port: number,
    handler: CommandHandler,
    options: {
      initXml?: string;
      closeAfterConnectMs?: number;
      closeOnFirstCommand?: boolean;
    } = {}
  ) {
    this.host = host;
    this.port = port;
    this.handler = handler;
    this.initXml = options.initXml ??
      '<init appid="900" idekey="sdk-test" session="integration" language="PHP" protocol_version="1.0" fileuri="file:///tmp/test.php"><engine version="3.3.0" name="Xdebug"></engine></init>';
    this.closeAfterConnectMs = options.closeAfterConnectMs;
    this.closeOnFirstCommand = options.closeOnFirstCommand ?? false;
  }

  async connect(): Promise<void> {
    this.socket = net.createConnection({ host: this.host, port: this.port });
    this.socket.on('data', (chunk) => this.onData(chunk));
    await onceConnected(this.socket);
    this.sendXml(this.initXml);
    if (this.closeAfterConnectMs && this.closeAfterConnectMs > 0) {
      setTimeout(() => {
        this.socket?.end();
      }, this.closeAfterConnectMs);
    }
  }

  close(): void {
    this.socket?.destroy();
  }

  private onData(chunk: Buffer): void {
    this.pending = Buffer.concat([this.pending, chunk]);
    while (true) {
      const sep = this.pending.indexOf(0x00);
      if (sep === -1) {
        break;
      }

      const line = this.pending.subarray(0, sep).toString('utf8').trim();
      this.pending = this.pending.subarray(sep + 1);
      if (!line) {
        continue;
      }

      const command = line.split(/\s+/u)[0];
      const txMatch = /-i\s+(\d+)/u.exec(line);
      const transactionId = txMatch ? Number(txMatch[1]) : 0;
      if (this.closeOnFirstCommand && !this.firstCommandReceived) {
        this.firstCommandReceived = true;
        this.socket?.end();
        break;
      }
      const response = this.handler(command, transactionId, line);
      this.sendXml(response);
    }
  }

  private sendXml(xml: string): void {
    this.socket?.write(DbgpFrameCodec.encode(xml));
  }
}

async function onceConnected(socket: net.Socket): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => resolve());
    socket.once('error', (error) => reject(error));
  });
}

describe('DebugIntegrationService', () => {
  const cleanup: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    for (const fn of cleanup.reverse()) {
      await fn();
    }
    cleanup.length = 0;
  });

  it('captures snapshot/trace/replay and emits deterministic evidence', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1200 });
    await server.start();
    cleanup.push(() => server.stop());

    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address unavailable.');
    }

    const commands: string[] = [];
    let statusCallCount = 0;

    const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx) => {
      commands.push(command);
      if (command === 'status') {
        statusCallCount += 1;
        const status = statusCallCount === 1 ? 'starting' : 'break';
        return `<response command="status" transaction_id="${tx}" status="${status}" reason="ok"></response>`;
      }
      if (command === 'step_into' || command === 'step_over') {
        return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
      if (command === 'stack_get') {
        return `<response command="stack_get" transaction_id="${tx}"><stack level="1" type="file" filename="file:///tmp/test.php" lineno="20" where="foo"/><stack level="0" type="file" filename="file:///tmp/test.php" lineno="10" where="main"/></response>`;
      }
      if (command === 'context_names') {
        return `<response command="context_names" transaction_id="${tx}"><context name="Superglobals" id="1"/><context name="Locals" id="0"/></response>`;
      }
      if (command === 'context_get') {
        return `<response command="context_get" transaction_id="${tx}"><property name="$z" fullname="$z" type="string" encoding="base64">enp6</property><property name="$a" fullname="$a" type="string" encoding="base64">YWFhYWFhYWFh</property></response>`;
      }
      if (command === 'eval') {
        return `<response command="eval" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>`;
      }
      if (command === 'property_set') {
        return `<response command="property_set" transaction_id="${tx}" success="1"></response>`;
      }

      return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
    });
    cleanup.push(() => engine.close());

    const integration = new DebugIntegrationService(server, {
      commandTimeoutMs: 1200,
      sessionTimeoutMs: 2000,
      primeAction: 'step_into',
      snapshotContextIds: [1, 0],
    });

    const result = await integration.captureForTrigger(
      {
        trigger: {
          candidateId: 'cand-1',
          sinkCategory: 'rce',
          sinkName: 'system',
        },
        includeTranscript: true,
        evaluateExpressions: ['$cmd'],
        tracePlan: {
          steps: 1,
          action: 'step_over',
          watchExpressions: ['$cmd'],
        },
        replayPlan: {
          variations: [
            {
              id: 'var-1',
              mutations: [{ propertyName: '$cmd', value: 'id' }],
              evalExpressions: ['$cmd'],
            },
          ],
          captureBefore: false,
          captureAfter: false,
          continueAfterMutation: false,
        },
        normalization: {
          maxStringLength: 8,
        },
      },
      async () => {
        await engine.connect();
      }
    );

    expect(result.errors).toEqual([]);
    expect(result.raw.snapshot).toBeDefined();
    expect(result.raw.trace?.steps.length).toBe(1);
    expect(result.raw.replayResults.length).toBe(1);
    expect(result.raw.transcript && result.raw.transcript.length > 0).toBe(true);
    expect(result.evidence.evaluations['$cmd']).toBe('id');
    expect(result.evidence.snapshot?.contexts[0]?.id).toBe(0);
    expect(result.evidence.snapshot?.contexts[0]?.properties[0]?.fullName).toBe('$a');
    expect(result.evidence.replay[0]?.variationId).toBe('var-1');
    expect(result.evidence.fingerprint.length).toBe(64);
    expect(commands.includes('step_into')).toBe(true);
    expect(commands.includes('step_over')).toBe(true);
    expect(commands.includes('property_set')).toBe(true);
  });

  it('captures using a sink replay template in a single call', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1200 });
    await server.start();
    cleanup.push(() => server.stop());

    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address unavailable.');
    }

    const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx) => {
      if (command === 'status' || command === 'step_into') {
        return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
      if (command === 'stack_get') {
        return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="14" where="main"/></response>`;
      }
      if (command === 'context_names') {
        return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/></response>`;
      }
      if (command === 'context_get') {
        return `<response command="context_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>`;
      }
      if (command === 'eval') {
        return `<response command="eval" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>`;
      }
      if (command === 'property_set') {
        return `<response command="property_set" transaction_id="${tx}" success="1"></response>`;
      }
      return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
    });
    cleanup.push(() => engine.close());

    const integration = new DebugIntegrationService(server, {
      commandTimeoutMs: 1200,
      sessionTimeoutMs: 2000,
    });

    const result = await integration.captureWithReplayTemplate(
      {
        trigger: {
          candidateId: 'cand-template',
          sinkCategory: 'rce',
        },
        captureSnapshot: false,
      },
      async () => {
        await engine.connect();
      }
    );

    expect(result.template.template.name).toBe('rce');
    expect(result.template.replayPlan.variations.length).toBeGreaterThan(1);
    expect(result.raw.replayResults.length).toBe(result.template.replayPlan.variations.length);
    expect(result.evidence.replay.length).toBe(result.template.replayPlan.variations.length);
  });

  it('routes to correlation-matching session when multiple sessions connect', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1200 });
    await server.start();
    cleanup.push(() => server.stop());

    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address unavailable.');
    }

    const defaultHandler: CommandHandler = (command, tx) => {
      if (command === 'status') {
        return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
      if (command === 'stack_get') {
        return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="9" where="main"/></response>`;
      }
      return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
    };

    const unmatched = new FakeXdebugEngine('127.0.0.1', address.port, defaultHandler, {
      initXml:
        '<init appid="900" idekey="unmatched" session="none" language="PHP" protocol_version="1.0" fileuri="file:///tmp/unmatched.php"><engine version="3.3.0" name="Xdebug"></engine></init>',
    });
    const matched = new FakeXdebugEngine('127.0.0.1', address.port, defaultHandler, {
      initXml:
        '<init appid="900" idekey="req-42" session="corr-42" language="PHP" protocol_version="1.0" fileuri="file:///tmp/matched.php"><engine version="3.3.0" name="Xdebug"></engine></init>',
    });
    cleanup.push(() => unmatched.close());
    cleanup.push(() => matched.close());

    const integration = new DebugIntegrationService(server, {
      commandTimeoutMs: 1200,
      sessionTimeoutMs: 2000,
      routing: {
        requireCorrelationMatch: true,
        allowUnmatchedFallback: false,
      },
    });

    const result = await integration.captureForTrigger(
      {
        trigger: {
          requestId: 'req-42',
          candidateId: 'cand-42',
        },
        captureSnapshot: false,
      },
      async () => {
        await unmatched.connect();
        setTimeout(() => {
          void matched.connect();
        }, 60);
      }
    );

    expect(result.init?.ideKey).toBe('req-42');
    expect(result.errors).toEqual([]);
  });

  it('recovers from closed session and retries capture on next session', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1200 });
    await server.start();
    cleanup.push(() => server.stop());

    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address unavailable.');
    }

    const broken = new FakeXdebugEngine(
      '127.0.0.1',
      address.port,
      (command, tx) =>
        `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`,
      { closeOnFirstCommand: true }
    );
    const healthy = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx) => {
      if (command === 'status') {
        return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
      if (command === 'stack_get') {
        return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="8" where="main"/></response>`;
      }
      return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
    });
    cleanup.push(() => broken.close());
    cleanup.push(() => healthy.close());

    const integration = new DebugIntegrationService(server, {
      commandTimeoutMs: 1200,
      sessionTimeoutMs: 3000,
      routing: {
        maxRecoveryAttempts: 1,
      },
    });

    const result = await integration.captureForTrigger(
      {
        trigger: {
          candidateId: 'cand-recover',
        },
        captureSnapshot: false,
      },
      async () => {
        await broken.connect();
        setTimeout(() => {
          void healthy.connect();
        }, 80);
      }
    );

    expect(result.sessionId).toBe('session-2');
    expect(result.errors.some((entry) => entry.toLowerCase().includes('closed'))).toBe(true);
  });

  it('supports cancellation via abort signal during session routing', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1200 });
    await server.start();
    cleanup.push(() => server.stop());

    const integration = new DebugIntegrationService(server, {
      sessionTimeoutMs: 5000,
    });

    const controller = new AbortController();
    setTimeout(() => controller.abort(), 40);

    await expect(
      integration.captureForTrigger({
        trigger: {
          candidateId: 'cand-abort',
        },
        abortSignal: controller.signal,
      })
    ).rejects.toThrow(/aborted/i);
  });

  it('runs bounded replay attempts and writes deterministic artifact bundle', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1200 });
    await server.start();
    cleanup.push(() => server.stop());

    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address unavailable.');
    }

    const artifactDir = await mkdtemp(path.join(tmpdir(), 'dbgp-replay-attempts-'));
    cleanup.push(() => rm(artifactDir, { recursive: true, force: true }));

    const broken = new FakeXdebugEngine(
      '127.0.0.1',
      address.port,
      (command, tx) =>
        `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`,
      { closeOnFirstCommand: true }
    );
    const healthy = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx) => {
      if (command === 'status' || command === 'step_into' || command === 'step_over') {
        return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
      if (command === 'stack_get') {
        return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="14" where="main"/></response>`;
      }
      if (command === 'context_names') {
        return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/></response>`;
      }
      if (command === 'context_get') {
        return `<response command="context_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>`;
      }
      if (command === 'eval') {
        return `<response command="eval" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>`;
      }
      if (command === 'property_set') {
        return `<response command="property_set" transaction_id="${tx}" success="1"></response>`;
      }
      return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
    });
    cleanup.push(() => broken.close());
    cleanup.push(() => healthy.close());

    const integration = new DebugIntegrationService(server, {
      commandTimeoutMs: 1200,
      sessionTimeoutMs: 3000,
      routing: {
        maxRecoveryAttempts: 0,
      },
    });

    const result = await integration.runReplayAttempts(
      {
        trigger: {
          candidateId: 'cand-attempts',
          sinkCategory: 'rce',
        },
        attempts: 3,
        stopOnFirstSuccess: true,
        includeTranscript: true,
        artifactDir,
      },
      async (_trigger, attempt) => {
        if (attempt === 0) {
          await broken.connect();
          return;
        }
        await healthy.connect();
      }
    );

    expect(result.bundle.finalStatus).toBe('succeeded');
    expect(result.bundle.attempts.length).toBe(2);
    expect(result.bundle.attempts[0]?.status).toBe('failed');
    expect(result.bundle.attempts[1]?.status).toBe('succeeded');
    expect(result.bundle.successfulAttempt).toBe(2);
    expect(result.artifactManifestPath).toBeTruthy();
    expect(result.captures.length).toBe(1);
    expect(result.captures[0]?.template.template.name).toBe('rce');

    const manifestPath = result.artifactManifestPath;
    if (!manifestPath) {
      throw new Error('Expected artifact manifest path');
    }
    const raw = await readFile(manifestPath, 'utf8');
    const manifest = JSON.parse(raw) as {
      entries?: Array<{ kind?: string }>;
    };
    const kinds = new Set((manifest.entries ?? []).map((entry) => entry.kind ?? ''));
    expect(kinds.has('replay_attempt_bundle')).toBe(true);
    expect(kinds.has('attempt_evidence')).toBe(true);
    expect(kinds.has('attempt_replay_results')).toBe(true);
    expect(kinds.has('attempt_transcript')).toBe(true);
  });

  it('classifies aborted routing in replay attempt flow and stops further attempts', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1200 });
    await server.start();
    cleanup.push(() => server.stop());

    const integration = new DebugIntegrationService(server, {
      sessionTimeoutMs: 5000,
      routing: {
        maxRecoveryAttempts: 0,
      },
    });

    const controller = new AbortController();
    setTimeout(() => controller.abort(), 40);

    const result = await integration.runReplayAttempts({
      trigger: {
        candidateId: 'cand-abort-attempt',
        sinkCategory: 'rce',
      },
      attempts: 3,
      abortSignal: controller.signal,
    });

    expect(result.bundle.finalStatus).toBe('failed');
    expect(result.bundle.attempts.length).toBe(1);
    expect(result.bundle.attempts[0]?.failureCode).toBe('routing_aborted');
  });

  it('adapts replay attempts to php_taint_trace verification payload', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1200 });
    await server.start();
    cleanup.push(() => server.stop());

    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address unavailable.');
    }

    const healthy = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx) => {
      if (command === 'status' || command === 'step_into') {
        return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
      if (command === 'stack_get') {
        return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="14" where="main"/></response>`;
      }
      if (command === 'context_names') {
        return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/></response>`;
      }
      if (command === 'context_get') {
        return `<response command="context_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>`;
      }
      if (command === 'eval') {
        return `<response command="eval" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>`;
      }
      if (command === 'property_set') {
        return `<response command="property_set" transaction_id="${tx}" success="1"></response>`;
      }
      return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
    });
    cleanup.push(() => healthy.close());

    const integration = new DebugIntegrationService(server, {
      commandTimeoutMs: 1200,
      sessionTimeoutMs: 3000,
      routing: {
        maxRecoveryAttempts: 0,
      },
    });

    const result = await integration.runReplayAttemptsAsVerifierDecision(
      {
        trigger: {
          candidateId: 'cand-verifier',
          sinkCategory: 'rce',
        },
        attempts: 1,
      },
      async () => {
        await healthy.connect();
      }
    );

    expect(result.verificationResult.candidate_id).toBe('cand-verifier');
    expect(result.verificationResult.outcome).toBe('confirmed');
    expect(result.verificationResult.reason_codes).toContain(
      'VERIFIER_DEBUG_REPLAY_ATTEMPT_CONFIRMED'
    );
  });
});
