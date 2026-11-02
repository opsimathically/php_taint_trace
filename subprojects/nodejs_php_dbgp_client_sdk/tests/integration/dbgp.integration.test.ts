import * as net from 'node:net';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { CandidateVerificationBridge } from '../../src/bridge/CandidateVerificationBridge.js';
import { DebugEventOrchestrator } from '../../src/orchestration/DebugEventOrchestrator.js';
import { ReplayController } from '../../src/replay/ReplayController.js';
import { DbgpServer } from '../../src/server/DbgpServer.js';
import { DbgpFrameCodec } from '../../src/protocol/DbgpFrameCodec.js';
import { PhpDebugInspector } from '../../src/inspector/PhpDebugInspector.js';

type CommandHandler = (command: string, transactionId: number, rawLine: string) => string;

class FakeXdebugEngine {
  private readonly host: string;
  private readonly port: number;
  private readonly handler: CommandHandler;
  private socket?: net.Socket;
  private pending = Buffer.alloc(0);

  constructor(host: string, port: number, handler: CommandHandler) {
    this.host = host;
    this.port = port;
    this.handler = handler;
  }

  async connect(): Promise<void> {
    this.socket = net.createConnection({ host: this.host, port: this.port });
    this.socket.on('data', (chunk) => this.onData(chunk));
    await onceConnected(this.socket);
    this.sendXml(
      '<init appid="900" idekey="sdk-test" session="abc" language="PHP" protocol_version="1.0" fileuri="file:///tmp/test.php"><engine version="3.3.0" name="Xdebug"></engine></init>'
    );
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

describe('Dbgp integration', () => {
  const cleanup: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    for (const fn of cleanup.reverse()) {
      await fn();
    }
    cleanup.length = 0;
  });

  it('correlates command responses by transaction id', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx) => {
      return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
    });
    await engine.connect();
    cleanup.push(() => engine.close());

    const session = await server.waitForNextSession(2000);
    await session.waitForInit(2000);
    const response = await session.sendCommand('status');
    expect(response.transactionId).toBeGreaterThan(0);
    expect(response.command).toBe('status');
    expect(response.status).toBe('break');
  });

  it('inspector stack/context/eval mappings run over real session transport', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx) => {
      switch (command) {
        case 'stack_get':
          return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="11" where="main"/></response>`;
        case 'context_names':
          return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/><context name="Superglobals" id="1"/></response>`;
        case 'eval':
          return `<response command="eval" transaction_id="${tx}"><property name="$x" fullname="$x" type="string" encoding="base64">dGVzdA==</property></response>`;
        case 'status':
          return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
        case 'context_get':
          return `<response command="context_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">cHdk</property></response>`;
        default:
          return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
    });
    await engine.connect();
    cleanup.push(() => engine.close());

    const session = await server.waitForNextSession(2000);
    await session.waitForInit(2000);
    const inspector = new PhpDebugInspector(session);

    const stack = await inspector.stackGet();
    const contexts = await inspector.contextNames();
    const evalValue = await inspector.evaluate('$x');

    expect(stack).toHaveLength(1);
    expect(stack[0]?.lineno).toBe(11);
    expect(contexts.map((value) => value.name)).toEqual(['Locals', 'Superglobals']);
    expect(evalValue).toBe('test');
  });

  it('supports advanced operations: feature/source/property/breakpoint and transcripts', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    let propertySetValue = '';
    const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx, rawLine) => {
      if (command === 'property_set') {
        const payloadMatch = /--\s+([A-Za-z0-9+/=]+)$/u.exec(rawLine);
        propertySetValue = payloadMatch
          ? Buffer.from(payloadMatch[1], 'base64').toString('utf8')
          : '';
      }

      switch (command) {
        case 'feature_get':
          return `<response command="feature_get" transaction_id="${tx}" feature_name="max_children" supported="1">128</response>`;
        case 'source':
          return `<response command="source" transaction_id="${tx}" encoding="base64">${Buffer.from('<?php echo "ok";', 'utf8').toString('base64')}</response>`;
        case 'property_get':
          return `<response command="property_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">cHdk</property></response>`;
        case 'property_value':
          return `<response command="property_value" transaction_id="${tx}" encoding="base64">${Buffer.from('pwd', 'utf8').toString('base64')}</response>`;
        case 'property_set':
          return `<response command="property_set" transaction_id="${tx}" success="1"></response>`;
        case 'breakpoint_list':
          return `<response command="breakpoint_list" transaction_id="${tx}"><breakpoint id="bp-1" type="line" state="enabled" filename="file:///tmp/test.php" lineno="8"/></response>`;
        case 'breakpoint_get':
          return `<response command="breakpoint_get" transaction_id="${tx}"><breakpoint id="bp-1" type="line" state="enabled" filename="file:///tmp/test.php" lineno="8"/></response>`;
        case 'breakpoint_update':
          return `<response command="breakpoint_update" transaction_id="${tx}" success="1"></response>`;
        case 'stdout':
        case 'stderr':
        case 'status':
          return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
        default:
          return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
    });
    await engine.connect();
    cleanup.push(() => engine.close());

    const session = await server.waitForNextSession(2000);
    await session.waitForInit(2000);
    const inspector = new PhpDebugInspector(session);

    const feature = await inspector.featureGet('max_children');
    const source = await inspector.source({ fileUri: 'file:///tmp/test.php' });
    const property = await inspector.propertyGet('$cmd');
    const propertyValue = await inspector.propertyValue('$cmd');
    await inspector.propertySet('$cmd', 'whoami');
    const breakpoints = await inspector.breakpointList();
    const breakpoint = await inspector.breakpointGet('bp-1');
    await inspector.breakpointUpdate({ id: 'bp-1', state: 'disabled' });
    await inspector.setStdIo('stdout', 1);
    await inspector.setStdIo('stderr', 2);

    expect(feature?.supported).toBe(true);
    expect(feature?.value).toBe('128');
    expect(source).toContain('<?php');
    expect(property?.value).toBe('pwd');
    expect(propertyValue).toBe('pwd');
    expect(propertySetValue).toBe('whoami');
    expect(breakpoints).toHaveLength(1);
    expect(breakpoint?.id).toBe('bp-1');
    expect(session.getTranscript().length).toBeGreaterThan(5);
  });

  it('replays variations with per-run mutations via ReplayController', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    const seenMutations: string[] = [];
    const connectEngine = async () => {
      const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx, rawLine) => {
        if (command === 'property_set') {
          const payloadMatch = /--\s+([A-Za-z0-9+/=]+)$/u.exec(rawLine);
          if (payloadMatch) {
            seenMutations.push(Buffer.from(payloadMatch[1], 'base64').toString('utf8'));
          }
        }

        if (command === 'status') {
          return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
        }
        if (command === 'context_get') {
          return `<response command="context_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">cHdk</property></response>`;
        }
        if (command === 'stack_get') {
          return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="8"/></response>`;
        }
        if (command === 'run') {
          return `<response command="run" transaction_id="${tx}" status="break" reason="ok"></response>`;
        }
        return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      });
      await engine.connect();
      cleanup.push(() => engine.close());
    };

    const controller = new ReplayController(server, { sessionTimeoutMs: 1500 });
    const output = await controller.run(
      {
        variations: [
          { id: 'first', mutations: [{ propertyName: '$cmd', value: 'id' }] },
          { id: 'second', mutations: [{ propertyName: '$cmd', value: 'whoami' }] },
        ],
        continueAfterMutation: true,
        captureBefore: false,
        captureAfter: false,
      },
      async () => {
        await connectEngine();
      }
    );

    expect(output).toHaveLength(2);
    expect(seenMutations).toEqual(['id', 'whoami']);
  });

  it('supports baseline/reset helpers and matrix expansion in replay mode', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    const seenMutations: string[] = [];
    const connectEngine = async () => {
      const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx, rawLine) => {
        if (command === 'property_set') {
          const payloadMatch = /--\s+([A-Za-z0-9+/=]+)$/u.exec(rawLine);
          if (payloadMatch) {
            seenMutations.push(Buffer.from(payloadMatch[1], 'base64').toString('utf8'));
          }
        }

        if (command === 'status') {
          return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
        }
        if (command === 'context_names') {
          return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/></response>`;
        }
        if (command === 'context_get') {
          return `<response command="context_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">cHdk</property></response>`;
        }
        if (command === 'stack_get') {
          return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="9"/></response>`;
        }
        if (command === 'run') {
          return `<response command="run" transaction_id="${tx}" status="break" reason="ok"></response>`;
        }
        return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      });
      await engine.connect();
      cleanup.push(() => engine.close());
    };

    const controller = new ReplayController(server, { sessionTimeoutMs: 1500 });
    const output = await controller.run(
      {
        variations: [{ id: 'matrix-base', evalExpressions: ['$cmd'] }],
        baselineMutations: [{ propertyName: '$baseline', value: 'stable' }],
        matrix: [
          {
            propertyName: '$cmd',
            values: ['id', 'whoami'],
          },
        ],
        captureBaseline: true,
        captureBefore: false,
        captureAfter: false,
        continueAfterMutation: false,
      },
      async () => {
        await connectEngine();
      }
    );

    expect(output).toHaveLength(2);
    expect(output.every((entry) => entry.result.baselineSnapshot)).toBe(true);
    expect(output.map((entry) => entry.variation.id)).toEqual([
      'matrix-base__$cmd:id',
      'matrix-base__$cmd:whoami',
    ]);
    expect(seenMutations).toEqual(['stable', 'id', 'stable', 'whoami']);
  });

  it('computes deterministic replay hashes and passes post-reset drift checks', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    let cmdValue = 'initial';
    const connectEngine = async () => {
      const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx, rawLine) => {
        if (command === 'property_set') {
          const payloadMatch = /--\s+([A-Za-z0-9+/=]+)$/u.exec(rawLine);
          if (payloadMatch) {
            cmdValue = Buffer.from(payloadMatch[1], 'base64').toString('utf8');
          }
        }
        if (command === 'status') {
          return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
        }
        if (command === 'stack_get') {
          return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="12"/></response>`;
        }
        if (command === 'context_names') {
          return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/></response>`;
        }
        if (command === 'context_get') {
          const encoded = Buffer.from(cmdValue, 'utf8').toString('base64');
          return `<response command="context_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">${encoded}</property></response>`;
        }
        if (command === 'eval') {
          const encoded = Buffer.from(cmdValue, 'utf8').toString('base64');
          return `<response command="eval" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">${encoded}</property></response>`;
        }
        return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      });
      await engine.connect();
      cleanup.push(() => engine.close());
    };

    const controller = new ReplayController(server, { sessionTimeoutMs: 1500 });
    const output = await controller.run(
      {
        variations: [
          {
            id: 'deterministic',
            mutations: [{ propertyName: '$cmd', value: 'id' }],
            resetMutations: [{ propertyName: '$cmd', value: 'stable' }],
          },
        ],
        baselineMutations: [{ propertyName: '$cmd', value: 'stable' }],
        captureBaseline: true,
        captureBefore: false,
        captureAfter: false,
        capturePostReset: true,
        continueAfterMutation: false,
        deterministicChecks: {
          enabled: true,
          failOnDrift: true,
          comparePhase: 'post_reset',
          driftExpressions: ['$cmd'],
        },
      },
      async () => {
        await connectEngine();
      }
    );

    expect(output).toHaveLength(1);
    const result = output[0]?.result;
    expect(result?.errors).toEqual([]);
    expect(result?.driftDetected).toBe(false);
    expect(result?.baselineSnapshotHash).toBe(result?.postResetSnapshotHash);
    expect(result?.baselineEvalResults?.$cmd).toBe('stable');
    expect(result?.driftEvalResults?.$cmd).toBe('stable');
  });

  it('fails deterministic replay when drift is detected and failOnDrift is enabled', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    let cmdValue = 'initial';
    const connectEngine = async () => {
      const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx, rawLine) => {
        if (command === 'property_set') {
          const payloadMatch = /--\s+([A-Za-z0-9+/=]+)$/u.exec(rawLine);
          if (payloadMatch) {
            cmdValue = Buffer.from(payloadMatch[1], 'base64').toString('utf8');
          }
        }
        if (command === 'status') {
          return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
        }
        if (command === 'stack_get') {
          return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="13"/></response>`;
        }
        if (command === 'context_names') {
          return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/></response>`;
        }
        if (command === 'context_get') {
          const encoded = Buffer.from(cmdValue, 'utf8').toString('base64');
          return `<response command="context_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">${encoded}</property></response>`;
        }
        if (command === 'eval') {
          const encoded = Buffer.from(cmdValue, 'utf8').toString('base64');
          return `<response command="eval" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">${encoded}</property></response>`;
        }
        return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      });
      await engine.connect();
      cleanup.push(() => engine.close());
    };

    const controller = new ReplayController(server, { sessionTimeoutMs: 1500 });
    const output = await controller.run(
      {
        variations: [{ id: 'drift', mutations: [{ propertyName: '$cmd', value: 'id' }] }],
        baselineMutations: [{ propertyName: '$cmd', value: 'stable' }],
        captureBaseline: true,
        captureAfter: true,
        continueAfterMutation: false,
        deterministicChecks: {
          enabled: true,
          failOnDrift: true,
          comparePhase: 'post',
          driftExpressions: ['$cmd'],
        },
      },
      async () => {
        await connectEngine();
      }
    );

    expect(output).toHaveLength(1);
    const result = output[0]?.result;
    expect(result?.driftDetected).toBe(true);
    expect(result?.driftReasons?.length).toBeGreaterThan(0);
    expect(result?.errors.join(' ')).toContain('Determinism drift detected');
  });

  it('supports deterministic drift thresholds with expression allowlist', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    let cmdValue = 'initial';
    const connectEngine = async () => {
      const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx, rawLine) => {
        if (command === 'property_set') {
          const payloadMatch = /--\s+([A-Za-z0-9+/=]+)$/u.exec(rawLine);
          if (payloadMatch) {
            cmdValue = Buffer.from(payloadMatch[1], 'base64').toString('utf8');
          }
        }
        if (command === 'status') {
          return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
        }
        if (command === 'context_names') {
          return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/></response>`;
        }
        if (command === 'context_get') {
          const encoded = Buffer.from(cmdValue, 'utf8').toString('base64');
          return `<response command="context_get" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">${encoded}</property></response>`;
        }
        if (command === 'stack_get') {
          return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="13"/></response>`;
        }
        if (command === 'eval') {
          const encoded = Buffer.from(cmdValue, 'utf8').toString('base64');
          return `<response command="eval" transaction_id="${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">${encoded}</property></response>`;
        }
        return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      });
      await engine.connect();
      cleanup.push(() => engine.close());
    };

    const controller = new ReplayController(server, { sessionTimeoutMs: 1500 });
    const output = await controller.run(
      {
        variations: [{ id: 'allowlisted', mutations: [{ propertyName: '$cmd', value: 'id' }] }],
        baselineMutations: [{ propertyName: '$cmd', value: 'stable' }],
        captureBaseline: true,
        captureAfter: true,
        continueAfterMutation: false,
        deterministicChecks: {
          enabled: true,
          failOnDrift: true,
          comparePhase: 'post',
          driftExpressions: ['$cmd'],
          thresholds: {
            allowSnapshotDrift: true,
            maxExpressionDriftCount: 1,
            allowedExpressionDrift: ['$cmd'],
          },
        },
      },
      async () => {
        await connectEngine();
      }
    );

    expect(output).toHaveLength(1);
    const result = output[0]?.result;
    expect(result?.errors).toEqual([]);
    expect(result?.driftDetected).toBe(false);
    expect(result?.observedExpressionDrifts?.[0]?.allowed).toBe(true);
  });

  it('runs candidate bridge capture flow and persists transcript artifact', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    const artifactsDir = await mkdtemp(path.join(tmpdir(), 'dbgp-bridge-artifacts-'));
    cleanup.push(() => rm(artifactsDir, { recursive: true, force: true }));

    const bridge = new CandidateVerificationBridge(server, {
      artifactsDir,
      commandTimeoutMs: 1000,
      traceSteps: 1,
      watchExpressions: ['$watch'],
    });

    const results = await bridge.runCandidates(
      [
        {
          candidateId: 'cand-bridge-1',
          sinkCategory: 'rce',
          sinkName: 'system',
          metadata: {},
        },
      ],
      async () => {
        const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx) => {
          if (command === 'status') {
            return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
          }
          if (command === 'stack_get') {
            return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="10" where="bridge"/></response>`;
          }
          if (command === 'context_names') {
            return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/></response>`;
          }
          if (command === 'context_get') {
            return `<response command="context_get" transaction_id="${tx}"><property name="$watch" fullname="$watch" type="string" encoding="base64">YnJpZGdlLXZhbHVl</property></response>`;
          }
          if (command === 'step_over') {
            return `<response command="step_over" transaction_id="${tx}" status="break" reason="ok"></response>`;
          }
          if (command === 'eval') {
            return `<response command="eval" transaction_id="${tx}"><property name="$watch" fullname="$watch" type="string" encoding="base64">YnJpZGdlLXZhbHVl</property></response>`;
          }
          return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
        });
        await engine.connect();
        cleanup.push(() => engine.close());
      }
    );

    expect(results).toHaveLength(1);
    expect(results[0]?.appliedPolicyPack.name).toBe('rce');
    expect(results[0]?.appliedCaptureProfile.name).toBe('rce');
    expect(results[0]?.correlationId).toBe('cand-bridge-1');
    const artifactPath = results[0]?.artifactPath;
    expect(artifactPath).toBeTruthy();
    if (!artifactPath) {
      throw new Error('Expected artifact path');
    }

    const raw = await readFile(artifactPath, 'utf8');
    const parsed = JSON.parse(raw) as { schemaVersion: string; metadata: Record<string, string> };
    expect(parsed.schemaVersion).toBe('dbgp-transcript.v1');
    expect(parsed.metadata?.candidateId).toBe('cand-bridge-1');
  });

  it('orchestrates break and exception events with conditional auto-capture', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx) => {
      if (command === 'run') {
        return `<response command="run" transaction_id="${tx}" status="break" reason="ok"><xdebug:message filename="file:///tmp/test.php" lineno="77" exception="RuntimeException" message="boom"/></response>`;
      }
      if (command === 'status') {
        return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
      if (command === 'stack_get') {
        return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="77" where="main"/></response>`;
      }
      if (command === 'context_get') {
        return `<response command="context_get" transaction_id="${tx}"><property name="$watch" fullname="$watch" type="string" encoding="base64">d2F0Y2gtdmFsdWU=</property></response>`;
      }
      if (command === 'eval') {
        return `<response command="eval" transaction_id="${tx}"><property name="$watch" fullname="$watch" type="string" encoding="base64">d2F0Y2gtdmFsdWU=</property></response>`;
      }
      if (command === 'context_names') {
        return `<response command="context_names" transaction_id="${tx}"><context name="Locals" id="0"/></response>`;
      }
      return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
    });
    await engine.connect();
    cleanup.push(() => engine.close());

    const session = await server.waitForNextSession(2000);
    await session.waitForInit(2000);
    const inspector = new PhpDebugInspector(session);
    const orchestrator = new DebugEventOrchestrator(session, inspector);

    const breakEvents: Array<{ exceptionName?: string }> = [];
    const exceptionEvents: Array<{ exceptionName?: string }> = [];
    const captures: Array<{ ruleId: string; watchValues: Record<string, string | undefined> }> = [];

    orchestrator.onBreak((event) => {
      breakEvents.push({ exceptionName: event.exceptionName });
    });
    orchestrator.onException((event) => {
      exceptionEvents.push({ exceptionName: event.exceptionName });
    });
    orchestrator.addAutoCaptureRule({
      id: 'exception_capture',
      when: (event) => Boolean(event.exceptionName),
      watchExpressions: ['$watch'],
      snapshotContextIds: [0],
    });
    orchestrator.onAutoCapture((record) => {
      captures.push({ ruleId: record.ruleId, watchValues: record.watchValues });
    });

    orchestrator.start();
    await inspector.run();
    await orchestrator.flush();
    orchestrator.stop();

    expect(breakEvents).toHaveLength(1);
    expect(exceptionEvents).toHaveLength(1);
    expect(exceptionEvents[0]?.exceptionName).toBe('RuntimeException');
    expect(captures).toHaveLength(1);
    expect(captures[0]?.watchValues['$watch']).toBe('watch-value');
  });

  it('traces execution across multiple steps with watch expressions', async () => {
    const server = new DbgpServer({ host: '127.0.0.1', port: 0, commandTimeoutMs: 1000 });
    await server.start();
    cleanup.push(() => server.stop());
    const address = server.getAddress();
    if (!address) {
      throw new Error('Server address not available.');
    }

    let line = 20;
    let evalCounter = 0;
    const engine = new FakeXdebugEngine('127.0.0.1', address.port, (command, tx, _rawLine) => {
      switch (command) {
        case 'status':
          return `<response command="status" transaction_id="${tx}" status="break" reason="ok"></response>`;
        case 'step_over':
          line += 1;
          return `<response command="step_over" transaction_id="${tx}" status="break" reason="ok"></response>`;
        case 'stack_get':
          return `<response command="stack_get" transaction_id="${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="${line}" where="trace"/></response>`;
        case 'eval':
          evalCounter += 1;
          return `<response command="eval" transaction_id="${tx}"><property name="$watch" fullname="$watch" type="string" encoding="base64">${Buffer.from(`watch-${evalCounter}`, 'utf8').toString('base64')}</property></response>`;
        default:
          return `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`;
      }
    });
    await engine.connect();
    cleanup.push(() => engine.close());

    const session = await server.waitForNextSession(2000);
    await session.waitForInit(2000);
    const inspector = new PhpDebugInspector(session);
    const trace = await inspector.traceExecution({
      steps: 3,
      action: 'step_over',
      watchExpressions: ['$watch'],
    });

    expect(trace.steps).toHaveLength(3);
    expect(trace.steps[0]?.topFrame?.lineno).toBe(21);
    expect(trace.steps[2]?.topFrame?.lineno).toBe(23);
    expect(trace.steps[0]?.watchValues['$watch']).toBe('watch-1');
    expect(trace.steps[2]?.watchValues['$watch']).toBe('watch-3');
  });
});
