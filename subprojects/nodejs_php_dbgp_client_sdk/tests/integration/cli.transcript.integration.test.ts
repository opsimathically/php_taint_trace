import { execFile } from 'node:child_process';
import net from 'node:net';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { DbgpFrameCodec } from '../../src/protocol/DbgpFrameCodec.js';

const execFileAsync = promisify(execFile);
const thisFile = fileURLToPath(import.meta.url);
const projectRoot = path.resolve(path.dirname(thisFile), '../..');
const tsxCliPath = path.resolve(projectRoot, 'node_modules/tsx/dist/cli.mjs');
const cliPath = path.resolve(projectRoot, 'src/cli.ts');

describe('CLI transcript artifact flow', () => {
  const cleanup: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    for (const fn of cleanup.reverse()) {
      await fn();
    }
    cleanup.length = 0;
  });

  it('applies redaction plugin during transcript-save artifact persistence', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-transcript-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const artifactPath = path.join(dir, 'session.transcript.json');
    const pluginPath = path.resolve(projectRoot, 'tests/fixtures/plugins/stream-redaction-plugin.ts');
    const port = await getFreePort();

    const cliPromise = execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'transcript-save',
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
        '--timeout-ms',
        '4000',
        '--artifact-path',
        artifactPath,
        '--redaction-plugin',
        pluginPath,
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );

    await driveCliSession(port);
    const output = await cliPromise;

    const parsed = JSON.parse(output.stdout.trim()) as {
      ok: boolean;
      data?: { artifactPath?: string };
    };
    expect(parsed.ok).toBe(true);
    expect(parsed.data?.artifactPath).toBe(artifactPath);

    const raw = await readFile(artifactPath, 'utf8');
    const artifact = JSON.parse(raw) as {
      entries: Array<{ type: string; payload: { payload?: string } }>;
    };
    const streamPayloads = artifact.entries
      .filter((entry) => entry.type === 'stream')
      .map((entry) => entry.payload?.payload ?? '');

    expect(streamPayloads.length).toBeGreaterThan(0);
    expect(streamPayloads.some((payload) => payload.includes('APIKEY=[REDACTED]'))).toBe(true);
    expect(streamPayloads.some((payload) => payload.includes('secret123'))).toBe(false);
  });
});

async function getFreePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.once('error', (error) => reject(error));
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Failed to allocate free port.'));
        return;
      }
      const port = address.port;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
  });
}

async function driveCliSession(port: number): Promise<void> {
  const socket = await waitForConnection('127.0.0.1', port, 4000);
  socket.write(
    DbgpFrameCodec.encode(
      '<init appid="901" idekey="sdk-cli-test" session="cli-1" language="PHP" protocol_version="1.0" fileuri="file:///tmp/cli.php"><engine version="3.3.0" name="Xdebug"></engine></init>'
    )
  );

  let pending = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    while (true) {
      const sep = pending.indexOf(0x00);
      if (sep === -1) {
        break;
      }
      const line = pending.subarray(0, sep).toString('utf8').trim();
      pending = pending.subarray(sep + 1);
      if (!line) {
        continue;
      }
      const command = line.split(/\s+/u)[0];
      const txMatch = /-i\s+(\d+)/u.exec(line);
      const tx = txMatch ? Number(txMatch[1]) : 0;

      if (command === 'status') {
        socket.write(
          DbgpFrameCodec.encode(
            `<response command="status" transaction_id="${tx}" status="starting" reason="ok"></response>`
          )
        );
        continue;
      }

      if (command === 'step_into') {
        socket.write(DbgpFrameCodec.encode('<stream type="stdout">APIKEY=secret123</stream>'));
        socket.write(
          DbgpFrameCodec.encode(
            `<response command="step_into" transaction_id="${tx}" status="break" reason="ok"></response>`
          )
        );
        continue;
      }

      socket.write(
        DbgpFrameCodec.encode(
          `<response command="${command}" transaction_id="${tx}" status="break" reason="ok"></response>`
        )
      );
    }
  });

  await new Promise<void>((resolve) => {
    socket.once('close', () => resolve());
    socket.once('end', () => resolve());
  });
}

async function waitForConnection(host: string, port: number, timeoutMs: number): Promise<net.Socket> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const socket = await new Promise<net.Socket>((resolve, reject) => {
        const candidate = net.createConnection({ host, port });
        candidate.once('connect', () => resolve(candidate));
        candidate.once('error', (error) => {
          candidate.destroy();
          reject(error);
        });
      });
      return socket;
    } catch {
      await new Promise<void>((resolve) => setTimeout(resolve, 50));
    }
  }

  throw new Error(`Timed out connecting to ${host}:${port}`);
}
