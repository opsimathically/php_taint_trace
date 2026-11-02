import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const thisFile = fileURLToPath(import.meta.url);
const projectRoot = path.resolve(path.dirname(thisFile), '../..');
const tsxCliPath = path.resolve(projectRoot, 'node_modules/tsx/dist/cli.mjs');
const cliPath = path.resolve(projectRoot, 'src/cli.ts');

describe('CLI verifier-decision', () => {
  const cleanup: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    for (const fn of cleanup.reverse()) {
      await fn();
    }
    cleanup.length = 0;
  });

  it('emits verifier decision payload and writes json/jsonl outputs', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-verifier-decision-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const port = await getAvailablePort();
    const engineScriptPath = path.join(dir, 'verifier_engine.mjs');
    const artifactDir = path.join(dir, 'artifacts');
    const manifestPath = path.join(artifactDir, 'replay-attempts.manifest.json');
    const decisionPath = path.join(dir, 'decision.json');
    const decisionJsonlPath = path.join(dir, 'decisions.jsonl');

    await writeFile(
      engineScriptPath,
      `
import net from 'node:net';
const host = process.argv[2];
const port = Number(process.argv[3]);
const socket = net.createConnection({ host, port });
let pending = Buffer.alloc(0);

function encode(xml) {
  return Buffer.concat([Buffer.from(String(Buffer.byteLength(xml, 'utf8'))), Buffer.from([0]), Buffer.from(xml), Buffer.from([0])]);
}
function send(xml) {
  socket.write(encode(xml));
}

socket.on('connect', () => {
  send('<init appid="900" idekey="sdk-test" session="verifier-cli" language="PHP" protocol_version="1.0" fileuri="file:///tmp/test.php"><engine version="3.3.0" name="Xdebug"></engine></init>');
});

socket.on('data', (chunk) => {
  pending = Buffer.concat([pending, chunk]);
  while (true) {
    const sep = pending.indexOf(0x00);
    if (sep === -1) break;
    const line = pending.subarray(0, sep).toString('utf8').trim();
    pending = pending.subarray(sep + 1);
    if (!line) continue;
    const command = line.split(/\\s+/u)[0];
    const txMatch = /-i\\s+(\\d+)/u.exec(line);
    const tx = txMatch ? Number(txMatch[1]) : 0;
    if (command === 'status' || command === 'step_into' || command === 'step_over') {
      send(\`<response command="\${command}" transaction_id="\${tx}" status="break" reason="ok"></response>\`);
      continue;
    }
    if (command === 'stack_get') {
      send(\`<response command="stack_get" transaction_id="\${tx}"><stack level="0" type="file" filename="file:///tmp/test.php" lineno="14" where="main"/></response>\`);
      continue;
    }
    if (command === 'context_names') {
      send(\`<response command="context_names" transaction_id="\${tx}"><context name="Locals" id="0"/></response>\`);
      continue;
    }
    if (command === 'context_get') {
      send(\`<response command="context_get" transaction_id="\${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>\`);
      continue;
    }
    if (command === 'eval') {
      send(\`<response command="eval" transaction_id="\${tx}"><property name="$cmd" fullname="$cmd" type="string" encoding="base64">aWQ=</property></response>\`);
      continue;
    }
    if (command === 'property_set') {
      send(\`<response command="property_set" transaction_id="\${tx}" success="1"></response>\`);
      continue;
    }
    if (command === 'run') {
      send(\`<response command="run" transaction_id="\${tx}" status="stopping" reason="ok"></response>\`);
      continue;
    }
    send(\`<response command="\${command}" transaction_id="\${tx}" status="break" reason="ok"></response>\`);
  }
});
socket.on('end', () => process.exit(0));
setTimeout(() => socket.end(), 10000);
      `.trim(),
      'utf8'
    );

    const result = await execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'verifier-decision',
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
        '--candidate-id',
        'cand-cli-1',
        '--sink-category',
        'rce',
        '--attempts',
        '1',
        '--trigger-cmd',
        `bash -lc '${process.execPath} ${engineScriptPath} 127.0.0.1 ${port} >/dev/null 2>&1 &'`,
        '--artifact-dir',
        artifactDir,
        '--manifest-path',
        manifestPath,
        '--decision-output',
        decisionPath,
        '--decision-jsonl',
        decisionJsonlPath,
        '--fail-on-unconfirmed',
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );

    const payload = JSON.parse(result.stdout) as {
      ok?: boolean;
      confirmed?: boolean;
      decision?: { outcome?: string; candidate_id?: string };
      decisionOutputPath?: string;
      decisionJsonlPath?: string;
      replay?: { artifactManifestPath?: string };
    };
    expect(payload.ok).toBe(true);
    expect(payload.confirmed).toBe(true);
    expect(payload.decision?.outcome).toBe('confirmed');
    expect(payload.decision?.candidate_id).toBe('cand-cli-1');
    expect(payload.decisionOutputPath).toBe(path.resolve(decisionPath));
    expect(payload.decisionJsonlPath).toBe(path.resolve(decisionJsonlPath));
    expect(payload.replay?.artifactManifestPath).toBe(path.resolve(manifestPath));

    const decisionRaw = await readFile(decisionPath, 'utf8');
    const decision = JSON.parse(decisionRaw) as { outcome?: string; candidate_id?: string };
    expect(decision.outcome).toBe('confirmed');
    expect(decision.candidate_id).toBe('cand-cli-1');

    const jsonlRaw = await readFile(decisionJsonlPath, 'utf8');
    const lines = jsonlRaw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '');
    expect(lines).toHaveLength(1);
    const linePayload = JSON.parse(lines[0]) as { outcome?: string };
    expect(linePayload.outcome).toBe('confirmed');
  }, 20000);

  it('supports fail-on-unconfirmed gate with non-zero exit on replay failure', async () => {
    let threw = false;
    try {
      await execFileAsync(
        process.execPath,
        [
          tsxCliPath,
          cliPath,
          'verifier-decision',
          '--candidate-id',
          'cand-cli-timeout',
          '--sink-category',
          'rce',
          '--attempts',
          '1',
          '--timeout-ms',
          '100',
          '--fail-on-unconfirmed',
          '--output',
          'json',
        ],
        { cwd: projectRoot }
      );
    } catch (error) {
      threw = true;
      const output = error as { stdout?: string };
      const payload = JSON.parse(output.stdout ?? '{}') as {
        ok?: boolean;
        confirmed?: boolean;
        decision?: { outcome?: string };
      };
      expect(payload.ok).toBe(false);
      expect(payload.confirmed).toBe(false);
      expect(payload.decision?.outcome).toBe('replay_failed');
    }

    expect(threw).toBe(true);
  });
});

async function getAvailablePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (!Number.isFinite(port) || port <= 0) {
    throw new Error('Unable to reserve ephemeral port.');
  }
  return port;
}
