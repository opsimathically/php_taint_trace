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

describe('CLI verifier-decision-batch', () => {
  const cleanup: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    for (const fn of cleanup.reverse()) {
      await fn();
    }
    cleanup.length = 0;
  });

  it('processes candidate JSONL and appends one decision row per candidate', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-verifier-decision-batch-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));

    const port = await getAvailablePort();
    const engineScriptPath = path.join(dir, 'verifier_engine.mjs');
    const candidatesPath = path.join(dir, 'candidates.jsonl');
    const decisionsJsonlPath = path.join(dir, 'decisions.jsonl');
    const decisionDir = path.join(dir, 'decision_rows');

    await writeEngineScript(engineScriptPath);
    await writeFile(
      candidatesPath,
      [
        JSON.stringify({ candidate_id: 'cand-batch-1', sink_category: 'rce', request_uri: '/?cmd=id' }),
        JSON.stringify({ candidate_id: 'cand-batch-2', sink_category: 'rce', request_uri: '/?cmd=id' }),
      ].join('\n') + '\n',
      'utf8'
    );

    const result = await execFileAsync(
      process.execPath,
      [
        tsxCliPath,
        cliPath,
        'verifier-decision-batch',
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
        '--candidates-jsonl',
        candidatesPath,
        '--trigger-cmd',
        `bash -lc '${process.execPath} ${engineScriptPath} 127.0.0.1 ${port} >/dev/null 2>&1 &'`,
        '--decisions-jsonl',
        decisionsJsonlPath,
        '--decision-dir',
        decisionDir,
        '--attempts',
        '1',
        '--truncate-decisions-jsonl',
        '--output',
        'json',
      ],
      { cwd: projectRoot }
    );

    const payload = JSON.parse(result.stdout) as {
      ok?: boolean;
      processed?: number;
      confirmedCount?: number;
      nonConfirmedCount?: number;
      errorCount?: number;
      decisionsJsonlPath?: string;
      results?: Array<{ candidateId?: string; outcome?: string; confirmed?: boolean }>;
    };

    expect(payload.ok).toBe(true);
    expect(payload.processed).toBe(2);
    expect(payload.confirmedCount).toBe(2);
    expect(payload.nonConfirmedCount).toBe(0);
    expect(payload.errorCount).toBe(0);
    expect(payload.decisionsJsonlPath).toBe(path.resolve(decisionsJsonlPath));
    expect(payload.results).toHaveLength(2);
    expect(payload.results?.every((entry) => entry.outcome === 'confirmed')).toBe(true);

    const jsonlRaw = await readFile(decisionsJsonlPath, 'utf8');
    const lines = jsonlRaw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '');
    expect(lines).toHaveLength(2);
    const rows = lines.map((line) => JSON.parse(line) as { candidate_id?: string; outcome?: string });
    expect(rows.map((entry) => entry.candidate_id)).toEqual(['cand-batch-1', 'cand-batch-2']);
    expect(rows.every((entry) => entry.outcome === 'confirmed')).toBe(true);
  }, 20000);

  it('supports fail-on-unconfirmed gate while still emitting decision rows', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-cli-verifier-decision-batch-gate-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));

    const port = await getAvailablePort();
    const engineScriptPath = path.join(dir, 'verifier_engine.mjs');
    const candidatesPath = path.join(dir, 'candidates.jsonl');
    const decisionsJsonlPath = path.join(dir, 'decisions.jsonl');

    await writeEngineScript(engineScriptPath);
    await writeFile(
      candidatesPath,
      [
        JSON.stringify({ candidate_id: 'cand-ok', sink_category: 'rce', request_uri: '/?cmd=id' }),
        JSON.stringify({ candidate_id: 'cand-miss', sink_category: 'rce', request_uri: '/?cmd=id' }),
      ].join('\n') + '\n',
      'utf8'
    );

    let threw = false;
    try {
      await execFileAsync(
        process.execPath,
        [
          tsxCliPath,
          cliPath,
          'verifier-decision-batch',
          '--host',
          '127.0.0.1',
          '--port',
          String(port),
          '--candidates-jsonl',
          candidatesPath,
          '--trigger-cmd',
          `bash -lc 'if [ ${'${candidateId}'} = '\''cand-ok'\'' ]; then ${process.execPath} ${engineScriptPath} 127.0.0.1 ${port} >/dev/null 2>&1 & fi'`,
          '--decisions-jsonl',
          decisionsJsonlPath,
          '--attempts',
          '1',
          '--truncate-decisions-jsonl',
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
        processed?: number;
        confirmedCount?: number;
        nonConfirmedCount?: number;
      };
      expect(payload.ok).toBe(false);
      expect(payload.processed).toBe(2);
      expect(payload.confirmedCount).toBe(1);
      expect(payload.nonConfirmedCount).toBe(1);
    }

    expect(threw).toBe(true);

    const jsonlRaw = await readFile(decisionsJsonlPath, 'utf8');
    const rows = jsonlRaw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '')
      .map((line) => JSON.parse(line) as { candidate_id?: string; outcome?: string });
    expect(rows).toHaveLength(2);
    expect(rows.map((entry) => entry.candidate_id)).toEqual(['cand-ok', 'cand-miss']);
    expect(rows.map((entry) => entry.outcome)).toEqual(['confirmed', 'replay_failed']);
  }, 20000);
});

async function writeEngineScript(scriptPath: string): Promise<void> {
  await writeFile(
    scriptPath,
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
  send('<init appid="900" idekey="sdk-test" session="verifier-cli-batch" language="PHP" protocol_version="1.0" fileuri="file:///tmp/test.php"><engine version="3.3.0" name="Xdebug"></engine></init>');
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
}

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
