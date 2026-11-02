import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import { exec as execCallback } from 'node:child_process';
import { DbgpServer, PhpDebugInspector, ReplayController } from '../src/index.js';

const exec = promisify(execCallback);

interface ContainerProfile {
  ipv4: string;
  ssh_username: string;
  ssh_password: string;
}

interface ParsedArgs {
  configPath?: string;
  profile?: string;
  host?: string;
  user?: string;
  password?: string;
  localHost?: string;
  port: number;
}

interface RemoteRunResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const profile = loadProfile(args.configPath, args.profile);
  const remoteHost = args.host ?? profile?.ipv4;
  const remoteUser = args.user ?? profile?.ssh_username;
  const remotePassword = args.password ?? profile?.ssh_password;

  if (!remoteHost || !remoteUser || !remotePassword) {
    throw new Error('Remote host/user/password must be provided via args or config profile.');
  }

  const localHost = args.localHost ?? (await detectLocalHost(remoteHost));
  const port = args.port;
  const server = new DbgpServer({ host: '0.0.0.0', port, commandTimeoutMs: 7000, strict: true });
  await server.start();

  const remoteRuns: Array<Promise<RemoteRunResult>> = [];
  try {
    const directSessionPromise = server.waitForNextSession(15000);
    remoteRuns.push(
      triggerRemotePhp({
        remoteHost,
        remoteUser,
        remotePassword,
        localHost,
        port,
      })
    );

    const directSession = await directSessionPromise;
    const inspector = new PhpDebugInspector(directSession, { commandTimeoutMs: 7000, strict: true });
    const init = await directSession.waitForInit(7000);
    await inspector.breakpointSet({
      type: 'line',
      fileUri: init.fileUri,
      line: 8,
    });
    await inspector.run();
    const before = await inspector.propertyValue('$cmd');
    const setResponse = await inspector.propertySet('$cmd', 'id');
    if (
      typeof setResponse.attributes.success === 'string' &&
      setResponse.attributes.success !== '1'
    ) {
      await inspector.evaluate("$cmd = 'id'");
    }
    const after = await inspector.evaluate('$cmd');
    await inspector.run();
    directSession.close();
    await waitForNoSessions(server, 5000);

    const directRemoteResult = await remoteRuns.shift();
    if (!directRemoteResult) {
      throw new Error('Missing direct remote execution result.');
    }
    assertOk(directRemoteResult);
    if (!directRemoteResult.stdout.includes('DBGPCMD=id')) {
      throw new Error(`Expected DBGPCMD=id in direct remote stdout, got: ${directRemoteResult.stdout}`);
    }

    const controller = new ReplayController(server, { sessionTimeoutMs: 15000, commandTimeoutMs: 7000 });
    const replayResults = await controller.run(
      {
        breakpoints: [
          {
            type: 'line',
            fileUri: 'file:///tmp/dbgp_sdk_smoke.php',
            line: 8,
          },
        ],
        variations: [
          { id: 'var-id', mutations: [{ propertyName: '$cmd', value: 'id' }] },
          { id: 'var-whoami', mutations: [{ propertyName: '$cmd', value: 'whoami' }] },
        ],
        continueAfterMutation: true,
      },
      async () => {
        remoteRuns.push(
          triggerRemotePhp({
            remoteHost,
            remoteUser,
            remotePassword,
            localHost,
            port,
          })
        );
      }
    );

    const replayRemoteResults = await Promise.all(remoteRuns);
    replayRemoteResults.forEach(assertOk);
    const replayStdout = replayRemoteResults.map((value) => value.stdout).join('\n');
    if (!replayStdout.includes('DBGPCMD=id') || !replayStdout.includes('DBGPCMD=whoami')) {
      throw new Error(`Replay outputs did not contain expected mutations. Output: ${replayStdout}`);
    }

    const traceSessionPromise = server.waitForNextSession(15000);
    const traceRemoteRun = triggerRemotePhp({
      remoteHost,
      remoteUser,
      remotePassword,
      localHost,
      port,
    });
    const traceSession = await traceSessionPromise;
    const traceInspector = new PhpDebugInspector(traceSession, { commandTimeoutMs: 7000, strict: true });
    const traceInit = await traceSession.waitForInit(7000);
    await traceInspector.breakpointSet({ type: 'line', fileUri: traceInit.fileUri, line: 4 });
    await traceInspector.run();
    const trace = await traceInspector.traceExecution({
      steps: 2,
      action: 'step_over',
      watchExpressions: ['$cmd'],
    });
    traceSession.close();
    await waitForNoSessions(server, 5000);
    const traceRemoteResult = await traceRemoteRun;
    assertOk(traceRemoteResult);
    if (trace.steps.length === 0) {
      throw new Error('Trace execution produced zero steps.');
    }

    const output = {
      ok: true,
      remoteHost,
      localHost,
      port,
      direct: {
        before,
        after,
        stdout: directRemoteResult.stdout.trim(),
      },
      replay: replayResults.map((entry) => ({
        variationId: entry.variation.id,
        sessionId: entry.sessionId,
        runStatus: entry.result.runStatus,
        errors: entry.result.errors,
      })),
      trace: {
        steps: trace.steps.length,
        firstStepStatus: trace.steps[0]?.status,
        firstTopFrame: trace.steps[0]?.topFrame,
      },
    };
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  } finally {
    await server.stop();
  }
}

async function waitForNoSessions(server: DbgpServer, timeoutMs: number): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (server.getSessions().length === 0) {
      return;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
  }
}

function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = { port: 19103 };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (!next) {
      continue;
    }

    if (arg === '--config') {
      parsed.configPath = next;
      i += 1;
    } else if (arg === '--profile') {
      parsed.profile = next;
      i += 1;
    } else if (arg === '--host') {
      parsed.host = next;
      i += 1;
    } else if (arg === '--user') {
      parsed.user = next;
      i += 1;
    } else if (arg === '--password') {
      parsed.password = next;
      i += 1;
    } else if (arg === '--local-host') {
      parsed.localHost = next;
      i += 1;
    } else if (arg === '--port') {
      parsed.port = Number(next);
      i += 1;
    }
  }

  return parsed;
}

function loadProfile(configPath?: string, profileKey?: string): ContainerProfile | undefined {
  if (!configPath) {
    return undefined;
  }

  const raw = readFileSync(configPath, 'utf8');
  const parsed = JSON.parse(raw) as Record<string, ContainerProfile>;
  const key = profileKey ?? Object.keys(parsed)[0];
  if (!key) {
    return undefined;
  }

  return parsed[key];
}

async function detectLocalHost(remoteHost: string): Promise<string> {
  const { stdout } = await exec(`ip -4 route get ${remoteHost}`);
  const match = stdout.match(/\bsrc\s+([0-9.]+)/u);
  if (!match) {
    throw new Error(`Could not detect local source IP for remote host ${remoteHost}.`);
  }

  return match[1];
}

function triggerRemotePhp(options: {
  remoteHost: string;
  remoteUser: string;
  remotePassword: string;
  localHost: string;
  port: number;
}): Promise<RemoteRunResult> {
  const script = [
    '<?php',
    '$cmd="initial";',
    '$a=1;',
    '$b=2;',
    '$c=$a+$b;',
    '$d=$c+1;',
    '$e=$d+1;',
    'echo "DBGPCMD=".$cmd.PHP_EOL;',
  ].join('\n');
  const scriptBase64 = Buffer.from(script, 'utf8').toString('base64');
  const scriptPath = '/tmp/dbgp_sdk_smoke.php';

  const remoteCommand = [
    `echo ${scriptBase64} | base64 -d > ${scriptPath}`,
    '&&',
    'php',
    '-dxdebug.mode=debug',
    '-dxdebug.start_with_request=yes',
    `-dxdebug.client_host=${options.localHost}`,
    `-dxdebug.client_port=${options.port}`,
    '-dxdebug.discover_client_host=0',
    scriptPath,
  ].join(' ');

  return new Promise<RemoteRunResult>((resolve, reject) => {
    const child = spawn(
      'sshpass',
      [
        '-p',
        options.remotePassword,
        'ssh',
        '-o',
        'StrictHostKeyChecking=no',
        `${options.remoteUser}@${options.remoteHost}`,
        remoteCommand,
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });
    child.once('error', (error) => reject(error));
    child.once('close', (code) => resolve({ stdout, stderr, code }));
  });
}

function assertOk(result: RemoteRunResult): void {
  if (result.code !== 0) {
    throw new Error(`Remote PHP command failed (code ${result.code}): ${result.stderr}`);
  }
}

main().catch((error) => {
  if (error instanceof Error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
  } else {
    process.stderr.write(`${String(error)}\n`);
  }
  process.exitCode = 1;
});
