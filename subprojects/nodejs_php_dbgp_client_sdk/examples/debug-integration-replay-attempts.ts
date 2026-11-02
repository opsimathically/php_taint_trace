import path from 'node:path';
import { DbgpServer, DebugIntegrationService } from '../src/index.js';

async function main(): Promise<void> {
  const server = new DbgpServer({ host: '127.0.0.1', port: 9003, strict: true });
  await server.start();
  const address = server.getAddress();
  process.stdout.write(
    `Listening for replay-attempt orchestration on ${address?.address ?? '127.0.0.1'}:${address?.port ?? 9003}\n`
  );

  const integration = new DebugIntegrationService(server, {
    commandTimeoutMs: 7000,
    sessionTimeoutMs: 30000,
    primeAction: 'step_into',
    snapshotContextIds: [0, 1],
  });

  try {
    const result = await integration.runReplayAttempts({
      trigger: {
        candidateId: 'demo-replay-attempts',
        sinkCategory: 'rce',
        sinkName: 'system',
        requestUri: '/?cmd=id',
      },
      attempts: 3,
      stopOnFirstSuccess: true,
      includeTranscript: true,
      artifactDir: path.resolve('.dbgp_replay_attempt_artifacts'),
    });

    process.stdout.write(
      `${JSON.stringify(
        {
          ok: true,
          finalStatus: result.bundle.finalStatus,
          successfulAttempt: result.bundle.successfulAttempt,
          attempts: result.bundle.attempts,
          artifactManifestPath: result.artifactManifestPath,
        },
        null,
        2
      )}\n`
    );
  } finally {
    await server.stop();
  }
}

main().catch((error) => {
  process.stderr.write(
    `Replay-attempt debug integration failed: ${error instanceof Error ? error.message : String(error)}\n`
  );
  process.exitCode = 1;
});
