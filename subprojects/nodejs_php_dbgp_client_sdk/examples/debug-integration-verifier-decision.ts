import { DbgpServer, DebugIntegrationService } from '../src/index.js';

async function main(): Promise<void> {
  const server = new DbgpServer({ host: '127.0.0.1', port: 9003, strict: true });
  await server.start();
  const address = server.getAddress();
  process.stdout.write(
    `Listening for verifier-decision orchestration on ${address?.address ?? '127.0.0.1'}:${address?.port ?? 9003}\n`
  );

  const integration = new DebugIntegrationService(server, {
    commandTimeoutMs: 7000,
    sessionTimeoutMs: 30000,
    primeAction: 'step_into',
  });

  try {
    const result = await integration.runReplayAttemptsAsVerifierDecision({
      trigger: {
        candidateId: 'demo-verifier-decision',
        sinkCategory: 'rce',
        sinkName: 'system',
        requestUri: '/?cmd=id',
      },
      attempts: 3,
      stopOnFirstSuccess: true,
    });

    process.stdout.write(
      `${JSON.stringify(
        {
          ok: true,
          finalStatus: result.replay.bundle.finalStatus,
          successfulAttempt: result.replay.bundle.successfulAttempt,
          verificationResult: result.verificationResult,
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
    `Verifier decision integration failed: ${error instanceof Error ? error.message : String(error)}\n`
  );
  process.exitCode = 1;
});
