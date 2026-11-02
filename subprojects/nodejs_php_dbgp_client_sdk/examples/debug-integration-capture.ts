import { DbgpServer, DebugIntegrationService } from '../src/index.js';

async function main(): Promise<void> {
  const server = new DbgpServer({ host: '127.0.0.1', port: 9003, strict: true });
  await server.start();
  const address = server.getAddress();
  process.stdout.write(
    `Listening for sink-driven debug capture on ${address?.address ?? '127.0.0.1'}:${address?.port ?? 9003}\n`
  );

  const integration = new DebugIntegrationService(server, {
    commandTimeoutMs: 7000,
    sessionTimeoutMs: 30000,
    primeAction: 'step_into',
    snapshotContextIds: [0, 1],
  });

  try {
    const result = await integration.captureForTrigger({
      trigger: {
        candidateId: 'demo-candidate',
        sinkCategory: 'rce',
        sinkName: 'system',
        requestUri: '/?cmd=id',
      },
      includeTranscript: true,
      evaluateExpressions: ['$cmd', '$_GET["cmd"]'],
      tracePlan: {
        steps: 2,
        action: 'step_over',
        watchExpressions: ['$cmd'],
      },
      normalization: {
        maxStringLength: 256,
      },
    });

    process.stdout.write(
      `${JSON.stringify(
        {
          ok: true,
          sessionId: result.sessionId,
          trigger: result.trigger,
          errors: result.errors,
          evidence: result.evidence,
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
    `Debug integration capture failed: ${error instanceof Error ? error.message : String(error)}\n`
  );
  process.exitCode = 1;
});
