import { DbgpServer, PhpDebugInspector } from '../src/index.js';

async function main(): Promise<void> {
  const server = new DbgpServer({ host: '127.0.0.1', port: 9003, strict: true });
  await server.start();
  const address = server.getAddress();
  process.stdout.write(
    `Listening for Xdebug on ${address?.address ?? '127.0.0.1'}:${address?.port ?? 9003}\n`
  );

  try {
    const session = await server.waitForNextSession(30000);
    const inspector = new PhpDebugInspector(session, { commandTimeoutMs: 5000, strict: true });
    const snapshot = await inspector.captureSnapshot([0]);
    process.stdout.write(`${JSON.stringify(snapshot, null, 2)}\n`);
  } finally {
    await server.stop();
  }
}

main().catch((error) => {
  process.stderr.write(`Snapshot capture failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
