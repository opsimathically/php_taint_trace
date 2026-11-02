import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createReplayArtifactManifest,
  verifyReplayArtifactManifest,
} from '../../src/replay/manifest.js';

describe('replay artifact manifest', () => {
  const cleanup: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    for (const fn of cleanup.reverse()) {
      await fn();
    }
    cleanup.length = 0;
  });

  it('builds and verifies manifest entries', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-replay-manifest-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const replayPath = path.join(dir, 'replay.json');
    const diffPath = path.join(dir, 'diff.json');

    await writeFile(replayPath, '{"ok":true}\n', 'utf8');
    await writeFile(diffPath, '{"drift":0}\n', 'utf8');

    const manifest = createReplayArtifactManifest(
      [
        { kind: 'replay_results', path: replayPath },
        { kind: 'replay_diff', path: diffPath },
      ],
      {
        baseDir: dir,
        signature: {
          hmacSecret: 'topsecret',
          keyId: 'test-key',
        },
      }
    );
    const verification = verifyReplayArtifactManifest(manifest, {
      baseDir: dir,
      hmacSecret: 'topsecret',
    });

    expect(manifest.schema).toBe('dbgp-replay-manifest.v1');
    expect(manifest.entries).toHaveLength(2);
    expect(manifest.signature?.algorithm).toBe('hmac-sha256');
    expect(manifest.signature?.keyId).toBe('test-key');
    expect(verification.ok).toBe(true);
    expect(verification.mismatches).toHaveLength(0);
    expect(verification.signature.verified).toBe(true);
  });

  it('reports mismatches when artifacts drift', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-replay-manifest-drift-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const replayPath = path.join(dir, 'replay.json');

    await writeFile(replayPath, '{"ok":true}\n', 'utf8');
    const manifest = createReplayArtifactManifest([{ kind: 'replay_results', path: replayPath }], {
      baseDir: dir,
    });

    await writeFile(replayPath, '{"ok":false}\n', 'utf8');
    const verification = verifyReplayArtifactManifest(manifest, { baseDir: dir });

    expect(verification.ok).toBe(false);
    expect(verification.mismatches.some((entry) => entry.reason === 'sha256_mismatch')).toBe(true);
  });

  it('fails signature verification when secret is missing or invalid', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-replay-manifest-signature-'));
    cleanup.push(() => rm(dir, { recursive: true, force: true }));
    const replayPath = path.join(dir, 'replay.json');

    await writeFile(replayPath, '{"ok":true}\n', 'utf8');
    const manifest = createReplayArtifactManifest([{ kind: 'replay_results', path: replayPath }], {
      baseDir: dir,
      signature: {
        hmacSecret: 'valid',
      },
    });

    const missingSecret = verifyReplayArtifactManifest(manifest, { baseDir: dir });
    expect(missingSecret.ok).toBe(false);
    expect(missingSecret.signature.error).toBe('signature_present_but_no_secret_provided');

    const invalidSecret = verifyReplayArtifactManifest(manifest, {
      baseDir: dir,
      hmacSecret: 'invalid',
    });
    expect(invalidSecret.ok).toBe(false);
    expect(invalidSecret.signature.error).toBe('signature_digest_mismatch');
  });
});
