import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { TranscriptArtifactStore } from '../../src/transcript/TranscriptArtifactStore.js';
import { redactTranscriptEntries } from '../../src/transcript/redaction.js';
import type { DbgpSession } from '../../src/server/DbgpSession.js';
import type { DbgpTranscriptEntry } from '../../src/server/DbgpSession.js';

describe('transcript redaction and artifact store', () => {
  it('redacts sensitive keys and token patterns', () => {
    const entries: DbgpTranscriptEntry[] = [
      {
        timestamp: new Date().toISOString(),
        direction: 'out',
        type: 'command',
        payload: {
          password: 'hunter2',
          nested: { authorization: 'Bearer abc.def.ghi' },
          notes: 'safe',
        },
      },
    ];

    const redacted = redactTranscriptEntries(entries);
    const payload = redacted[0]?.payload as Record<string, unknown>;
    expect(payload.password).toBe('[REDACTED]');
    expect(payload.nested).toEqual({ authorization: '[REDACTED]' });
    expect(payload.notes).toBe('safe');
  });

  it('writes persisted transcript artifact schema', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-transcript-test-'));
    const output = path.join(dir, 'artifact.json');
    const store = new TranscriptArtifactStore();
    const fakeSession = {
      id: 'session-1',
      getTranscript() {
        return [
          {
            timestamp: new Date().toISOString(),
            direction: 'in',
            type: 'response',
            payload: { ok: true, token: 'abc123' },
          },
        ] satisfies DbgpTranscriptEntry[];
      },
    };

    await store.persistSession(fakeSession as unknown as DbgpSession, output, { redaction: {} });
    const raw = await readFile(output, 'utf8');
    const parsed = JSON.parse(raw) as {
      schemaVersion: string;
      sessionId: string;
      entries: Array<{ payload: Record<string, unknown> }>;
    };

    expect(parsed.schemaVersion).toBe('dbgp-transcript.v1');
    expect(parsed.sessionId).toBe('session-1');
    expect(parsed.entries[0]?.payload.token).toBe('[REDACTED]');
    await rm(dir, { recursive: true, force: true });
  });
});
