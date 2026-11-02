import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { DbgpSession } from '../server/DbgpSession.js';
import { redactTranscriptEntries } from './redaction.js';
import type { TranscriptArtifactV1, TranscriptStoreOptions } from './types.js';

export class TranscriptArtifactStore {
  async persistSession(
    session: DbgpSession,
    outputPath: string,
    options: TranscriptStoreOptions = {}
  ): Promise<string> {
    const dir = path.dirname(outputPath);
    await mkdir(dir, { recursive: true });

    const entries = options.redaction
      ? redactTranscriptEntries(session.getTranscript(), options.redaction)
      : [...session.getTranscript()];
    const payload: TranscriptArtifactV1 = {
      schemaVersion: 'dbgp-transcript.v1',
      createdAt: new Date().toISOString(),
      sessionId: session.id,
      metadata: options.metadata,
      entries,
    };

    await writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    return outputPath;
  }
}
