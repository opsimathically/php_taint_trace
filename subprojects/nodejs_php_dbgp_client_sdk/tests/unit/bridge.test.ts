import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { CandidateVerificationBridge } from '../../src/bridge/CandidateVerificationBridge.js';

describe('CandidateVerificationBridge candidate loading', () => {
  it('loads candidates from mixed candidate and envelope JSONL', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'dbgp-candidates-'));
    const file = path.join(dir, 'candidates.jsonl');
    const lines = [
      JSON.stringify({
        request_id: 'req-envelope-1',
        finding_id: 'find-envelope-1',
        candidates: [
          {
            candidate_id: 'cand-1',
            sink_category: 'rce',
            sink_name: 'system',
            request_uri: '/?cmd=id',
          },
        ],
      }),
      JSON.stringify({
        candidate: {
          candidateId: 'cand-2',
          sinkCategory: 'ssrf',
          sinkName: 'curl_exec',
          request_evidence: {
            request_uri: '/probe.php?url=http://example.test',
          },
        },
      }),
      JSON.stringify({
        id: 'cand-3',
        category: 'xss',
        sink_name: 'echo',
      }),
      JSON.stringify({
        request_uri: '/envelope.php?cmd=id',
        candidates: [
          {
            candidate_id: 'cand-4',
            sink_category: 'rce',
            sink_name: 'system',
          },
        ],
      }),
    ].join('\n');
    await writeFile(file, `${lines}\n`, 'utf8');

    const loaded = await CandidateVerificationBridge.loadCandidatesFromJsonl(file);
    expect(loaded.map((value) => value.candidateId)).toEqual(['cand-1', 'cand-2', 'cand-3', 'cand-4']);
    expect(loaded[0]?.sinkCategory).toBe('rce');
    expect(loaded[1]?.sinkName).toBe('curl_exec');
    expect(loaded[1]?.requestUri).toBe('/probe.php?url=http://example.test');
    expect(loaded[0]?.requestId).toBe('req-envelope-1');
    expect(loaded[0]?.findingId).toBe('find-envelope-1');
    expect(loaded[2]?.correlationId).toBe('cand-3');
    expect(loaded[3]?.requestUri).toBe('/envelope.php?cmd=id');
    await rm(dir, { recursive: true, force: true });
  });
});
