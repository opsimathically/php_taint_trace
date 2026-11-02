import { describe, expect, it } from 'vitest';
import {
  buildDebugReplayVerifierDecision,
  buildPhpTaintTraceVerificationResultFromReplayAttempts,
  type DebugReplayAttemptRunResult,
} from '../../src/index.js';

describe('verifier decision adapter', () => {
  it('maps successful replay attempts to confirmed outcome payload', () => {
    const replay = baseReplayResult({
      attempts: [
        {
          attempt: 1,
          startedAt: '2026-04-24T00:00:00.000Z',
          finishedAt: '2026-04-24T00:00:01.000Z',
          status: 'succeeded',
          failureCode: 'none',
          sessionId: 'session-1',
          evidenceFingerprint: 'abc123',
          replayVariationCount: 2,
          replayErrorCount: 0,
          artifacts: {
            evidencePath: '/tmp/attempt-1.evidence.json',
            replayResultsPath: '/tmp/attempt-1.replay-results.json',
            transcriptPath: '/tmp/attempt-1.transcript.json',
          },
        },
      ],
      finalStatus: 'succeeded',
      successfulAttempt: 1,
      captures: [
        {
          trigger: {
            candidateId: 'cand-1',
            sinkCategory: 'rce',
            sinkName: 'system',
            requestUri: '/?cmd=id',
          },
          sessionId: 'session-1',
          errors: [],
          raw: {
            replayResults: [],
            evaluations: {},
          },
          evidence: {
            trigger: {
              candidateId: 'cand-1',
              sinkCategory: 'rce',
              sinkName: 'system',
              requestUri: '/?cmd=id',
            },
            evaluations: {},
            replay: [],
            fingerprint: 'fingerprint-1',
            snapshot: {
              capturedAt: '2026-04-24T00:00:00.500Z',
              frames: [
                {
                  level: 0,
                  where: 'main',
                  fileUri: 'file:///var/www/html/index.php',
                  lineno: 33,
                  type: 'file',
                },
              ],
              contexts: [],
              fingerprint: 'snapshot-fingerprint-1',
            },
          },
          template: {
            template: {
              name: 'rce',
              categories: ['rce'],
              description: 'Command replay template',
              captureProfile: 'rce',
              mutationTarget: '$_GET["cmd"]',
              payloads: ['id'],
              resetValue: 'echo baseline',
              driftExpressions: ['$_GET["cmd"]'],
              comparePhase: 'post_reset',
              failOnDrift: false,
              allowSnapshotDrift: false,
              maxExpressionDriftCount: 0,
              allowedExpressionDrift: [],
            },
            replayPlan: {
              variations: [],
            },
            tracePlan: {
              steps: 1,
              action: 'step_over',
            },
            evaluateExpressions: [],
            snapshotContextIds: [0],
            primeAction: 'step_into',
          },
        },
      ] as unknown as DebugReplayAttemptRunResult['captures'],
    });

    const payload = buildPhpTaintTraceVerificationResultFromReplayAttempts(replay, {
      jobId: 'job-fixed',
      createdAt: '2026-04-24T00:00:02.000Z',
    });

    expect(payload.job_id).toBe('job-fixed');
    expect(payload.outcome).toBe('confirmed');
    expect(payload.reason_codes).toContain('VERIFIER_DEBUG_REPLAY_ATTEMPT_CONFIRMED');
    expect(payload.reason_codes).toContain('CATEGORY_RCE');
    expect(payload.artifacts.map((entry) => entry.type)).toContain('debug_attempt_manifest');
    expect(payload.replay_transcripts).toHaveLength(1);
    expect(payload.metadata.successful_attempt).toBe(1);
    expect(payload.metadata.request_uri).toBe('/?cmd=id');
    expect((payload.metadata.reproduction as { request_uri?: string }).request_uri).toBe('/?cmd=id');
    expect(Array.isArray(payload.metadata.stacktrace)).toBe(true);
    expect((payload.metadata.stacktrace as Array<unknown>).length).toBe(1);
  });

  it('maps replay-failed attempts with explicit replay failure to not_confirmed', () => {
    const replay = baseReplayResult({
      attempts: [
        {
          attempt: 1,
          startedAt: '2026-04-24T00:00:00.000Z',
          finishedAt: '2026-04-24T00:00:01.000Z',
          status: 'failed',
          failureCode: 'replay_failed',
          failureMessage: 'Replay evidence contains errors.',
          replayVariationCount: 2,
          replayErrorCount: 1,
        },
      ],
      finalStatus: 'failed',
      successfulAttempt: undefined,
    });

    const payload = buildPhpTaintTraceVerificationResultFromReplayAttempts(replay);
    expect(payload.outcome).toBe('not_confirmed');
    expect(payload.reason_codes).toContain('VERIFIER_DEBUG_FAILURE_REPLAY_FAILED');
  });

  it('maps routing-aborted attempts to blocked_by_policy', () => {
    const replay = baseReplayResult({
      attempts: [
        {
          attempt: 1,
          startedAt: '2026-04-24T00:00:00.000Z',
          finishedAt: '2026-04-24T00:00:01.000Z',
          status: 'failed',
          failureCode: 'routing_aborted',
          failureMessage: 'Debug session routing aborted.',
          replayVariationCount: 0,
          replayErrorCount: 0,
        },
      ],
      finalStatus: 'failed',
      successfulAttempt: undefined,
    });

    const payload = buildPhpTaintTraceVerificationResultFromReplayAttempts(replay);
    expect(payload.outcome).toBe('blocked_by_policy');
    expect(payload.reason_codes).toContain('VERIFIER_DEBUG_FAILURE_ROUTING_ABORTED');
  });

  it('maps infrastructure-only failures to replay_failed and wraps result in decision helper', () => {
    const replay = baseReplayResult({
      attempts: [
        {
          attempt: 1,
          startedAt: '2026-04-24T00:00:00.000Z',
          finishedAt: '2026-04-24T00:00:01.000Z',
          status: 'failed',
          failureCode: 'routing_timeout',
          failureMessage: 'Timed out waiting for routed DBGp session.',
          replayVariationCount: 0,
          replayErrorCount: 0,
        },
        {
          attempt: 2,
          startedAt: '2026-04-24T00:00:02.000Z',
          finishedAt: '2026-04-24T00:00:03.000Z',
          status: 'failed',
          failureCode: 'session_closed',
          failureMessage: 'Closed DBGp session.',
          replayVariationCount: 0,
          replayErrorCount: 0,
        },
      ],
      finalStatus: 'failed',
      successfulAttempt: undefined,
    });

    const decision = buildDebugReplayVerifierDecision(replay);
    expect(decision.verificationResult.outcome).toBe('replay_failed');
    expect(decision.verificationResult.reason_codes).toContain(
      'VERIFIER_DEBUG_FAILURE_ROUTING_TIMEOUT'
    );
    expect(decision.verificationResult.reason_codes).toContain(
      'VERIFIER_DEBUG_FAILURE_SESSION_CLOSED'
    );
  });
});

function baseReplayResult(overrides: {
  attempts: DebugReplayAttemptRunResult['bundle']['attempts'];
  finalStatus: DebugReplayAttemptRunResult['bundle']['finalStatus'];
  successfulAttempt?: number;
  captures?: DebugReplayAttemptRunResult['captures'];
}): DebugReplayAttemptRunResult {
  return {
    bundle: {
      schemaVersion: 'dbgp-replay-attempts.v1',
      createdAt: '2026-04-24T00:00:00.000Z',
      trigger: {
        candidateId: 'cand-1',
        sinkCategory: 'rce',
        sinkName: 'system',
        requestUri: '/?cmd=id',
        metadata: {
          request_evidence: {
            request_uri: '/?cmd=id',
            request_method: 'GET',
          },
        },
      },
      template: {
        template: {
          name: 'rce',
          categories: ['rce'],
          description: 'Command replay template',
          captureProfile: 'rce',
          mutationTarget: '$_GET["cmd"]',
          payloads: ['id'],
          resetValue: 'echo baseline',
          driftExpressions: ['$_GET["cmd"]'],
          comparePhase: 'post_reset',
          failOnDrift: false,
          allowSnapshotDrift: false,
          maxExpressionDriftCount: 0,
          allowedExpressionDrift: [],
        },
        replayPlan: {
          variations: [
            {
              id: 'rce_payload_1',
              mutations: [{ propertyName: '$_GET["cmd"]', value: 'id' }],
              evalExpressions: ['$_GET["cmd"]'],
            },
          ],
        },
        tracePlan: {
          steps: 1,
          action: 'step_over',
        },
        evaluateExpressions: ['$_GET["cmd"]'],
        snapshotContextIds: [0],
        primeAction: 'step_into',
      },
      maxAttempts: 3,
      stopOnFirstSuccess: true,
      requireReplayEvidence: true,
      attempts: overrides.attempts,
      finalStatus: overrides.finalStatus,
      successfulAttempt: overrides.successfulAttempt,
    },
    captures: overrides.captures ?? [],
    artifactManifestPath: '/tmp/replay-attempts.manifest.json',
    artifactManifest: {
      schema: 'dbgp-replay-manifest.v1',
      createdAt: '2026-04-24T00:00:04.000Z',
      entries: [],
      signature: {
        algorithm: 'hmac-sha256',
        digest: 'abc123',
      },
    },
  };
}
