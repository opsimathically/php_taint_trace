<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification\Scoring;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Model\VerificationResult;
use PhpTaintTrace\Verification\Scoring\EvidenceAggregator;
use PHPUnit\Framework\TestCase;

final class EvidenceAggregatorTest extends TestCase
{
    public function testAggregateMapsConfirmedOutcomeAndReplaySuccessToHighScores(): void
    {
        $job = new VerificationJob(
            jobId: 'job-1',
            candidateId: 'candidate-1',
            sinkCategory: 'rce',
            oracleType: 'rce_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 1,
            status: 'completed',
            candidateSnapshot: array(
                'reason_codes' => array('CATEGORY_RCE'),
                'taint_evidence' => array('has_taint' => true),
                'detector_evidence' => array(
                    'finding_count' => 1,
                    'detectors' => array('taint-input-detector', 'payload-keyword-detector'),
                ),
            ),
            replayPlan: array('request_method' => 'GET', 'request_uri' => '/?cmd=id')
        );

        $result = new VerificationResult(
            jobId: 'job-1',
            candidateId: 'candidate-1',
            outcome: VerificationOutcome::CONFIRMED,
            reasonCodes: array('VERIFIER_RCE_NONCE_CONFIRMED'),
            summary: 'summary',
            artifacts: array(),
            replayTranscripts: array(
                array('status_code' => 200, 'error' => null),
                array('status_code' => 200, 'error' => null),
            ),
            createdAt: gmdate('c')
        );

        $aggregate = (new EvidenceAggregator())->aggregate($job, $result);

        self::assertSame(1.0, $aggregate['reachability_score']);
        self::assertSame(1.0, $aggregate['exploit_score']);
        self::assertSame(1.0, $aggregate['repro_score']);
        self::assertSame(0.0, $aggregate['sanitization_score']);
    }

    public function testAggregateMapsBlockedPolicyAndSanitizerProof(): void
    {
        $job = new VerificationJob(
            jobId: 'job-2',
            candidateId: 'candidate-2',
            sinkCategory: 'ssrf',
            oracleType: 'ssrf_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 1,
            status: 'completed',
            candidateSnapshot: array(
                'reason_codes' => array('CATEGORY_SSRF', 'SANITIZER_TRUSTED_PROOF_PRESENT'),
                'taint_evidence' => array('has_taint' => true),
                'detector_evidence' => array('finding_count' => 1, 'detectors' => array('taint-input-detector')),
            ),
            replayPlan: array('request_method' => 'GET', 'request_uri' => '/?url=x')
        );

        $result = new VerificationResult(
            jobId: 'job-2',
            candidateId: 'candidate-2',
            outcome: VerificationOutcome::BLOCKED_BY_POLICY,
            reasonCodes: array('VERIFIER_PHASE_B_GET_ONLY_POLICY'),
            summary: 'summary',
            artifacts: array(),
            replayTranscripts: array(),
            createdAt: gmdate('c')
        );

        $aggregate = (new EvidenceAggregator())->aggregate($job, $result);

        self::assertSame(0.0, $aggregate['environment_score']);
        self::assertSame(1.0, $aggregate['sanitization_score']);
        self::assertContains('SANITIZER_TRUSTED_PROOF_PRESENT', $aggregate['reason_codes']);
    }

    public function testAggregateCarriesSinkTimeStacktraceIntoDecisionMetadata(): void
    {
        $job = new VerificationJob(
            jobId: 'job-stack',
            candidateId: 'candidate-stack',
            sinkCategory: 'xss',
            oracleType: 'xss_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 1,
            status: 'completed',
            candidateSnapshot: array(
                'reason_codes' => array('CATEGORY_XSS'),
                'taint_evidence' => array('has_taint' => true),
                'detector_evidence' => array('finding_count' => 1, 'detectors' => array('taint-input-detector')),
                'sink_evidence' => array(
                    'metadata' => array(
                        'stacktrace' => array(
                            array(
                                'level' => 0,
                                'where' => 'App\\Controller->render',
                                'file_uri' => '/var/www/html/app.php',
                                'lineno' => 99,
                                'type' => '->',
                            ),
                        ),
                        'stacktrace_captured_at' => '2026-04-27T00:00:00+00:00',
                    ),
                ),
            ),
            replayPlan: array('request_method' => 'GET', 'request_uri' => '/xss?name=test')
        );

        $result = new VerificationResult(
            jobId: 'job-stack',
            candidateId: 'candidate-stack',
            outcome: VerificationOutcome::CONFIRMED,
            reasonCodes: array('VERIFIER_XSS_CONTEXT_CONFIRMED'),
            summary: 'summary',
            artifacts: array(),
            replayTranscripts: array(),
            createdAt: gmdate('c')
        );

        $aggregate = (new EvidenceAggregator())->aggregate($job, $result);
        self::assertIsArray($aggregate['metadata']['stacktrace'] ?? null);
        self::assertSame('App\\Controller->render', $aggregate['metadata']['stacktrace'][0]['where'] ?? null);
        self::assertSame('2026-04-27T00:00:00+00:00', $aggregate['metadata']['stacktrace_captured_at'] ?? null);
    }

    public function testAggregateAddsReproductionMetadataFromCandidateAndReplayPlan(): void
    {
        $job = new VerificationJob(
            jobId: 'job-repro',
            candidateId: 'candidate-repro',
            sinkCategory: 'rce',
            oracleType: 'rce_oracle',
            replayProfile: 'remote_lab',
            createdAt: gmdate('c'),
            attemptCount: 1,
            status: 'completed',
            candidateSnapshot: array(
                'sink_name' => 'system',
                'sink_category' => 'rce',
                'reason_codes' => array('CATEGORY_RCE'),
                'taint_evidence' => array('has_taint' => true),
                'detector_evidence' => array('finding_count' => 1, 'detectors' => array('taint-input-detector')),
                'request_evidence' => array(
                    'request_method' => 'GET',
                    'request_uri' => '/rce.php?cmd=id',
                    'metadata' => array(
                        'trace_id' => 'trace-123',
                    ),
                ),
                'sink_evidence' => array(
                    'metadata' => array(
                        'mutation_target' => '$_GET["cmd"]',
                        'sql' => array(
                            'hook_id' => 'sink.sqli.mysqli_query',
                            'query' => 'SELECT * FROM users WHERE id = ?',
                            'parameters' => array('42'),
                        ),
                    ),
                ),
            ),
            replayPlan: array(
                'request_method' => 'GET',
                'request_uri' => '/rce.php?cmd=id',
                'target_query_param' => 'cmd',
                'target_param_location' => 'query',
            )
        );

        $result = new VerificationResult(
            jobId: 'job-repro',
            candidateId: 'candidate-repro',
            outcome: VerificationOutcome::CONFIRMED,
            reasonCodes: array('VERIFIER_RCE_NONCE_CONFIRMED'),
            summary: 'summary',
            artifacts: array(),
            replayTranscripts: array(
                array(
                    'request' => array(
                        'payload_label' => 'positive_nonce',
                    ),
                ),
            ),
            createdAt: gmdate('c')
        );

        $aggregate = (new EvidenceAggregator())->aggregate($job, $result);
        self::assertSame('GET', $aggregate['metadata']['request_method'] ?? null);
        self::assertSame('/rce.php?cmd=id', $aggregate['metadata']['request_uri'] ?? null);
        self::assertSame('system', $aggregate['metadata']['sink_name'] ?? null);
        self::assertSame('rce', $aggregate['metadata']['sink_category'] ?? null);
        self::assertSame('cmd', $aggregate['metadata']['reproduction']['target_query_param'] ?? null);
        self::assertSame('query', $aggregate['metadata']['reproduction']['target_param_location'] ?? null);
        self::assertSame(array('positive_nonce'), $aggregate['metadata']['reproduction']['payloads'] ?? array());
        self::assertSame('trace-123', $aggregate['metadata']['reproduction']['trace_id'] ?? null);
        self::assertSame('SELECT * FROM users WHERE id = ?', $aggregate['metadata']['sql']['query'] ?? null);
        self::assertSame(array('42'), $aggregate['metadata']['sql']['parameters'] ?? null);
    }
}
