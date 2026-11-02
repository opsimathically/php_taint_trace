<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Oracle\OracleDecision;
use PhpTaintTrace\Verification\Oracle\OracleInterface;
use PhpTaintTrace\Verification\Storage\DecisionStoreInterface;
use PhpTaintTrace\Verification\Verifier\JsonlVerificationQueue;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;
use PhpTaintTrace\Verification\Verifier\VerificationWorker;
use PHPUnit\Framework\TestCase;

final class VerificationWorkerTest extends TestCase
{
    public function testWorkerRetriesOnceAndThenMarksCompletion(): void
    {
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-worker-' . uniqid('', true);
        $queue = new JsonlVerificationQueue($runtimeDir);
        $queue->enqueue($this->job('job-1', 'rce'));

        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $oracle = new class implements OracleInterface {
            private int $attempts = 0;

            public function supports(VerificationJob $job): bool
            {
                return true;
            }

            public function verify(OracleContext $context): OracleDecision
            {
                $this->attempts++;
                if ($this->attempts === 1) {
                    throw new \RuntimeException('first attempt failure');
                }

                return new OracleDecision(
                    VerificationOutcome::CONFIRMED,
                    array('VERIFIER_RETRY_SUCCESS'),
                    'retry success',
                    array()
                );
            }
        };

        $worker = new VerificationWorker($queue, $runner, array($oracle), maxAttempts: 2, artifactDirectory: $queue->artifactsDirectory());
        self::assertSame(1, $worker->process(10));

        $rows = file($queue->resultsPath(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($rows);
        self::assertCount(1, $rows);
        $result = json_decode($rows[0], true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('confirmed', $result['outcome']);
        self::assertSame(2, $result['metadata']['attempt_count']);
        self::assertSame(0, $queue->deadLetterCount());
    }

    public function testWorkerMarksFailureWhenNoOracleSupportsJob(): void
    {
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-worker-' . uniqid('', true);
        $queue = new JsonlVerificationQueue($runtimeDir);
        $queue->enqueue($this->job('job-2', 'rce'));

        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $worker = new VerificationWorker($queue, $runner, array(), maxAttempts: 1, artifactDirectory: $queue->artifactsDirectory());
        self::assertSame(1, $worker->process(10));

        $rows = file($queue->resultsPath(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($rows);
        self::assertCount(1, $rows);
        $result = json_decode($rows[0], true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('replay_failed', $result['outcome']);
        self::assertContains('VERIFIER_ORACLE_UNAVAILABLE', $result['reason_codes']);
        self::assertSame(1, $queue->deadLetterCount());
    }

    public function testWorkerMarksRetryExhaustedAsDeadLetter(): void
    {
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-worker-' . uniqid('', true);
        $queue = new JsonlVerificationQueue($runtimeDir);
        $queue->enqueue($this->job('job-2b', 'rce'));

        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $oracle = new class implements OracleInterface {
            public function supports(VerificationJob $job): bool
            {
                return true;
            }

            public function verify(OracleContext $context): OracleDecision
            {
                throw new \RuntimeException('forced failure');
            }
        };

        $worker = new VerificationWorker($queue, $runner, array($oracle), maxAttempts: 2, artifactDirectory: $queue->artifactsDirectory());
        self::assertSame(1, $worker->process(10));

        $rows = file($queue->resultsPath(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($rows);
        self::assertCount(1, $rows);
        $result = json_decode($rows[0], true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('replay_failed', $result['outcome']);
        self::assertContains('VERIFIER_EXCEPTION_RETRY_EXHAUSTED', $result['reason_codes']);
        self::assertSame('oracle_verify', $result['metadata']['failure_stage']);
        self::assertSame(2, $result['metadata']['max_attempts']);
        self::assertSame(2, $result['metadata']['attempt_count']);
        self::assertSame(1, $queue->deadLetterCount());

        $deadLetterRows = file($queue->deadLettersPath(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($deadLetterRows);
        self::assertCount(1, $deadLetterRows);
        $deadLetter = json_decode($deadLetterRows[0], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('job-2b', $deadLetter['job_id']);
        self::assertSame('VERIFIER_EXCEPTION_RETRY_EXHAUSTED', $deadLetter['reason_code']);
    }

    public function testWorkerKeepsVerifierResultWhenDecisionStoreFails(): void
    {
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-worker-' . uniqid('', true);
        $queue = new JsonlVerificationQueue($runtimeDir);
        $queue->enqueue($this->job('job-3', 'rce'));

        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $oracle = new class implements OracleInterface {
            public function supports(VerificationJob $job): bool
            {
                return true;
            }

            public function verify(OracleContext $context): OracleDecision
            {
                return new OracleDecision(
                    VerificationOutcome::CONFIRMED,
                    array('VERIFIER_RCE_NONCE_CONFIRMED'),
                    'confirmed',
                    array()
                );
            }
        };

        $failingStore = new class implements DecisionStoreInterface {
            public function persist(\PhpTaintTrace\Verification\Model\RiskDecision $decision): bool
            {
                throw new \RuntimeException('decision store failure');
            }

            public function decisionsPath(): string
            {
                return '/tmp/decisions.jsonl';
            }
        };

        $worker = new VerificationWorker(
            $queue,
            $runner,
            array($oracle),
            maxAttempts: 1,
            artifactDirectory: $queue->artifactsDirectory(),
            decisionStore: $failingStore
        );

        self::assertSame(1, $worker->process(10));
        $rows = file($queue->resultsPath(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($rows);
        self::assertCount(1, $rows);

        $result = json_decode($rows[0], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('confirmed', $result['outcome']);
    }

    public function testWorkerPersistsSinkTimeStacktraceInResultMetadata(): void
    {
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-worker-' . uniqid('', true);
        $queue = new JsonlVerificationQueue($runtimeDir);
        $queue->enqueue($this->job(
            'job-stacktrace',
            'xss',
            array(
                'sink_evidence' => array(
                    'metadata' => array(
                        'stacktrace' => array(
                            array(
                                'level' => 0,
                                'where' => 'App\\Controller->render',
                                'file_uri' => '/var/www/html/index.php',
                                'lineno' => 77,
                                'type' => '->',
                            ),
                        ),
                        'sql' => array(
                            'hook_id' => 'sink.sqli.mysqli_query',
                            'query' => 'SELECT * FROM users WHERE id = ?',
                            'parameters' => array('7'),
                        ),
                        'rce' => array(
                            'hook_id' => 'sink.rce.exec',
                            'argument_index' => 0,
                            'command' => 'cat /etc/passwd',
                        ),
                    ),
                ),
            )
        ));

        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $oracle = new class implements OracleInterface {
            public function supports(VerificationJob $job): bool
            {
                return true;
            }

            public function verify(OracleContext $context): OracleDecision
            {
                return new OracleDecision(
                    VerificationOutcome::CONFIRMED,
                    array('VERIFIER_XSS_CONTEXT_CONFIRMED'),
                    'confirmed',
                    array()
                );
            }
        };

        $worker = new VerificationWorker($queue, $runner, array($oracle), maxAttempts: 1, artifactDirectory: $queue->artifactsDirectory());
        self::assertSame(1, $worker->process(10));

        $rows = file($queue->resultsPath(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($rows);
        self::assertCount(1, $rows);
        $result = json_decode($rows[0], true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('App\\Controller->render', $result['metadata']['stacktrace'][0]['where'] ?? null);
        self::assertSame('SELECT * FROM users WHERE id = ?', $result['metadata']['sql']['query'] ?? null);
        self::assertSame(array('7'), $result['metadata']['sql']['parameters'] ?? null);
        self::assertSame('sink.rce.exec', $result['metadata']['rce']['hook_id'] ?? null);
        self::assertSame('cat /etc/passwd', $result['metadata']['rce']['command'] ?? null);
    }

    /**
     * @param array<string, mixed> $candidateSnapshot
     */
    private function job(string $jobId, string $sinkCategory, array $candidateSnapshot = array()): VerificationJob
    {
        return new VerificationJob(
            jobId: $jobId,
            candidateId: 'candidate-' . $jobId,
            sinkCategory: $sinkCategory,
            oracleType: $sinkCategory . '_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: $candidateSnapshot,
            replayPlan: array('request_method' => 'GET', 'request_uri' => '/?x=1')
        );
    }
}
