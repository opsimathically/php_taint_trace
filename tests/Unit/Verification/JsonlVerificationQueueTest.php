<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Model\VerificationResult;
use PhpTaintTrace\Verification\Verifier\JsonlVerificationQueue;
use PHPUnit\Framework\TestCase;

final class JsonlVerificationQueueTest extends TestCase
{
    public function testQueueEnqueueDequeueDedupAndCompletionFlow(): void
    {
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-verifier-queue-' . uniqid('', true);
        $queue = new JsonlVerificationQueue($runtimeDir);

        $job = $this->job('job-1', 'candidate-1');
        self::assertTrue($queue->enqueue($job));
        self::assertFalse($queue->enqueue($job));
        self::assertSame(1, $queue->pendingCount());
        self::assertSame(0, $queue->deadLetterCount());

        $dequeued = $queue->dequeueBatch(10);
        self::assertCount(1, $dequeued);
        self::assertSame('job-1', $dequeued[0]->jobId());
        self::assertCount(0, $queue->dequeueBatch(10));

        $queue->markCompleted(
            $dequeued[0],
            new VerificationResult(
                jobId: $dequeued[0]->jobId(),
                candidateId: $dequeued[0]->candidateId(),
                outcome: VerificationOutcome::CONFIRMED,
                reasonCodes: array('VERIFIER_OK'),
                summary: 'ok',
                artifacts: array(),
                replayTranscripts: array(),
                createdAt: gmdate('c')
            )
        );

        self::assertSame(0, $queue->pendingCount());
        self::assertSame(0, $queue->deadLetterCount());
        self::assertFileExists($queue->resultsPath());
    }

    public function testQueueEnqueueManyDedupsWithoutAppendingDuplicateRows(): void
    {
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-verifier-queue-' . uniqid('', true);
        $queue = new JsonlVerificationQueue($runtimeDir);

        $jobA = $this->job('job-a', 'candidate-a');
        $jobADuplicate = $this->job('job-a-dup', 'candidate-a');
        $jobB = $this->job('job-b', 'candidate-b');

        $summary = $queue->enqueueMany(array($jobA, $jobADuplicate, $jobB));
        self::assertSame(2, $summary['enqueued']);
        self::assertSame(1, $summary['duplicate']);
        self::assertSame(2, $queue->pendingCount());

        $rows = file($runtimeDir . '/jobs.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($rows);
        self::assertCount(2, $rows);
    }

    public function testQueueScavengesStaleClaimsAndWritesDeadLetters(): void
    {
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-verifier-queue-' . uniqid('', true);
        $queue = new JsonlVerificationQueue($runtimeDir, claimTtlSeconds: 1);

        $job = $this->job('job-stale', 'candidate-stale');
        self::assertTrue($queue->enqueue($job));
        $dequeued = $queue->dequeueBatch(1);
        self::assertCount(1, $dequeued);

        $claimsPath = $runtimeDir . '/claims.jsonl';
        file_put_contents($claimsPath, json_encode(array(
            'job_id' => 'job-stale',
            'claimed_at' => gmdate('c', time() - 3600),
            'worker' => 'test-worker',
        ), JSON_UNESCAPED_SLASHES) . PHP_EOL);

        self::assertSame(1, $queue->pendingCount());
        self::assertSame('', (string) file_get_contents($claimsPath));

        $dequeued = $queue->dequeueBatch(1);
        self::assertCount(1, $dequeued);
        $queue->markFailed($dequeued[0], 'VERIFIER_TEST_FAILURE', array('stage' => 'unit_test'));

        self::assertSame(0, $queue->pendingCount());
        self::assertSame(1, $queue->deadLetterCount());

        $deadLetterRows = file($queue->deadLettersPath(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($deadLetterRows);
        self::assertCount(1, $deadLetterRows);
        $deadLetter = json_decode($deadLetterRows[0], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('job-stale', $deadLetter['job_id']);
        self::assertSame('VERIFIER_TEST_FAILURE', $deadLetter['reason_code']);
        self::assertSame('unit_test', $deadLetter['metadata']['stage']);
    }

    private function job(string $jobId, string $candidateId): VerificationJob
    {
        return new VerificationJob(
            jobId: $jobId,
            candidateId: $candidateId,
            sinkCategory: 'rce',
            oracleType: 'rce_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: array('id' => $candidateId),
            replayPlan: array('request_method' => 'GET', 'request_uri' => '/?cmd=id')
        );
    }
}
