<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\OracleArtifactRef;
use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Model\VerificationResult;
use PHPUnit\Framework\TestCase;

final class VerificationModelTest extends TestCase
{
    public function testVerificationJobSerializationAndDedupKeyAreDeterministic(): void
    {
        $job = new VerificationJob(
            jobId: 'job-1',
            candidateId: 'candidate-1',
            sinkCategory: 'rce',
            oracleType: 'rce_oracle',
            replayProfile: 'local',
            createdAt: '2026-04-22T00:00:00+00:00',
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: array('id' => 'candidate-1'),
            replayPlan: array('request_method' => 'GET', 'request_uri' => '/?cmd=id')
        );

        $restored = VerificationJob::fromArray($job->toArray());
        self::assertSame($job->jobId(), $restored->jobId());
        self::assertSame($job->candidateId(), $restored->candidateId());
        self::assertSame($job->dedupKey(), $restored->dedupKey());
    }

    public function testVerificationResultSerializationPreservesOutcomeAndArtifacts(): void
    {
        $result = new VerificationResult(
            jobId: 'job-1',
            candidateId: 'candidate-1',
            outcome: VerificationOutcome::CONFIRMED,
            reasonCodes: array('A_CODE', 'A_CODE', 'B_CODE'),
            summary: 'ok',
            artifacts: array(new OracleArtifactRef('oracle', '/tmp/artifact.json')),
            replayTranscripts: array(array('status_code' => 200)),
            createdAt: '2026-04-22T00:00:00+00:00'
        );

        $restored = VerificationResult::fromArray($result->toArray());
        self::assertSame(VerificationOutcome::CONFIRMED, $restored->outcome());
        self::assertSame(array('A_CODE', 'B_CODE'), $restored->reasonCodes());
        self::assertCount(1, $restored->artifacts());
        self::assertSame('/tmp/artifact.json', $restored->artifacts()[0]->path());
    }
}
