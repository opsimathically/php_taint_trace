<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationResult;

interface VerificationQueueInterface
{
    public function enqueue(VerificationJob $job): bool;

    /**
     * @return VerificationJob[]
     */
    public function dequeueBatch(int $maxJobs = 10): array;

    public function markCompleted(VerificationJob $job, VerificationResult $result): void;

    /**
     * @param array<string, mixed> $metadata
     */
    public function markFailed(VerificationJob $job, string $reason, array $metadata = array()): void;

    public function pendingCount(): int;

    public function deadLetterCount(): int;

    /**
     * @return array{pending_count: int, active_claim_count: int, stale_claim_count: int, dead_letter_count: int}
     */
    public function queueHealth(): array;
}
