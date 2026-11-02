<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Model\VerificationResult;
use RuntimeException;

final class JsonlVerificationQueue implements VerificationQueueInterface
{
    private readonly string $jobsPath;
    private readonly string $resultsPath;
    private readonly string $deadLettersPath;
    private readonly string $claimsPath;
    private readonly string $lockPath;
    private readonly string $artifactsDirectory;

    public function __construct(
        private readonly string $runtimeDirectory,
        private readonly int $claimTtlSeconds = 300
    ) {
        $this->jobsPath = $this->runtimeDirectory . '/jobs.jsonl';
        $this->resultsPath = $this->runtimeDirectory . '/results.jsonl';
        $this->deadLettersPath = $this->runtimeDirectory . '/dead_letters.jsonl';
        $this->claimsPath = $this->runtimeDirectory . '/claims.jsonl';
        $this->lockPath = $this->runtimeDirectory . '/queue.lock';
        $this->artifactsDirectory = $this->runtimeDirectory . '/artifacts';

        $this->ensureRuntimeLayout();
    }

    public function enqueue(VerificationJob $job): bool
    {
        $result = $this->enqueueMany(array($job));
        return $result['enqueued'] === 1;
    }

    /**
     * @param VerificationJob[] $jobs
     * @return array{enqueued: int, duplicate: int}
     */
    public function enqueueMany(array $jobs): array
    {
        if ($jobs === array()) {
            return array('enqueued' => 0, 'duplicate' => 0);
        }

        return $this->withLock(function () use ($jobs): array {
            $dedupKeys = $this->dedupKeySetLocked();
            $enqueued = 0;
            $duplicate = 0;

            foreach ($jobs as $job) {
                if (!$job instanceof VerificationJob) {
                    continue;
                }

                $dedupKey = $job->dedupKey();
                if (isset($dedupKeys[$dedupKey])) {
                    $duplicate++;
                    continue;
                }

                $this->appendJsonLine($this->jobsPath, $job->withStatus('pending')->toArray());
                $dedupKeys[$dedupKey] = true;
                $enqueued++;
            }

            return array(
                'enqueued' => $enqueued,
                'duplicate' => $duplicate,
            );
        });
    }

    /**
     * @return VerificationJob[]
     */
    public function dequeueBatch(int $maxJobs = 10): array
    {
        if ($maxJobs < 1) {
            return array();
        }

        return $this->withLock(function () use ($maxJobs): array {
            $terminalIds = $this->terminalJobIdsLocked();
            $claimState = $this->claimStateLocked($terminalIds);
            $claimedIds = $claimState['active_ids'];

            $selected = array();
            foreach ($this->readJsonLinesIter($this->jobsPath) as $payload) {
                $status = (string) ($payload['status'] ?? '');
                if ($status !== 'pending') {
                    continue;
                }

                $jobId = (string) ($payload['job_id'] ?? '');
                if ($jobId === '') {
                    continue;
                }

                if (isset($terminalIds[$jobId])) {
                    continue;
                }

                if (isset($claimedIds[$jobId])) {
                    continue;
                }

                $selected[] = VerificationJob::fromArray($payload);
                if (count($selected) >= $maxJobs) {
                    break;
                }
            }

            if ($selected === array()) {
                return array();
            }

            $worker = sprintf('%s:%d', gethostname() ?: 'unknown-host', getmypid());
            $claimedAt = gmdate('c');
            foreach ($selected as $job) {
                $this->appendJsonLine($this->claimsPath, array(
                    'job_id' => $job->jobId(),
                    'claimed_at' => $claimedAt,
                    'worker' => $worker,
                ));
            }

            return $selected;
        });
    }

    public function markCompleted(VerificationJob $job, VerificationResult $result): void
    {
        $this->withLock(function () use ($result): void {
            $this->appendJsonLine($this->resultsPath, $result->toArray());
        });
    }

    public function markFailed(VerificationJob $job, string $reason, array $metadata = array()): void
    {
        $failedResult = new VerificationResult(
            jobId: $job->jobId(),
            candidateId: $job->candidateId(),
            outcome: VerificationOutcome::REPLAY_FAILED,
            reasonCodes: array($reason),
            summary: 'Verification worker failed before oracle completion.',
            artifacts: array(),
            replayTranscripts: array(),
            createdAt: gmdate('c'),
            metadata: array_merge(
                array(
                    'sink_category' => $job->sinkCategory(),
                    'oracle_type' => $job->oracleType(),
                    'attempt_count' => $job->attemptCount(),
                ),
                $metadata
            )
        );

        $this->withLock(function () use ($job, $reason, $metadata, $failedResult): void {
            $this->appendJsonLine($this->resultsPath, $failedResult->toArray());

            if (!$this->deadLetterExistsLocked($job->jobId())) {
                $this->appendJsonLine($this->deadLettersPath, array(
                    'job_id' => $job->jobId(),
                    'candidate_id' => $job->candidateId(),
                    'sink_category' => $job->sinkCategory(),
                    'oracle_type' => $job->oracleType(),
                    'attempt_count' => $job->attemptCount(),
                    'reason_code' => $reason,
                    'failed_at' => gmdate('c'),
                    'metadata' => $metadata,
                    'job' => $job->toArray(),
                ));
            }

            $terminalIds = $this->terminalJobIdsLocked();
            $this->claimStateLocked($terminalIds);
        });
    }

    public function pendingCount(): int
    {
        return $this->withLock(function (): int {
            $terminalIds = $this->terminalJobIdsLocked();
            $claimState = $this->claimStateLocked($terminalIds);
            $claimedIds = $claimState['active_ids'];

            $count = 0;
            foreach ($this->readJsonLinesIter($this->jobsPath) as $payload) {
                if ((string) ($payload['status'] ?? '') !== 'pending') {
                    continue;
                }

                $jobId = (string) ($payload['job_id'] ?? '');
                if ($jobId === '') {
                    continue;
                }

                if (isset($terminalIds[$jobId])) {
                    continue;
                }

                if (isset($claimedIds[$jobId])) {
                    continue;
                }

                $count++;
            }

            return $count;
        });
    }

    public function deadLetterCount(): int
    {
        return $this->withLock(function (): int {
            $count = 0;
            foreach ($this->readJsonLinesIter($this->deadLettersPath) as $_) {
                $count++;
            }

            return $count;
        });
    }

    public function queueHealth(): array
    {
        return $this->withLock(function (): array {
            $terminalIds = $this->terminalJobIdsLocked();
            $claimState = $this->claimStateLocked($terminalIds);
            $pendingCount = 0;
            foreach ($this->readJsonLinesIter($this->jobsPath) as $payload) {
                if ((string) ($payload['status'] ?? '') !== 'pending') {
                    continue;
                }

                $jobId = (string) ($payload['job_id'] ?? '');
                if ($jobId === '') {
                    continue;
                }

                if (isset($terminalIds[$jobId])) {
                    continue;
                }
                if (isset($claimState['active_ids'][$jobId])) {
                    continue;
                }
                $pendingCount++;
            }

            $deadLetterCount = 0;
            foreach ($this->readJsonLinesIter($this->deadLettersPath) as $_) {
                $deadLetterCount++;
            }

            return array(
                'pending_count' => $pendingCount,
                'active_claim_count' => count($claimState['active_ids']),
                'stale_claim_count' => $claimState['stale_count'],
                'dead_letter_count' => $deadLetterCount,
            );
        });
    }

    public function resultsPath(): string
    {
        return $this->resultsPath;
    }

    public function deadLettersPath(): string
    {
        return $this->deadLettersPath;
    }

    public function artifactsDirectory(): string
    {
        return $this->artifactsDirectory;
    }

    private function ensureRuntimeLayout(): void
    {
        if (!is_dir($this->runtimeDirectory) && !@mkdir($this->runtimeDirectory, 0775, true) && !is_dir($this->runtimeDirectory)) {
            throw new RuntimeException(sprintf('Failed to create verifier runtime directory: %s', $this->runtimeDirectory));
        }

        if (!is_dir($this->artifactsDirectory)) {
            @mkdir($this->artifactsDirectory, 0775, true);
        }

        foreach (array($this->jobsPath, $this->resultsPath, $this->deadLettersPath, $this->claimsPath, $this->lockPath) as $path) {
            if (!is_file($path)) {
                @touch($path);
            }
        }
    }

    /**
     * @template T
     * @param callable(): T $callback
     * @return T
     */
    private function withLock(callable $callback): mixed
    {
        $handle = fopen($this->lockPath, 'c+');
        if (!is_resource($handle)) {
            throw new RuntimeException(sprintf('Unable to open verifier lock file: %s', $this->lockPath));
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Unable to acquire verifier queue lock.');
            }

            return $callback();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * @return array<string, bool>
     */
    private function dedupKeySetLocked(): array
    {
        $dedupKeys = array();
        foreach ($this->readJsonLinesIter($this->jobsPath) as $payload) {
            $dedupKey = (string) ($payload['dedup_key'] ?? '');
            if ($dedupKey === '') {
                continue;
            }
            $dedupKeys[$dedupKey] = true;
        }

        return $dedupKeys;
    }

    /**
     * @return array<string, bool>
     */
    private function terminalJobIdsLocked(): array
    {
        $result = array();
        foreach ($this->readJsonLinesIter($this->resultsPath) as $payload) {
            $jobId = (string) ($payload['job_id'] ?? '');
            if ($jobId === '') {
                continue;
            }

            $result[$jobId] = true;
        }

        return $result;
    }

    /**
     * @return array<string, bool>
     */
    private function deadLetterExistsLocked(string $jobId): bool
    {
        foreach ($this->readJsonLinesIter($this->deadLettersPath) as $payload) {
            if ((string) ($payload['job_id'] ?? '') === $jobId) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, bool> $terminalIds
     * @return array{active_ids: array<string, bool>, active_rows: array<int, array<string, mixed>>, stale_count: int}
     */
    private function claimStateLocked(array $terminalIds): array
    {
        /** @var array<string, array{ts: int, row: array<string, mixed>}> $latestClaimByJob */
        $latestClaimByJob = array();
        $now = time();
        $staleCount = 0;
        foreach ($this->readJsonLinesIter($this->claimsPath) as $payload) {
            $jobId = (string) ($payload['job_id'] ?? '');
            $claimedAtRaw = (string) ($payload['claimed_at'] ?? '');
            if ($jobId === '' || $claimedAtRaw === '') {
                $staleCount++;
                continue;
            }

            $claimedAt = strtotime($claimedAtRaw);
            if ($claimedAt === false) {
                $staleCount++;
                continue;
            }

            if (!isset($latestClaimByJob[$jobId]) || $claimedAt >= $latestClaimByJob[$jobId]['ts']) {
                $latestClaimByJob[$jobId] = array(
                    'ts' => $claimedAt,
                    'row' => $payload,
                );
            }
        }

        $activeIds = array();
        $activeRows = array();
        foreach ($latestClaimByJob as $jobId => $claimState) {
            if (isset($terminalIds[$jobId])) {
                $staleCount++;
                continue;
            }

            if (($now - $claimState['ts']) > $this->claimTtlSeconds) {
                $staleCount++;
                continue;
            }

            $activeRows[] = $claimState['row'];
            $activeIds[$jobId] = true;
        }

        if ($staleCount > 0 || count($activeRows) !== count($latestClaimByJob)) {
            $this->rewriteJsonLines($this->claimsPath, $activeRows);
        }

        return array(
            'active_ids' => $activeIds,
            'active_rows' => $activeRows,
            'stale_count' => $staleCount,
        );
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function readJsonLines(string $path): array
    {
        $result = array();
        foreach ($this->readJsonLinesIter($path) as $decoded) {
            $result[] = $decoded;
        }

        return $result;
    }

    /**
     * @return \Generator<int, array<string, mixed>>
     */
    private function readJsonLinesIter(string $path): \Generator
    {
        $handle = @fopen($path, 'rb');
        if (!is_resource($handle)) {
            return;
        }

        try {
            while (($line = fgets($handle)) !== false) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }

                $decoded = json_decode($line, true);
                if (!is_array($decoded)) {
                    continue;
                }

                yield $decoded;
            }
        } finally {
            fclose($handle);
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function appendJsonLine(string $path, array $payload): void
    {
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($encoded)) {
            throw new RuntimeException('Failed to encode verifier JSONL payload.');
        }

        @file_put_contents($path, $encoded . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /**
     * @param array<int, array<string, mixed>> $payloads
     */
    private function rewriteJsonLines(string $path, array $payloads): void
    {
        $buffer = '';
        foreach ($payloads as $payload) {
            $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
            if (!is_string($encoded)) {
                throw new RuntimeException('Failed to encode verifier JSONL payload for rewrite.');
            }
            $buffer .= $encoded . PHP_EOL;
        }

        @file_put_contents($path, $buffer, LOCK_EX);
    }
}
