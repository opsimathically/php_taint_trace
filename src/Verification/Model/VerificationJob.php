<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class VerificationJob
{
    /**
     * @param array<string, mixed> $candidateSnapshot
     * @param array<string, mixed> $replayPlan
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $jobId,
        private readonly string $candidateId,
        private readonly string $sinkCategory,
        private readonly string $oracleType,
        private readonly string $replayProfile,
        private readonly string $createdAt,
        private readonly int $attemptCount,
        private readonly string $status,
        private readonly array $candidateSnapshot,
        private readonly array $replayPlan,
        private readonly array $metadata = array()
    ) {
    }

    public function jobId(): string
    {
        return $this->jobId;
    }

    public function candidateId(): string
    {
        return $this->candidateId;
    }

    public function sinkCategory(): string
    {
        return $this->sinkCategory;
    }

    public function oracleType(): string
    {
        return $this->oracleType;
    }

    public function replayProfile(): string
    {
        return $this->replayProfile;
    }

    public function createdAt(): string
    {
        return $this->createdAt;
    }

    public function attemptCount(): int
    {
        return $this->attemptCount;
    }

    public function status(): string
    {
        return $this->status;
    }

    /**
     * @return array<string, mixed>
     */
    public function candidateSnapshot(): array
    {
        return $this->candidateSnapshot;
    }

    /**
     * @return array<string, mixed>
     */
    public function replayPlan(): array
    {
        return $this->replayPlan;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }

    public function dedupKey(): string
    {
        return hash('sha256', implode('|', array(
            $this->candidateId,
            $this->oracleType,
            $this->replayProfile,
        )));
    }

    public function withAttemptCount(int $attemptCount): self
    {
        return new self(
            jobId: $this->jobId,
            candidateId: $this->candidateId,
            sinkCategory: $this->sinkCategory,
            oracleType: $this->oracleType,
            replayProfile: $this->replayProfile,
            createdAt: $this->createdAt,
            attemptCount: $attemptCount,
            status: $this->status,
            candidateSnapshot: $this->candidateSnapshot,
            replayPlan: $this->replayPlan,
            metadata: $this->metadata
        );
    }

    public function withStatus(string $status): self
    {
        return new self(
            jobId: $this->jobId,
            candidateId: $this->candidateId,
            sinkCategory: $this->sinkCategory,
            oracleType: $this->oracleType,
            replayProfile: $this->replayProfile,
            createdAt: $this->createdAt,
            attemptCount: $this->attemptCount,
            status: $status,
            candidateSnapshot: $this->candidateSnapshot,
            replayPlan: $this->replayPlan,
            metadata: $this->metadata
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array(
            'job_id' => $this->jobId,
            'candidate_id' => $this->candidateId,
            'sink_category' => $this->sinkCategory,
            'oracle_type' => $this->oracleType,
            'replay_profile' => $this->replayProfile,
            'created_at' => $this->createdAt,
            'attempt_count' => $this->attemptCount,
            'status' => $this->status,
            'dedup_key' => $this->dedupKey(),
            'candidate_snapshot' => $this->candidateSnapshot,
            'replay_plan' => $this->replayPlan,
            'metadata' => $this->metadata,
        );
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        return new self(
            jobId: (string) ($payload['job_id'] ?? ''),
            candidateId: (string) ($payload['candidate_id'] ?? ''),
            sinkCategory: (string) ($payload['sink_category'] ?? ''),
            oracleType: (string) ($payload['oracle_type'] ?? ''),
            replayProfile: (string) ($payload['replay_profile'] ?? 'local'),
            createdAt: (string) ($payload['created_at'] ?? gmdate('c')),
            attemptCount: (int) ($payload['attempt_count'] ?? 0),
            status: (string) ($payload['status'] ?? 'pending'),
            candidateSnapshot: is_array($payload['candidate_snapshot'] ?? null)
                ? $payload['candidate_snapshot']
                : array(),
            replayPlan: is_array($payload['replay_plan'] ?? null)
                ? $payload['replay_plan']
                : array(),
            metadata: is_array($payload['metadata'] ?? null)
                ? $payload['metadata']
                : array()
        );
    }
}
