<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class VerificationResult
{
    /**
     * @param string[] $reasonCodes
     * @param OracleArtifactRef[] $artifacts
     * @param array<int, array<string, mixed>> $replayTranscripts
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $jobId,
        private readonly string $candidateId,
        private readonly VerificationOutcome $outcome,
        array $reasonCodes,
        private readonly string $summary,
        array $artifacts,
        private readonly array $replayTranscripts,
        private readonly string $createdAt,
        private readonly array $metadata = array()
    ) {
        $reasonCodes = array_values(array_unique($reasonCodes));
        sort($reasonCodes);
        $this->reasonCodes = $reasonCodes;

        $this->artifacts = array_values($artifacts);
    }

    /**
     * @var string[]
     */
    private readonly array $reasonCodes;

    /**
     * @var OracleArtifactRef[]
     */
    private readonly array $artifacts;

    public function jobId(): string
    {
        return $this->jobId;
    }

    public function candidateId(): string
    {
        return $this->candidateId;
    }

    public function outcome(): VerificationOutcome
    {
        return $this->outcome;
    }

    /**
     * @return string[]
     */
    public function reasonCodes(): array
    {
        return $this->reasonCodes;
    }

    public function summary(): string
    {
        return $this->summary;
    }

    /**
     * @return OracleArtifactRef[]
     */
    public function artifacts(): array
    {
        return $this->artifacts;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function replayTranscripts(): array
    {
        return $this->replayTranscripts;
    }

    public function createdAt(): string
    {
        return $this->createdAt;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array(
            'job_id' => $this->jobId,
            'candidate_id' => $this->candidateId,
            'outcome' => $this->outcome->value,
            'reason_codes' => $this->reasonCodes,
            'summary' => $this->summary,
            'artifacts' => array_map(
                static fn (OracleArtifactRef $artifact): array => $artifact->toArray(),
                $this->artifacts
            ),
            'replay_transcripts' => $this->replayTranscripts,
            'created_at' => $this->createdAt,
            'metadata' => $this->metadata,
        );
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        $artifacts = array();
        if (is_array($payload['artifacts'] ?? null)) {
            foreach ($payload['artifacts'] as $artifact) {
                if (!is_array($artifact)) {
                    continue;
                }

                $artifacts[] = OracleArtifactRef::fromArray($artifact);
            }
        }

        $replayTranscripts = array();
        if (is_array($payload['replay_transcripts'] ?? null)) {
            foreach ($payload['replay_transcripts'] as $transcript) {
                if (is_array($transcript)) {
                    $replayTranscripts[] = $transcript;
                }
            }
        }

        return new self(
            jobId: (string) ($payload['job_id'] ?? ''),
            candidateId: (string) ($payload['candidate_id'] ?? ''),
            outcome: VerificationOutcome::from((string) ($payload['outcome'] ?? VerificationOutcome::INCONCLUSIVE->value)),
            reasonCodes: is_array($payload['reason_codes'] ?? null)
                ? array_map(static fn (mixed $code): string => (string) $code, $payload['reason_codes'])
                : array(),
            summary: (string) ($payload['summary'] ?? ''),
            artifacts: $artifacts,
            replayTranscripts: $replayTranscripts,
            createdAt: (string) ($payload['created_at'] ?? gmdate('c')),
            metadata: is_array($payload['metadata'] ?? null) ? $payload['metadata'] : array()
        );
    }
}
