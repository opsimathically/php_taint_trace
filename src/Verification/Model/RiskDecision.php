<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class RiskDecision
{
    /**
     * @param string[] $reasonCodes
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $decisionId,
        private readonly string $jobId,
        private readonly string $candidateId,
        private readonly DecisionTier $decisionTier,
        private readonly float $riskScore,
        private readonly ScoreBreakdown $scoreBreakdown,
        array $reasonCodes,
        private readonly string $createdAt,
        private readonly array $metadata = array()
    ) {
        $reasonCodes = array_values(array_unique($reasonCodes));
        sort($reasonCodes);
        $this->reasonCodes = $reasonCodes;
    }

    /**
     * @var string[]
     */
    private readonly array $reasonCodes;

    public function decisionId(): string
    {
        return $this->decisionId;
    }

    public function jobId(): string
    {
        return $this->jobId;
    }

    public function candidateId(): string
    {
        return $this->candidateId;
    }

    public function decisionTier(): DecisionTier
    {
        return $this->decisionTier;
    }

    public function riskScore(): float
    {
        return $this->riskScore;
    }

    public function scoreBreakdown(): ScoreBreakdown
    {
        return $this->scoreBreakdown;
    }

    /**
     * @return string[]
     */
    public function reasonCodes(): array
    {
        return $this->reasonCodes;
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

    public function dedupKey(): string
    {
        return hash('sha256', implode('|', array(
            $this->jobId,
            $this->scoreBreakdown->formulaVersion(),
        )));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array(
            'decision_id' => $this->decisionId,
            'job_id' => $this->jobId,
            'candidate_id' => $this->candidateId,
            'decision_tier' => $this->decisionTier->value,
            'risk_score' => round(max(0.0, min(1.0, $this->riskScore)), 6),
            'score_breakdown' => $this->scoreBreakdown->toArray(),
            'reason_codes' => $this->reasonCodes,
            'created_at' => $this->createdAt,
            'metadata' => $this->metadata,
            'dedup_key' => $this->dedupKey(),
        );
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        return new self(
            decisionId: (string) ($payload['decision_id'] ?? ''),
            jobId: (string) ($payload['job_id'] ?? ''),
            candidateId: (string) ($payload['candidate_id'] ?? ''),
            decisionTier: DecisionTier::from((string) ($payload['decision_tier'] ?? DecisionTier::REACHABLE_UNVERIFIED->value)),
            riskScore: (float) ($payload['risk_score'] ?? 0.0),
            scoreBreakdown: ScoreBreakdown::fromArray(
                is_array($payload['score_breakdown'] ?? null) ? $payload['score_breakdown'] : array()
            ),
            reasonCodes: is_array($payload['reason_codes'] ?? null)
                ? array_map(static fn (mixed $code): string => (string) $code, $payload['reason_codes'])
                : array(),
            createdAt: (string) ($payload['created_at'] ?? gmdate('c')),
            metadata: is_array($payload['metadata'] ?? null) ? $payload['metadata'] : array()
        );
    }
}
