<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class ScoreBreakdown
{
    private readonly float $reachabilityScore;
    private readonly float $exploitScore;
    private readonly float $sanitizationScore;
    private readonly float $environmentScore;
    private readonly float $reproScore;
    private readonly float $riskScore;
    private readonly string $formulaVersion;

    public function __construct(
        float $reachabilityScore,
        float $exploitScore,
        float $sanitizationScore,
        float $environmentScore,
        float $reproScore,
        float $riskScore,
        string $formulaVersion
    ) {
        $this->reachabilityScore = self::normalizeScore($reachabilityScore);
        $this->exploitScore = self::normalizeScore($exploitScore);
        $this->sanitizationScore = self::normalizeScore($sanitizationScore);
        $this->environmentScore = self::normalizeScore($environmentScore);
        $this->reproScore = self::normalizeScore($reproScore);
        $this->riskScore = self::normalizeScore($riskScore);
        $this->formulaVersion = trim($formulaVersion) === '' ? 'phase_c_v1_step27' : trim($formulaVersion);
    }

    public function reachabilityScore(): float
    {
        return $this->reachabilityScore;
    }

    public function exploitScore(): float
    {
        return $this->exploitScore;
    }

    public function sanitizationScore(): float
    {
        return $this->sanitizationScore;
    }

    public function environmentScore(): float
    {
        return $this->environmentScore;
    }

    public function reproScore(): float
    {
        return $this->reproScore;
    }

    public function riskScore(): float
    {
        return $this->riskScore;
    }

    public function formulaVersion(): string
    {
        return $this->formulaVersion;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array(
            'reachability_score' => $this->reachabilityScore,
            'exploit_score' => $this->exploitScore,
            'sanitization_score' => $this->sanitizationScore,
            'environment_score' => $this->environmentScore,
            'repro_score' => $this->reproScore,
            'risk_score' => $this->riskScore,
            'formula_version' => $this->formulaVersion,
        );
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        return new self(
            reachabilityScore: (float) ($payload['reachability_score'] ?? 0.0),
            exploitScore: (float) ($payload['exploit_score'] ?? 0.0),
            sanitizationScore: (float) ($payload['sanitization_score'] ?? 0.0),
            environmentScore: (float) ($payload['environment_score'] ?? 0.0),
            reproScore: (float) ($payload['repro_score'] ?? 0.0),
            riskScore: (float) ($payload['risk_score'] ?? 0.0),
            formulaVersion: (string) ($payload['formula_version'] ?? 'phase_c_v1_step27')
        );
    }

    private static function normalizeScore(float $score): float
    {
        return round(max(0.0, min(1.0, $score)), 6);
    }
}
