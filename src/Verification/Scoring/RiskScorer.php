<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Scoring;

use PhpTaintTrace\Verification\Model\ScoreBreakdown;

final class RiskScorer
{
    private readonly ScoreWeights $weights;

    public function __construct(
        ?ScoreWeights $weights = null
    ) {
        $this->weights = $weights ?? ScoreWeights::v1();
    }

    public function score(
        float $reachabilityScore,
        float $exploitScore,
        float $sanitizationScore,
        float $environmentScore,
        float $reproScore
    ): ScoreBreakdown {
        $riskScore =
            ($this->weights->reachabilityWeight() * $reachabilityScore) +
            ($this->weights->exploitWeight() * $exploitScore) +
            ($this->weights->environmentWeight() * $environmentScore) +
            ($this->weights->reproWeight() * $reproScore) -
            ($this->weights->sanitizationWeight() * $sanitizationScore);

        return new ScoreBreakdown(
            reachabilityScore: $reachabilityScore,
            exploitScore: $exploitScore,
            sanitizationScore: $sanitizationScore,
            environmentScore: $environmentScore,
            reproScore: $reproScore,
            riskScore: $riskScore,
            formulaVersion: $this->weights->formulaVersion()
        );
    }
}
