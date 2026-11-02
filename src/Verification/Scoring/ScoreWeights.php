<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Scoring;

final class ScoreWeights
{
    public const FORMULA_VERSION_V1 = 'phase_c_v1_step27';

    public function __construct(
        private readonly float $reachabilityWeight,
        private readonly float $exploitWeight,
        private readonly float $environmentWeight,
        private readonly float $reproWeight,
        private readonly float $sanitizationWeight,
        private readonly string $formulaVersion = self::FORMULA_VERSION_V1
    ) {
    }

    public static function v1(): self
    {
        return new self(
            reachabilityWeight: 0.30,
            exploitWeight: 0.40,
            environmentWeight: 0.15,
            reproWeight: 0.15,
            sanitizationWeight: 0.35,
            formulaVersion: self::FORMULA_VERSION_V1
        );
    }

    public function reachabilityWeight(): float
    {
        return $this->reachabilityWeight;
    }

    public function exploitWeight(): float
    {
        return $this->exploitWeight;
    }

    public function environmentWeight(): float
    {
        return $this->environmentWeight;
    }

    public function reproWeight(): float
    {
        return $this->reproWeight;
    }

    public function sanitizationWeight(): float
    {
        return $this->sanitizationWeight;
    }

    public function formulaVersion(): string
    {
        return $this->formulaVersion;
    }
}
