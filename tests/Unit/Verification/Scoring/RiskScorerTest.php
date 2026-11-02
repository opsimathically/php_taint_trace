<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification\Scoring;

use PhpTaintTrace\Verification\Scoring\RiskScorer;
use PHPUnit\Framework\TestCase;

final class RiskScorerTest extends TestCase
{
    public function testRiskScoreMatchesStep27Formula(): void
    {
        $breakdown = (new RiskScorer())->score(
            reachabilityScore: 0.90,
            exploitScore: 0.80,
            sanitizationScore: 0.10,
            environmentScore: 1.00,
            reproScore: 0.50
        );

        self::assertSame(0.78, $breakdown->riskScore());
        self::assertSame('phase_c_v1_step27', $breakdown->formulaVersion());
    }

    public function testRiskScoreIsClampedToZeroAndOne(): void
    {
        $scorer = new RiskScorer();

        $low = $scorer->score(
            reachabilityScore: 0.0,
            exploitScore: 0.0,
            sanitizationScore: 1.0,
            environmentScore: 0.0,
            reproScore: 0.0
        );
        self::assertSame(0.0, $low->riskScore());

        $high = $scorer->score(
            reachabilityScore: 2.0,
            exploitScore: 2.0,
            sanitizationScore: 0.0,
            environmentScore: 2.0,
            reproScore: 2.0
        );
        self::assertSame(1.0, $high->riskScore());
    }
}
