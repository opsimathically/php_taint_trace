<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\DecisionTier;
use PhpTaintTrace\Verification\Model\RiskDecision;
use PhpTaintTrace\Verification\Model\ScoreBreakdown;
use PHPUnit\Framework\TestCase;

final class RiskDecisionModelTest extends TestCase
{
    public function testDecisionTierEnumContainsExpectedValues(): void
    {
        self::assertSame(
            array('confirmed', 'high_likelihood', 'reachable_unverified', 'suppressed', 'invalid'),
            array_map(static fn (DecisionTier $tier): string => $tier->value, DecisionTier::cases())
        );
    }

    public function testScoreBreakdownClampsAndSerializesDeterministically(): void
    {
        $breakdown = new ScoreBreakdown(
            reachabilityScore: 1.5,
            exploitScore: -2.0,
            sanitizationScore: 0.12555555,
            environmentScore: 0.99,
            reproScore: 0.3333333,
            riskScore: 1.25,
            formulaVersion: 'phase_c_v1_step27'
        );

        $restored = ScoreBreakdown::fromArray($breakdown->toArray());
        self::assertSame(1.0, $restored->reachabilityScore());
        self::assertSame(0.0, $restored->exploitScore());
        self::assertSame(0.125556, $restored->sanitizationScore());
        self::assertSame(1.0, $restored->riskScore());
        self::assertSame('phase_c_v1_step27', $restored->formulaVersion());
    }

    public function testRiskDecisionSerializationNormalizesReasonCodesAndDedupKey(): void
    {
        $decision = new RiskDecision(
            decisionId: 'decision-1',
            jobId: 'job-1',
            candidateId: 'candidate-1',
            decisionTier: DecisionTier::CONFIRMED,
            riskScore: 0.95,
            scoreBreakdown: new ScoreBreakdown(
                reachabilityScore: 1.0,
                exploitScore: 1.0,
                sanitizationScore: 0.0,
                environmentScore: 1.0,
                reproScore: 1.0,
                riskScore: 0.95,
                formulaVersion: 'phase_c_v1_step27'
            ),
            reasonCodes: array('B', 'A', 'A'),
            createdAt: '2026-04-22T00:00:00+00:00'
        );

        $restored = RiskDecision::fromArray($decision->toArray());
        self::assertSame('decision-1', $restored->decisionId());
        self::assertSame(DecisionTier::CONFIRMED, $restored->decisionTier());
        self::assertSame(array('A', 'B'), $restored->reasonCodes());
        self::assertSame($decision->dedupKey(), $restored->dedupKey());
    }
}
