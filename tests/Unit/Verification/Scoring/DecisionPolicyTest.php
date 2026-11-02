<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification\Scoring;

use PhpTaintTrace\Verification\Model\DecisionTier;
use PhpTaintTrace\Verification\Model\ScoreBreakdown;
use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Model\VerificationResult;
use PhpTaintTrace\Verification\Scoring\DecisionPolicy;
use PHPUnit\Framework\TestCase;

final class DecisionPolicyTest extends TestCase
{
    public function testInvalidHasHighestPrecedence(): void
    {
        $decision = (new DecisionPolicy())->buildDecision(
            $this->job(),
            $this->verificationResult(VerificationOutcome::NOT_CONFIRMED, array('VERIFIER_RCE_NONCE_NOT_OBSERVED')),
            $this->scoreBreakdown(0.95, 1.0),
            array(),
            array()
        );

        self::assertSame(DecisionTier::INVALID, $decision->decisionTier());
    }

    public function testNotConfirmedNeverEscalatesToConfirmedWithHighScore(): void
    {
        $decision = (new DecisionPolicy())->buildDecision(
            $this->job(),
            $this->verificationResult(VerificationOutcome::NOT_CONFIRMED, array('VERIFIER_SQLI_WEAK_DIFFERENTIAL')),
            $this->scoreBreakdown(1.0, 1.0),
            array(),
            array()
        );

        self::assertSame(DecisionTier::INVALID, $decision->decisionTier());
    }

    public function testSuppressedPrecedesConfirmed(): void
    {
        $decision = (new DecisionPolicy())->buildDecision(
            $this->job(),
            $this->verificationResult(VerificationOutcome::BLOCKED_BY_POLICY, array('VERIFIER_PHASE_B_GET_ONLY_POLICY')),
            $this->scoreBreakdown(0.95, 1.0),
            array(),
            array()
        );

        self::assertSame(DecisionTier::SUPPRESSED, $decision->decisionTier());
    }

    public function testConfirmedRequiresThresholdsAndConfirmedOutcome(): void
    {
        $decision = (new DecisionPolicy())->buildDecision(
            $this->job(),
            $this->verificationResult(VerificationOutcome::CONFIRMED, array('VERIFIER_RCE_NONCE_CONFIRMED')),
            $this->scoreBreakdown(0.90, 0.90),
            array(),
            array()
        );

        self::assertSame(DecisionTier::CONFIRMED, $decision->decisionTier());
    }

    public function testHighLikelihoodWhenRiskThresholdMetAndReplayDidNotFail(): void
    {
        $decision = (new DecisionPolicy())->buildDecision(
            $this->job(),
            $this->verificationResult(VerificationOutcome::INCONCLUSIVE, array('VERIFIER_REPLAY_ERROR')),
            $this->scoreBreakdown(0.70, 0.50),
            array(),
            array()
        );

        self::assertSame(DecisionTier::HIGH_LIKELIHOOD, $decision->decisionTier());
    }

    public function testReachableUnverifiedFallback(): void
    {
        $decision = (new DecisionPolicy())->buildDecision(
            $this->job(),
            $this->verificationResult(VerificationOutcome::REPLAY_FAILED, array('VERIFIER_REPLAY_ERROR')),
            $this->scoreBreakdown(0.40, 0.20),
            array(),
            array()
        );

        self::assertSame(DecisionTier::REACHABLE_UNVERIFIED, $decision->decisionTier());
    }

    /**
     * @dataProvider goldenVectorProvider
     */
    public function testGoldenVectorsForTierPrecedence(
        VerificationOutcome $outcome,
        float $riskScore,
        float $exploitScore,
        array $reasonCodes,
        DecisionTier $expectedTier
    ): void {
        $decision = (new DecisionPolicy())->buildDecision(
            $this->job(),
            $this->verificationResult($outcome, $reasonCodes),
            $this->scoreBreakdown($riskScore, $exploitScore),
            array(),
            array()
        );

        self::assertSame($expectedTier, $decision->decisionTier());
    }

    public static function goldenVectorProvider(): array
    {
        return array(
            'confirmed_threshold_met' => array(
                VerificationOutcome::CONFIRMED,
                0.90,
                0.90,
                array('VERIFIER_RCE_NONCE_CONFIRMED'),
                DecisionTier::CONFIRMED,
            ),
            'confirmed_outcome_below_threshold' => array(
                VerificationOutcome::CONFIRMED,
                0.70,
                0.79,
                array('VERIFIER_XSS_CONTEXT_CONFIRMED'),
                DecisionTier::HIGH_LIKELIHOOD,
            ),
            'blocked_by_policy_without_confirm_reason' => array(
                VerificationOutcome::BLOCKED_BY_POLICY,
                0.95,
                1.00,
                array('VERIFIER_PHASE_D_GET_ONLY_POLICY'),
                DecisionTier::SUPPRESSED,
            ),
            'blocked_by_policy_with_confirm_reason' => array(
                VerificationOutcome::BLOCKED_BY_POLICY,
                0.70,
                0.90,
                array('VERIFIER_FILE_DIFFERENTIAL_CONFIRMED'),
                DecisionTier::HIGH_LIKELIHOOD,
            ),
            'replay_failed_never_high_likelihood' => array(
                VerificationOutcome::REPLAY_FAILED,
                0.95,
                0.90,
                array('VERIFIER_SSRF_REPLAY_ERROR'),
                DecisionTier::REACHABLE_UNVERIFIED,
            ),
            'not_confirmed_always_invalid' => array(
                VerificationOutcome::NOT_CONFIRMED,
                1.00,
                1.00,
                array('VERIFIER_IDOR_CONTROL_MISMATCH'),
                DecisionTier::INVALID,
            ),
        );
    }

    private function job(): VerificationJob
    {
        return new VerificationJob(
            jobId: 'job-1',
            candidateId: 'candidate-1',
            sinkCategory: 'rce',
            oracleType: 'rce_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 1,
            status: 'completed',
            candidateSnapshot: array(),
            replayPlan: array('request_method' => 'GET', 'request_uri' => '/?cmd=id')
        );
    }

    private function verificationResult(VerificationOutcome $outcome, array $reasonCodes): VerificationResult
    {
        return new VerificationResult(
            jobId: 'job-1',
            candidateId: 'candidate-1',
            outcome: $outcome,
            reasonCodes: $reasonCodes,
            summary: 'summary',
            artifacts: array(),
            replayTranscripts: array(),
            createdAt: gmdate('c')
        );
    }

    private function scoreBreakdown(float $riskScore, float $exploitScore): ScoreBreakdown
    {
        return new ScoreBreakdown(
            reachabilityScore: 1.0,
            exploitScore: $exploitScore,
            sanitizationScore: 0.0,
            environmentScore: 1.0,
            reproScore: 1.0,
            riskScore: $riskScore,
            formulaVersion: 'phase_c_v1_step27'
        );
    }
}
