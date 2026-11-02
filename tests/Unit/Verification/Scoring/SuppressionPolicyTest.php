<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification\Scoring;

use PhpTaintTrace\Verification\Model\ScoreBreakdown;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Model\VerificationResult;
use PhpTaintTrace\Verification\Scoring\SuppressionPolicy;
use PHPUnit\Framework\TestCase;

final class SuppressionPolicyTest extends TestCase
{
    public function testSuppressesBlockedByPolicyWithoutExploitConfirmation(): void
    {
        $policy = new SuppressionPolicy();
        $result = $this->verificationResult(VerificationOutcome::BLOCKED_BY_POLICY, array('VERIFIER_PHASE_B_GET_ONLY_POLICY'));

        $evaluation = $policy->evaluate($result, $this->scoreBreakdown());

        self::assertTrue($evaluation['suppressed']);
        self::assertContains('SUPPRESSION_POLICY_BLOCKED_BY_POLICY', $evaluation['reason_codes']);
    }

    public function testSuppressesOnlyOnExplicitTrustedSanitizerProof(): void
    {
        $policy = new SuppressionPolicy();
        $result = $this->verificationResult(VerificationOutcome::INCONCLUSIVE, array('CONFIDENCE_SANITIZER_TRUSTED_PROOF'));

        $evaluation = $policy->evaluate($result, $this->scoreBreakdown());

        self::assertTrue($evaluation['suppressed']);
        self::assertContains('SUPPRESSION_POLICY_TRUSTED_SANITIZER_PROOF', $evaluation['reason_codes']);
    }

    public function testBlockedByPolicyDoesNotSuppressWhenExploitConfirmedReasonExists(): void
    {
        $policy = new SuppressionPolicy();
        $result = $this->verificationResult(
            VerificationOutcome::BLOCKED_BY_POLICY,
            array('VERIFIER_FILE_DIFFERENTIAL_CONFIRMED')
        );

        $evaluation = $policy->evaluate($result, $this->scoreBreakdown());

        self::assertFalse($evaluation['suppressed']);
        self::assertSame(array(), $evaluation['reason_codes']);
    }

    public function testDoesNotSuppressByDefaultWithoutPolicyOrSanitizerProof(): void
    {
        $policy = new SuppressionPolicy();
        $result = $this->verificationResult(VerificationOutcome::INCONCLUSIVE, array('VERIFIER_REPLAY_ERROR'));

        $evaluation = $policy->evaluate($result, $this->scoreBreakdown());

        self::assertFalse($evaluation['suppressed']);
        self::assertSame(array(), $evaluation['reason_codes']);
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

    private function scoreBreakdown(): ScoreBreakdown
    {
        return new ScoreBreakdown(1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 'phase_c_v1_step27');
    }
}
