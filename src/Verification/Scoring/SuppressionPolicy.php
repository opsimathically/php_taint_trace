<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Scoring;

use PhpTaintTrace\Verification\Model\ScoreBreakdown;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Model\VerificationResult;

final class SuppressionPolicy
{
    /**
     * @param string[] $evidenceReasonCodes
     * @return array{suppressed: bool, reason_codes: string[]}
     */
    public function evaluate(
        VerificationResult $result,
        ScoreBreakdown $scoreBreakdown,
        array $evidenceReasonCodes = array()
    ): array {
        $reasonCodes = array_values(array_unique(array_merge($result->reasonCodes(), $evidenceReasonCodes)));

        if (
            $result->outcome() === VerificationOutcome::BLOCKED_BY_POLICY &&
            !$this->hasExploitConfirmationReason($reasonCodes)
        ) {
            return array(
                'suppressed' => true,
                'reason_codes' => array('SUPPRESSION_POLICY_BLOCKED_BY_POLICY'),
            );
        }

        if ($this->hasTrustedSanitizerProof($reasonCodes)) {
            return array(
                'suppressed' => true,
                'reason_codes' => array('SUPPRESSION_POLICY_TRUSTED_SANITIZER_PROOF'),
            );
        }

        return array(
            'suppressed' => false,
            'reason_codes' => array(),
        );
    }

    /**
     * @param string[] $reasonCodes
     */
    private function hasExploitConfirmationReason(array $reasonCodes): bool
    {
        foreach ($reasonCodes as $reasonCode) {
            if (preg_match('/^VERIFIER_[A-Z0-9_]+_CONFIRMED$/', $reasonCode) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string[] $reasonCodes
     */
    private function hasTrustedSanitizerProof(array $reasonCodes): bool
    {
        $trustedProofCodes = array(
            'SANITIZER_TRUSTED_PROOF_PRESENT',
            'VALIDATOR_TRUSTED_PROOF_PRESENT',
            'CONFIDENCE_SANITIZER_TRUSTED_PROOF',
        );

        foreach ($reasonCodes as $reasonCode) {
            if (in_array($reasonCode, $trustedProofCodes, true)) {
                return true;
            }
        }

        return false;
    }
}
