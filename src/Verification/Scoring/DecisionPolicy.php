<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Scoring;

use PhpTaintTrace\Verification\Model\DecisionTier;
use PhpTaintTrace\Verification\Model\RiskDecision;
use PhpTaintTrace\Verification\Model\ScoreBreakdown;
use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Model\VerificationResult;

final class DecisionPolicy
{
    private readonly SuppressionPolicy $suppressionPolicy;

    public function __construct(
        ?SuppressionPolicy $suppressionPolicy = null
    ) {
        $this->suppressionPolicy = $suppressionPolicy ?? new SuppressionPolicy();
    }

    /**
     * @param string[] $evidenceReasonCodes
     * @param array<string, mixed> $evidenceMetadata
     */
    public function buildDecision(
        VerificationJob $job,
        VerificationResult $result,
        ScoreBreakdown $scoreBreakdown,
        array $evidenceReasonCodes = array(),
        array $evidenceMetadata = array()
    ): RiskDecision {
        $reasonCodes = array_values(array_unique(array_merge($result->reasonCodes(), $evidenceReasonCodes)));
        $tierReasonCodes = array();

        if ($result->outcome() === VerificationOutcome::NOT_CONFIRMED) {
            $tier = DecisionTier::INVALID;
            $tierReasonCodes[] = 'DECISION_TIER_INVALID_NOT_CONFIRMED';
        } else {
            $suppression = $this->suppressionPolicy->evaluate($result, $scoreBreakdown, $reasonCodes);
            if ($suppression['suppressed']) {
                $tier = DecisionTier::SUPPRESSED;
                $tierReasonCodes = array_merge($tierReasonCodes, $suppression['reason_codes']);
            } elseif (
                $result->outcome() === VerificationOutcome::CONFIRMED &&
                $scoreBreakdown->riskScore() >= 0.85 &&
                $scoreBreakdown->exploitScore() >= 0.80
            ) {
                $tier = DecisionTier::CONFIRMED;
                $tierReasonCodes[] = 'DECISION_TIER_CONFIRMED_THRESHOLD_MET';
            } elseif (
                $scoreBreakdown->riskScore() >= 0.65 &&
                $result->outcome() !== VerificationOutcome::REPLAY_FAILED
            ) {
                $tier = DecisionTier::HIGH_LIKELIHOOD;
                $tierReasonCodes[] = 'DECISION_TIER_HIGH_LIKELIHOOD_THRESHOLD_MET';
            } else {
                $tier = DecisionTier::REACHABLE_UNVERIFIED;
                $tierReasonCodes[] = 'DECISION_TIER_REACHABLE_UNVERIFIED_DEFAULT';
            }
        }

        $decisionId = hash('sha256', implode('|', array(
            $job->jobId(),
            $scoreBreakdown->formulaVersion(),
        )));

        $decisionMetadata = array_merge(
            $evidenceMetadata,
            array(
                'verification_outcome' => $result->outcome()->value,
                'sink_category' => $job->sinkCategory(),
                'oracle_type' => $job->oracleType(),
            )
        );

        return new RiskDecision(
            decisionId: $decisionId,
            jobId: $job->jobId(),
            candidateId: $job->candidateId(),
            decisionTier: $tier,
            riskScore: $scoreBreakdown->riskScore(),
            scoreBreakdown: $scoreBreakdown,
            reasonCodes: array_merge($reasonCodes, $tierReasonCodes),
            createdAt: gmdate('c'),
            metadata: $decisionMetadata
        );
    }
}
