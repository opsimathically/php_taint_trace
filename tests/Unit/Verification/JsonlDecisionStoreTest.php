<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\DecisionTier;
use PhpTaintTrace\Verification\Model\RiskDecision;
use PhpTaintTrace\Verification\Model\ScoreBreakdown;
use PhpTaintTrace\Verification\Storage\JsonlDecisionStore;
use PHPUnit\Framework\TestCase;

final class JsonlDecisionStoreTest extends TestCase
{
    public function testPersistAndDedupAreStable(): void
    {
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-decision-store-' . uniqid('', true);
        $store = new JsonlDecisionStore($runtimeDir);

        $decision = $this->decision(jobId: 'job-1');
        self::assertTrue($store->persist($decision));
        self::assertFalse($store->persist($decision));

        $rows = file($store->decisionsPath(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($rows);
        self::assertCount(1, $rows);

        $payload = json_decode($rows[0], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('job-1', $payload['job_id']);
        self::assertSame('confirmed', $payload['decision_tier']);
        self::assertArrayHasKey('score_breakdown', $payload);
        self::assertSame('phase_c_v1_step27', $payload['score_breakdown']['formula_version']);
    }

    private function decision(string $jobId): RiskDecision
    {
        return new RiskDecision(
            decisionId: hash('sha256', $jobId),
            jobId: $jobId,
            candidateId: 'candidate-' . $jobId,
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
            reasonCodes: array('VERIFIER_RCE_NONCE_CONFIRMED'),
            createdAt: gmdate('c')
        );
    }
}
