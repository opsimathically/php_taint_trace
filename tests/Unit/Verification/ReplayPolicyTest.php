<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\ReplayPolicy;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PHPUnit\Framework\TestCase;

final class ReplayPolicyTest extends TestCase
{
    public function testEnforceMethodPolicyBlocksWhenMethodNotAllowed(): void
    {
        $job = $this->job(array(
            'request_method' => 'POST',
            'request_uri' => '/rce',
        ));
        $request = ReplayRequest::fromReplayPlan('rce', $job->replayPlan());
        self::assertNotNull($request);

        $decision = ReplayPolicy::enforceMethodPolicy(
            $job,
            $request,
            array('GET'),
            'VERIFIER_PHASE_B_GET_ONLY_POLICY',
            'Phase B verifier method policy rejected this request.'
        );

        self::assertNotNull($decision);
        self::assertSame(VerificationOutcome::BLOCKED_BY_POLICY, $decision->outcome());
        self::assertContains('VERIFIER_REPLAY_METHOD_BLOCKED', $decision->reasonCodes());
        self::assertContains('VERIFIER_PHASE_B_GET_ONLY_POLICY', $decision->reasonCodes());
    }

    public function testEnforceMethodPolicyAllowsWhenReplayPlanExplicitlyAllowsPost(): void
    {
        $job = $this->job(array(
            'request_method' => 'POST',
            'request_uri' => '/rce',
            'allowed_methods' => array('POST'),
        ));
        $request = ReplayRequest::fromReplayPlan('rce', $job->replayPlan());
        self::assertNotNull($request);

        $decision = ReplayPolicy::enforceMethodPolicy(
            $job,
            $request,
            array('GET'),
            'VERIFIER_PHASE_B_GET_ONLY_POLICY',
            'Phase B verifier method policy rejected this request.'
        );

        self::assertNull($decision);
    }

    public function testResolveTargetParameterUsesBodyWhenConfigured(): void
    {
        $job = $this->job(array(
            'request_method' => 'POST',
            'request_uri' => '/rce',
            'target_param_location' => 'body',
            'target_body_param' => 'cmd',
            'replay_body' => 'cmd=id&keep=1',
        ));
        $request = ReplayRequest::fromReplayPlan('rce', $job->replayPlan());
        self::assertNotNull($request);

        $target = ReplayPolicy::resolveTargetParameter($job, $request);
        self::assertSame(array('location' => 'body', 'parameter' => 'cmd'), $target);

        $mutated = ReplayPolicy::mutateRequest($request, $target, 'echo nonce', 'positive');
        self::assertSame('body', $mutated->mutatedParameterLocation());
        self::assertSame('echo nonce', $mutated->bodyParams()['cmd'] ?? null);
    }

    public function testResolveTargetParameterSkipsRoutingKeysWhenFallingBack(): void
    {
        $job = $this->job(array(
            'request_method' => 'GET',
            'request_uri' => '/?sink=eval&mode=vuln&cmd=id',
            'target_query_param' => 'missing',
        ));
        $request = ReplayRequest::fromReplayPlan('rce', $job->replayPlan());
        self::assertNotNull($request);

        $target = ReplayPolicy::resolveTargetParameter($job, $request);
        self::assertSame(array('location' => 'query', 'parameter' => 'cmd'), $target);
    }

    public function testResolveTargetParameterPrefersSinkSpecificParameterWhenAvailable(): void
    {
        $job = $this->job(
            array(
                'request_method' => 'GET',
                'request_uri' => '/?alpha=1&sink=curl_setopt&target_url=http%3A%2F%2F127.0.0.1',
            ),
            sinkCategory: 'ssrf'
        );
        $request = ReplayRequest::fromReplayPlan('ssrf', $job->replayPlan());
        self::assertNotNull($request);

        $target = ReplayPolicy::resolveTargetParameter($job, $request);
        self::assertSame(array('location' => 'query', 'parameter' => 'target_url'), $target);
    }

    /**
     * @param array<string, mixed> $replayPlan
     */
    private function job(array $replayPlan, string $sinkCategory = 'rce'): VerificationJob
    {
        $oracleType = match ($sinkCategory) {
            'ssrf' => 'ssrf_oracle',
            'sqli' => 'sqli_oracle',
            'file' => 'file_oracle',
            'xss' => 'xss_oracle',
            'idor' => 'idor_oracle',
            'xxe' => 'xxe_oracle',
            default => 'rce_oracle',
        };

        return new VerificationJob(
            jobId: 'job-policy',
            candidateId: 'candidate-policy',
            sinkCategory: $sinkCategory,
            oracleType: $oracleType,
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: array(),
            replayPlan: $replayPlan
        );
    }
}
