<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\IdorOracle;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;
use PHPUnit\Framework\TestCase;

final class IdorOracleTest extends TestCase
{
    public function testIdorOracleConfirmsAuthorizationDifferential(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $params = $request->queryParams();
                $resource = (string) ($params['resource_id'] ?? '42');
                $owner = (string) ((int) $resource + 1000);
                $actor = (string) ($params['actor_id'] ?? '');
                $mode = (string) ($params['mode'] ?? 'vuln');

                if ($mode === 'safe' && $actor !== $owner) {
                    return new ReplayResult($request, 403, 'forbidden', null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult(
                    $request,
                    200,
                    sprintf('resource:%s owner:%s actor:%s mode:%s', $resource, $owner, $actor, $mode),
                    null,
                    gmdate('c'),
                    gmdate('c')
                );
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new IdorOracle())->verify(new OracleContext(
            $this->job('/idor?resource_id=42&actor_id=1043&mode=vuln'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-idor-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_IDOR_DIFFERENTIAL_CONFIRMED', $decision->reasonCodes());
    }

    public function testIdorOracleReturnsNotConfirmedWhenSafeModeAlsoAllowsNonOwner(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $params = $request->queryParams();
                $resource = (string) ($params['resource_id'] ?? '42');
                $actor = (string) ($params['actor_id'] ?? '');
                $mode = (string) ($params['mode'] ?? 'vuln');

                return new ReplayResult(
                    $request,
                    200,
                    sprintf('resource:%s actor:%s mode:%s', $resource, $actor, $mode),
                    null,
                    gmdate('c'),
                    gmdate('c')
                );
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new IdorOracle())->verify(new OracleContext(
            $this->job('/idor?resource_id=42&actor_id=1043&mode=vuln'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-idor-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_IDOR_AMBIGUOUS_CONTROL_SIGNAL', $decision->reasonCodes());
    }

    public function testIdorOracleReturnsBlockedByPolicyForNonGetRequests(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'ignored', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new IdorOracle())->verify(new OracleContext(
            $this->job('/idor?resource_id=42&actor_id=1043&mode=vuln', 'POST'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-idor-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::BLOCKED_BY_POLICY, $decision->outcome());
    }

    public function testIdorOracleReturnsReplayFailedWhenAnyAttemptFails(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                if (($request->payloadLabel() ?? '') === 'owner_safe_mode') {
                    return new ReplayResult($request, null, '', 'timeout', gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'resource:42', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new IdorOracle())->verify(new OracleContext(
            $this->job('/idor?resource_id=42&actor_id=1043&mode=vuln'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-idor-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::REPLAY_FAILED, $decision->outcome());
    }

    public function testIdorOracleRejectsUnstableDifferentialAcrossRepeatedAttempts(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $params = $request->queryParams();
                $resource = (string) ($params['resource_id'] ?? '42');
                $owner = (string) ((int) $resource + 1000);
                $actor = (string) ($params['actor_id'] ?? '');
                $mode = (string) ($params['mode'] ?? 'vuln');
                $label = (string) ($request->payloadLabel() ?? '');

                if ($mode === 'safe' && $actor !== $owner) {
                    return new ReplayResult($request, 403, 'forbidden', null, gmdate('c'), gmdate('c'));
                }
                if ($mode === 'vuln' && $actor !== $owner && str_ends_with($label, '_repeat')) {
                    return new ReplayResult($request, 403, 'forbidden', null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult(
                    $request,
                    200,
                    sprintf('resource:%s owner:%s actor:%s mode:%s', $resource, $owner, $actor, $mode),
                    null,
                    gmdate('c'),
                    gmdate('c')
                );
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new IdorOracle())->verify(new OracleContext(
            $this->job('/idor?resource_id=42&actor_id=1043&mode=vuln'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-idor-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_IDOR_RESPONSE_INSTABILITY', $decision->reasonCodes());
    }

    public function testIdorOracleRejectsWeakDifferentialWhenSignalsDoNotAlign(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $params = $request->queryParams();
                $resource = (string) ($params['resource_id'] ?? '42');
                $owner = (string) ((int) $resource + 1000);
                $actor = (string) ($params['actor_id'] ?? '');
                $mode = (string) ($params['mode'] ?? 'vuln');

                if ($mode === 'vuln' && $actor !== $owner) {
                    return new ReplayResult($request, 403, 'forbidden', null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult(
                    $request,
                    200,
                    sprintf('resource:%s owner:%s actor:%s mode:%s', $resource, $owner, $actor, $mode),
                    null,
                    gmdate('c'),
                    gmdate('c')
                );
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new IdorOracle())->verify(new OracleContext(
            $this->job('/idor?resource_id=42&actor_id=1043&mode=vuln'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-idor-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_IDOR_WEAK_DIFFERENTIAL', $decision->reasonCodes());
    }

    private function job(string $requestUri, string $method = 'GET'): VerificationJob
    {
        return new VerificationJob(
            jobId: 'job-idor',
            candidateId: 'candidate-idor',
            sinkCategory: 'idor',
            oracleType: 'idor_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: array(),
            replayPlan: array(
                'request_method' => $method,
                'request_uri' => $requestUri,
                'target_query_param' => 'resource_id',
                'idor_resource_param' => 'resource_id',
                'idor_actor_param' => 'actor_id',
                'idor_mode_param' => 'mode',
            )
        );
    }
}
