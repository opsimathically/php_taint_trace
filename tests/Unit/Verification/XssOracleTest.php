<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Oracle\XssOracle;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;
use PHPUnit\Framework\TestCase;

final class XssOracleTest extends TestCase
{
    public function testXssOracleConfirmsScriptReflectionDifferential(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $name = $request->queryParams()[$request->mutatedParameter() ?? 'name'] ?? 'guest';
                return new ReplayResult(
                    $request,
                    200,
                    sprintf('Hello %s', $name),
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

        $decision = (new XssOracle())->verify(new OracleContext(
            $this->job('/xss?name=guest'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xss-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XSS_CONTEXT_CONFIRMED', $decision->reasonCodes());
    }

    public function testXssOracleReturnsNotConfirmedWhenNoDifferential(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'constant', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new XssOracle())->verify(new OracleContext(
            $this->job('/xss?name=guest'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xss-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XSS_WEAK_DIFFERENTIAL', $decision->reasonCodes());
        self::assertContains('VERIFIER_XSS_CONTEXT_NOT_OBSERVED', $decision->reasonCodes());
    }

    public function testXssOracleReturnsNotConfirmedWhenControlAlsoContainsNonce(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            private string $nonce = '';

            public function replay(ReplayRequest $request): ReplayResult
            {
                $name = $request->queryParams()[$request->mutatedParameter() ?? 'name'] ?? 'guest';
                if (($request->payloadLabel() ?? '') === 'positive_script') {
                    if (preg_match('/<script>([^<]+)<\/script>/', $name, $matches) === 1) {
                        $this->nonce = $matches[1];
                    }
                    return new ReplayResult($request, 200, sprintf('Hello %s', $name), null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'Hello ' . $this->nonce, null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new XssOracle())->verify(new OracleContext(
            $this->job('/xss?name=guest'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xss-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XSS_AMBIGUOUS_CONTROL_SIGNAL', $decision->reasonCodes());
    }

    public function testXssOracleReturnsBlockedByPolicyForNonGetRequests(): void
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

        $decision = (new XssOracle())->verify(new OracleContext(
            $this->job('/xss?name=guest', 'POST'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xss-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::BLOCKED_BY_POLICY, $decision->outcome());
    }

    public function testXssOracleReturnsReplayFailedWhenPositiveReplayFails(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                if (($request->payloadLabel() ?? '') === 'positive_script') {
                    return new ReplayResult($request, null, '', 'timeout', gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new XssOracle())->verify(new OracleContext(
            $this->job('/xss?name=guest'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xss-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::REPLAY_FAILED, $decision->outcome());
    }

    public function testXssOracleRejectsUnstableDifferentialAcrossRepeatedAttempts(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $name = (string) ($request->queryParams()[$request->mutatedParameter() ?? 'name'] ?? 'guest');
                $label = (string) ($request->payloadLabel() ?? '');
                if (str_starts_with($label, 'positive_script')) {
                    if ($label === 'positive_script') {
                        return new ReplayResult($request, 200, sprintf('Hello %s', $name), null, gmdate('c'), gmdate('c'));
                    }

                    return new ReplayResult($request, 200, 'Hello guest', null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'Hello control', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new XssOracle())->verify(new OracleContext(
            $this->job('/xss?name=guest'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xss-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XSS_RESPONSE_INSTABILITY', $decision->reasonCodes());
    }

    private function job(string $requestUri, string $method = 'GET'): VerificationJob
    {
        return new VerificationJob(
            jobId: 'job-xss',
            candidateId: 'candidate-xss',
            sinkCategory: 'xss',
            oracleType: 'xss_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: array(),
            replayPlan: array(
                'request_method' => $method,
                'request_uri' => $requestUri,
                'target_query_param' => 'name',
            )
        );
    }
}
