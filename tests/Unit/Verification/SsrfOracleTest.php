<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Oracle\SsrfOracle;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;
use PHPUnit\Framework\TestCase;

final class SsrfOracleTest extends TestCase
{
    public function testSsrfOracleConfirmsCallbackDifferential(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $url = $request->queryParams()[$request->mutatedParameter() ?? 'url'] ?? '';
                $body = 'control';
                parse_str((string) parse_url($url, PHP_URL_QUERY), $parsed);
                if (str_starts_with((string) ($request->payloadLabel() ?? ''), 'positive_callback') && isset($parsed['name'])) {
                    $body = 'Hello ' . $parsed['name'];
                }

                return new ReplayResult($request, 200, $body, null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SsrfOracle())->verify(new OracleContext(
            $this->job('/ssrf?url=http%3A%2F%2F127.0.0.1%2F%3Fname%3Dxtanzi'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-ssrf-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SSRF_CALLBACK_CONFIRMED', $decision->reasonCodes());
    }

    public function testSsrfOracleReturnsInconclusiveWhenNoReplayParamExists(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SsrfOracle())->verify(new OracleContext(
            $this->job('/ssrf'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-ssrf-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::INCONCLUSIVE, $decision->outcome());
    }

    public function testSsrfOracleReturnsNotConfirmedWhenNonceAppearsInControlResponse(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            private string $nonce = '';

            public function replay(ReplayRequest $request): ReplayResult
            {
                $url = $request->queryParams()[$request->mutatedParameter() ?? 'url'] ?? '';
                parse_str((string) parse_url($url, PHP_URL_QUERY), $parsed);
                if (($request->payloadLabel() ?? '') === 'positive_callback' && isset($parsed['name'])) {
                    $this->nonce = (string) $parsed['name'];
                    return new ReplayResult($request, 200, 'Hello ' . $this->nonce, null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'Hello ' . $this->nonce, null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SsrfOracle())->verify(new OracleContext(
            $this->job('/ssrf?url=http%3A%2F%2F127.0.0.1%2F%3Fname%3Dxtanzi'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-ssrf-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SSRF_AMBIGUOUS_CONTROL_SIGNAL', $decision->reasonCodes());
    }

    public function testSsrfOracleRejectsWeakDifferentialWhenNonceIsNeverObserved(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'constant body', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SsrfOracle())->verify(new OracleContext(
            $this->job('/ssrf?url=http%3A%2F%2F127.0.0.1%2F%3Fname%3Dxtanzi'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-ssrf-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SSRF_WEAK_DIFFERENTIAL', $decision->reasonCodes());
    }

    public function testSsrfOracleRejectsUnstableDifferentialAcrossRepeatedAttempts(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            private string $nonce = '';

            public function replay(ReplayRequest $request): ReplayResult
            {
                $url = (string) ($request->queryParams()[$request->mutatedParameter() ?? 'url'] ?? '');
                $label = (string) ($request->payloadLabel() ?? '');
                parse_str((string) parse_url($url, PHP_URL_QUERY), $parsed);
                if (str_starts_with($label, 'positive_callback') && isset($parsed['name'])) {
                    $this->nonce = (string) $parsed['name'];
                    if ($label === 'positive_callback') {
                        return new ReplayResult($request, 200, 'Hello ' . $this->nonce, null, gmdate('c'), gmdate('c'));
                    }

                    return new ReplayResult($request, 200, 'Hello control', null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'Hello control', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SsrfOracle())->verify(new OracleContext(
            $this->job('/ssrf?url=http%3A%2F%2F127.0.0.1%2F%3Fname%3Dxtanzi'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-ssrf-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SSRF_RESPONSE_INSTABILITY', $decision->reasonCodes());
    }

    public function testSsrfOracleReturnsReplayFailedOnTransportError(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                if (($request->payloadLabel() ?? '') === 'positive_callback') {
                    return new ReplayResult($request, null, '', 'timeout', gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SsrfOracle())->verify(new OracleContext(
            $this->job('/ssrf?url=http%3A%2F%2F127.0.0.1%2F%3Fname%3Dxtanzi'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-ssrf-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::REPLAY_FAILED, $decision->outcome());
        self::assertContains('VERIFIER_SSRF_REPLAY_ERROR', $decision->reasonCodes());
    }

    private function job(string $requestUri): VerificationJob
    {
        return new VerificationJob(
            jobId: 'job-ssrf',
            candidateId: 'candidate-ssrf',
            sinkCategory: 'ssrf',
            oracleType: 'ssrf_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: array(),
            replayPlan: array(
                'request_method' => 'GET',
                'request_uri' => $requestUri,
                'target_query_param' => 'url',
            )
        );
    }
}
