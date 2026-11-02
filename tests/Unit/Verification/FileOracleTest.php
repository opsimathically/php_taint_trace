<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\FileOracle;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;
use PHPUnit\Framework\TestCase;

final class FileOracleTest extends TestCase
{
    public function testFileOracleConfirmsSuccessAndDenyDifferential(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $path = $request->queryParams()[$request->mutatedParameter() ?? 'path'] ?? '';
                if ($path === '/etc/hostname') {
                    return new ReplayResult($request, 200, "fixture-host\n", null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 500, 'read failed', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new FileOracle())->verify(new OracleContext(
            $this->job('/file?path=/tmp/input'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-file-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_FILE_DIFFERENTIAL_CONFIRMED', $decision->reasonCodes());
    }

    public function testFileOracleReturnsNotConfirmedWhenControlsMatch(): void
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

        $decision = (new FileOracle())->verify(new OracleContext(
            $this->job('/file?path=/tmp/input'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-file-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_FILE_AMBIGUOUS_CONTROL_SIGNAL', $decision->reasonCodes());
    }

    public function testFileOracleReturnsBlockedByPolicyForNonGetRequests(): void
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

        $decision = (new FileOracle())->verify(new OracleContext(
            $this->job('/file?path=/tmp/input', 'POST'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-file-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::BLOCKED_BY_POLICY, $decision->outcome());
    }

    public function testFileOracleReturnsReplayFailedOnRequestError(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                if (($request->payloadLabel() ?? '') === 'positive_file_read') {
                    return new ReplayResult($request, null, '', 'timeout', gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 500, 'read failed', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new FileOracle())->verify(new OracleContext(
            $this->job('/file?path=/tmp/input'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-file-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::REPLAY_FAILED, $decision->outcome());
    }

    public function testFileOracleRejectsUnstableDifferentialAcrossRepeatedAttempts(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $label = (string) ($request->payloadLabel() ?? '');
                $path = (string) ($request->queryParams()[$request->mutatedParameter() ?? 'path'] ?? '');
                if ($path === '/etc/hostname') {
                    if ($label === 'positive_file_read') {
                        return new ReplayResult($request, 200, "fixture-host\n", null, gmdate('c'), gmdate('c'));
                    }

                    return new ReplayResult($request, 500, 'read failed', null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 500, 'read failed', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new FileOracle())->verify(new OracleContext(
            $this->job('/file?path=/tmp/input'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-file-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_FILE_RESPONSE_INSTABILITY', $decision->reasonCodes());
    }

    public function testFileOracleRejectsWeakDifferentialWhenSignalsAreAbsent(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, '', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new FileOracle())->verify(new OracleContext(
            $this->job('/file?path=/tmp/input'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-file-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_FILE_WEAK_DIFFERENTIAL', $decision->reasonCodes());
    }

    private function job(string $requestUri, string $method = 'GET'): VerificationJob
    {
        return new VerificationJob(
            jobId: 'job-file',
            candidateId: 'candidate-file',
            sinkCategory: 'file',
            oracleType: 'file_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: array(),
            replayPlan: array(
                'request_method' => $method,
                'request_uri' => $requestUri,
                'target_query_param' => 'path',
            )
        );
    }
}
