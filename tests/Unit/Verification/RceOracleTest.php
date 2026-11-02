<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Oracle\RceOracle;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;
use PHPUnit\Framework\TestCase;

final class RceOracleTest extends TestCase
{
    public function testRceOracleConfirmsNonceDifferential(): void
    {
        $runner = $this->runnerWithCallback(function (ReplayRequest $request): ReplayResult {
            $label = (string) ($request->payloadLabel() ?? '');
            $body = 'control';
            if (str_starts_with($label, 'positive_nonce')) {
                $body = $this->payloadExecutionOutput($request) ?? 'control';
            }

            return new ReplayResult($request, 200, $body, null, gmdate('c'), gmdate('c'));
        });

        $oracle = new RceOracle();
        $decision = $oracle->verify(new OracleContext(
            $this->job('/rce?cmd=id'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-rce-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_RCE_NONCE_CONFIRMED', $decision->reasonCodes());
    }

    public function testRceOracleReturnsInconclusiveWhenNoReplayParamExists(): void
    {
        $runner = $this->runnerWithCallback(fn (ReplayRequest $request): ReplayResult => new ReplayResult(
            $request,
            200,
            'ok',
            null,
            gmdate('c'),
            gmdate('c')
        ));

        $decision = (new RceOracle())->verify(new OracleContext(
            $this->job('/rce'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-rce-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::INCONCLUSIVE, $decision->outcome());
    }

    public function testRceOracleReturnsNotConfirmedWhenNonceAppearsInControlResponse(): void
    {
        $positiveToken = '';
        $runner = $this->runnerWithCallback(function (ReplayRequest $request) use (&$positiveToken): ReplayResult {
            $label = (string) ($request->payloadLabel() ?? '');
            if ($label === 'positive_nonce') {
                $positiveToken = $this->payloadExecutionOutput($request) ?? '';
                return new ReplayResult($request, 200, $positiveToken, null, gmdate('c'), gmdate('c'));
            }

            return new ReplayResult($request, 200, $positiveToken, null, gmdate('c'), gmdate('c'));
        });

        $decision = (new RceOracle())->verify(new OracleContext(
            $this->job('/rce?cmd=id'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-rce-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_RCE_AMBIGUOUS_CONTROL_SIGNAL', $decision->reasonCodes());
    }

    public function testRceOracleRejectsWeakDifferentialWhenNonceIsNeverObserved(): void
    {
        $runner = $this->runnerWithCallback(fn (ReplayRequest $request): ReplayResult => new ReplayResult(
            $request,
            200,
            'constant body',
            null,
            gmdate('c'),
            gmdate('c')
        ));

        $decision = (new RceOracle())->verify(new OracleContext(
            $this->job('/rce?cmd=id'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-rce-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_RCE_WEAK_DIFFERENTIAL', $decision->reasonCodes());
    }

    public function testRceOracleRejectsUnstableDifferentialAcrossRepeatedAttempts(): void
    {
        $runner = $this->runnerWithCallback(function (ReplayRequest $request): ReplayResult {
            $label = (string) ($request->payloadLabel() ?? '');
            if ($label === 'positive_nonce') {
                return new ReplayResult(
                    $request,
                    200,
                    $this->payloadExecutionOutput($request) ?? 'control',
                    null,
                    gmdate('c'),
                    gmdate('c')
                );
            }

            return new ReplayResult($request, 200, 'control', null, gmdate('c'), gmdate('c'));
        });

        $decision = (new RceOracle())->verify(new OracleContext(
            $this->job('/rce?cmd=id'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-rce-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_RCE_RESPONSE_INSTABILITY', $decision->reasonCodes());
    }

    public function testRceOracleReturnsReplayFailedOnTransportError(): void
    {
        $runner = $this->runnerWithCallback(function (ReplayRequest $request): ReplayResult {
            if (($request->payloadLabel() ?? '') === 'positive_nonce') {
                return new ReplayResult($request, null, '', 'timeout', gmdate('c'), gmdate('c'));
            }

            return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
        });

        $decision = (new RceOracle())->verify(new OracleContext(
            $this->job('/rce?cmd=id'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-rce-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::REPLAY_FAILED, $decision->outcome());
        self::assertContains('VERIFIER_RCE_REPLAY_ERROR', $decision->reasonCodes());
    }

    public function testRceOracleAllowsPostWhenReplayPlanAllowsPostAndBodyTargetConfigured(): void
    {
        $runner = $this->runnerWithCallback(function (ReplayRequest $request): ReplayResult {
            $label = (string) ($request->payloadLabel() ?? '');
            $body = 'control';
            if (str_starts_with($label, 'positive_nonce')) {
                $body = $this->payloadExecutionOutput($request) ?? 'control';
            }

            return new ReplayResult($request, 200, $body, null, gmdate('c'), gmdate('c'));
        });

        $decision = (new RceOracle())->verify(new OracleContext(
            $this->job(
                '/rce',
                'POST',
                array(
                    'allowed_methods' => array('POST'),
                    'target_param_location' => 'body',
                    'target_body_param' => 'cmd',
                    'replay_body' => 'cmd=id&keep=1',
                )
            ),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-rce-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_RCE_NONCE_CONFIRMED', $decision->reasonCodes());
    }

    public function testRceOracleUsesPhpPayloadShapeForEvalReplayTargets(): void
    {
        $runner = $this->runnerWithCallback(function (ReplayRequest $request): ReplayResult {
            $label = (string) ($request->payloadLabel() ?? '');
            $body = 'control';
            if (str_starts_with($label, 'positive_nonce')) {
                $body = $this->payloadExecutionOutput($request) ?? 'control';
            }

            return new ReplayResult($request, 200, $body, null, gmdate('c'), gmdate('c'));
        });

        $decision = (new RceOracle())->verify(new OracleContext(
            $this->job('/rce_eval?cmd=echo%20%22safe%22%3B'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-rce-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_RCE_NONCE_CONFIRMED', $decision->reasonCodes());
    }

    public function testRceOracleUsesPhpPayloadShapeForEvalSinkQueryRoutes(): void
    {
        $runner = $this->runnerWithCallback(function (ReplayRequest $request): ReplayResult {
            $label = (string) ($request->payloadLabel() ?? '');
            $body = 'control';
            if (str_starts_with($label, 'positive_nonce')) {
                $body = $this->payloadExecutionOutput($request) ?? 'control';
            }

            return new ReplayResult($request, 200, $body, null, gmdate('c'), gmdate('c'));
        });

        $decision = (new RceOracle())->verify(new OracleContext(
            $this->job(
                '/?sink=eval&cmd=echo%20%22safe%22%3B',
                'GET',
                array(),
                array('sink_name' => 'include_or_eval')
            ),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-rce-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_RCE_NONCE_CONFIRMED', $decision->reasonCodes());
    }

    /**
     * @param array<string, mixed> $extraReplayPlan
     * @param array<string, mixed> $candidateSnapshot
     */
    private function job(
        string $requestUri,
        string $method = 'GET',
        array $extraReplayPlan = array(),
        array $candidateSnapshot = array()
    ): VerificationJob
    {
        $replayPlan = array_merge(array(
            'request_method' => $method,
            'request_uri' => $requestUri,
            'target_query_param' => 'cmd',
        ), $extraReplayPlan);

        return new VerificationJob(
            jobId: 'job-rce',
            candidateId: 'candidate-rce',
            sinkCategory: 'rce',
            oracleType: 'rce_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: $candidateSnapshot,
            replayPlan: $replayPlan
        );
    }

    private function runnerWithCallback(callable $callback): ReplayRunnerInterface
    {
        return new class($callback) implements ReplayRunnerInterface {
            /** @var callable(ReplayRequest): ReplayResult */
            private $callback;

            public function __construct(callable $callback)
            {
                $this->callback = $callback;
            }

            public function replay(ReplayRequest $request): ReplayResult
            {
                $callback = $this->callback;
                return $callback($request);
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };
    }

    private function payloadExecutionOutput(ReplayRequest $request): ?string
    {
        $param = $request->mutatedParameter() ?? 'cmd';
        $value = $request->mutatedParameterLocation() === 'body'
            ? (string) ($request->bodyParams()[$param] ?? '')
            : (string) ($request->queryParams()[$param] ?? '');

        $matches = array();
        if (preg_match('/^echo (ptt_rce_\\d+)$/', $value, $matches) === 1) {
            return $matches[1];
        }

        if (preg_match('/^printf (ptt_rce_\\d+)$/', $value, $matches) === 1) {
            return $matches[1];
        }

        if (preg_match('/^printf ptt_rce_;expr (\\d+) \\+ (\\d+)$/', $value, $matches) === 1) {
            return 'ptt_rce_' . (string) (((int) $matches[1]) + ((int) $matches[2]));
        }

        if (preg_match('/^printf ptt_rce_%s \\$\\(\\( (\\d+)\\+(\\d+) \\)\\)$/', $value, $matches) === 1) {
            return 'ptt_rce_' . (string) (((int) $matches[1]) + ((int) $matches[2]));
        }

        if (preg_match("/^echo 'ptt_rce_'\\.\\((\\d+)\\+(\\d+)\\);$/", $value, $matches) === 1) {
            return 'ptt_rce_' . (string) (((int) $matches[1]) + ((int) $matches[2]));
        }

        return null;
    }
}
