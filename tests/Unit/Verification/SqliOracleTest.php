<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Oracle\SqliOracle;
use PhpTaintTrace\Verification\Oracle\SqliReplayTelemetryStore;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;
use PHPUnit\Framework\TestCase;

final class SqliOracleTest extends TestCase
{
    public function testSqliOracleConfirmsUnionNonceDifferential(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $query = $request->queryParams()[$request->mutatedParameter() ?? 'q'] ?? '';
                $body = 'alice';
                if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
                    $body = $matches[1];
                }

                return new ReplayResult($request, 200, $body, null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SqliOracle())->verify(new OracleContext(
            $this->job('/sqli?q=1'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-sqli-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SQLI_UNION_CONFIRMED', $decision->reasonCodes());
    }

    public function testSqliOracleReturnsNotConfirmedWhenNoDifferential(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'alice', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SqliOracle())->verify(new OracleContext(
            $this->job('/sqli?q=1'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-sqli-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SQLI_WEAK_DIFFERENTIAL', $decision->reasonCodes());
    }

    public function testSqliOracleConfirmsDirectQueryDifferentialWhenUnionPatternIsUnavailable(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $query = $request->queryParams()[$request->mutatedParameter() ?? 'q'] ?? '';
                $body = 'no rows';
                if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $query, $matches) === 1) {
                    $body = $matches[1];
                }

                return new ReplayResult($request, 200, $body, null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SqliOracle())->verify(new OracleContext(
            $this->job('/sqli?q=SELECT%20username%20FROM%20users%20WHERE%20id%20%3D%201'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-sqli-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SQLI_DIRECT_QUERY_CONFIRMED', $decision->reasonCodes());
    }

    public function testSqliOracleReturnsBlockedByPolicyForNonGetRequests(): void
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

        $decision = (new SqliOracle())->verify(new OracleContext(
            $this->job('/sqli?q=1', 'POST'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-sqli-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::BLOCKED_BY_POLICY, $decision->outcome());
        self::assertContains('VERIFIER_PHASE_D_GET_ONLY_POLICY', $decision->reasonCodes());
    }

    public function testSqliOracleReturnsReplayFailedOnTransportError(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                if (($request->payloadLabel() ?? '') === 'positive_union') {
                    return new ReplayResult($request, null, '', 'network timeout', gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'alice', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SqliOracle())->verify(new OracleContext(
            $this->job('/sqli?q=1'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-sqli-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::REPLAY_FAILED, $decision->outcome());
        self::assertContains('VERIFIER_SQLI_REPLAY_ERROR', $decision->reasonCodes());
    }

    public function testSqliOracleRejectsUnstableDifferentialAcrossRepeatedAttempts(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $query = (string) ($request->queryParams()[$request->mutatedParameter() ?? 'q'] ?? '');
                $label = (string) ($request->payloadLabel() ?? '');
                if (str_starts_with($label, 'positive_union') && preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
                    if ($label === 'positive_union') {
                        return new ReplayResult($request, 200, $matches[1], null, gmdate('c'), gmdate('c'));
                    }

                    return new ReplayResult($request, 200, 'alice', null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'alice', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SqliOracle())->verify(new OracleContext(
            $this->job('/sqli?q=1'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-sqli-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SQLI_RESPONSE_INSTABILITY', $decision->reasonCodes());
    }

    public function testSqliOracleAllowsPostWhenReplayPlanAllowsPostAndBodyTargetConfigured(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $param = $request->mutatedParameter() ?? 'q';
                $query = $request->mutatedParameterLocation() === 'body'
                    ? ($request->bodyParams()[$param] ?? '')
                    : ($request->queryParams()[$param] ?? '');

                $body = 'alice';
                if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
                    $body = $matches[1];
                }

                return new ReplayResult($request, 200, $body, null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SqliOracle())->verify(new OracleContext(
            $this->job(
                '/sqli',
                'POST',
                array(
                    'allowed_methods' => array('POST'),
                    'target_param_location' => 'body',
                    'target_body_param' => 'q',
                    'replay_body' => 'q=1&keep=1',
                )
            ),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-sqli-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SQLI_UNION_CONFIRMED', $decision->reasonCodes());
    }

    public function testSqliOracleRejectsReflectionOnlyNonceDifferentialWhenSqlTelemetryHasNoNonce(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $query = $request->queryParams()[$request->mutatedParameter() ?? 'q'] ?? '';
                $body = 'alice';
                if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
                    $body = $matches[1];
                }

                $replayId = 'ptt_test_reflection_' . bin2hex(random_bytes(4));
                SqliReplayTelemetryStore::append($replayId, array(
                    'sql' => array(
                        'query' => 'SELECT username FROM users WHERE id = 1',
                    ),
                ));

                return new ReplayResult(
                    $request,
                    200,
                    $body,
                    null,
                    gmdate('c'),
                    gmdate('c'),
                    array('replay_id' => $replayId)
                );
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SqliOracle())->verify(new OracleContext(
            $this->job('/sqli?q=1'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-sqli-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SQLI_REFLECTION_ONLY_SIGNAL', $decision->reasonCodes());
    }

    public function testSqliOracleConfirmsWhenSqlTelemetryCarriesStableNonceDifferential(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $query = $request->queryParams()[$request->mutatedParameter() ?? 'q'] ?? '';
                $replayId = 'ptt_test_sql_' . bin2hex(random_bytes(4));

                $capturedQuery = 'SELECT username FROM users WHERE id = 1';
                if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
                    $capturedQuery = "SELECT username FROM users WHERE id = 1 UNION SELECT '" . $matches[1] . "'";
                }

                SqliReplayTelemetryStore::append($replayId, array(
                    'sql' => array(
                        'query' => $capturedQuery,
                    ),
                ));

                return new ReplayResult(
                    $request,
                    200,
                    'ok',
                    null,
                    gmdate('c'),
                    gmdate('c'),
                    array('replay_id' => $replayId)
                );
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new SqliOracle())->verify(new OracleContext(
            $this->job('/sqli?q=1'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-sqli-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_SQLI_UNION_CONFIRMED', $decision->reasonCodes());
    }

    /**
     * @param array<string, mixed> $extraReplayPlan
     */
    private function job(string $requestUri, string $method = 'GET', array $extraReplayPlan = array()): VerificationJob
    {
        $replayPlan = array_merge(array(
            'request_method' => $method,
            'request_uri' => $requestUri,
            'target_query_param' => 'q',
        ), $extraReplayPlan);

        return new VerificationJob(
            jobId: 'job-sqli',
            candidateId: 'candidate-sqli',
            sinkCategory: 'sqli',
            oracleType: 'sqli_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: array(),
            replayPlan: $replayPlan
        );
    }
}
