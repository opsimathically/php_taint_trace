<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Oracle\XxeOracle;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;
use PHPUnit\Framework\TestCase;

final class XxeOracleTest extends TestCase
{
    public function testXxeOracleConfirmsEntityResolutionDifferential(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $xml = (string) ($request->queryParams()[$request->mutatedParameter() ?? 'xml'] ?? '');
                $body = 'control';
                if (str_starts_with((string) ($request->payloadLabel() ?? ''), 'positive_entity')) {
                    $url = $this->entityUrl($xml);
                    if (is_string($url)) {
                        parse_str((string) parse_url($url, PHP_URL_QUERY), $parsed);
                        if (isset($parsed['name'])) {
                            $body = 'Hello ' . $parsed['name'];
                        }
                    }
                }

                return new ReplayResult($request, 200, $body, null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }

            private function entityUrl(string $xml): ?string
            {
                if (preg_match('/<!ENTITY\s+[a-zA-Z0-9_:-]+\s+SYSTEM\s+["\']([^"\']+)["\']\s*>/i', $xml, $matches) !== 1) {
                    return null;
                }

                return trim((string) ($matches[1] ?? ''));
            }
        };

        $decision = (new XxeOracle())->verify(new OracleContext(
            $this->job('/xxe?xml=%3Croot%3Extanzi%3C%2Froot%3E'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xxe-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XXE_ENTITY_RESOLUTION_CONFIRMED', $decision->reasonCodes());
    }

    public function testXxeOracleReturnsInconclusiveWhenNoReplayParamExists(): void
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

        $decision = (new XxeOracle())->verify(new OracleContext(
            $this->job('/xxe'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xxe-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::INCONCLUSIVE, $decision->outcome());
        self::assertContains('VERIFIER_XXE_TARGET_PARAM_MISSING', $decision->reasonCodes());
    }

    public function testXxeOracleReturnsNotConfirmedWhenNonceAppearsInControlResponse(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            private string $nonce = '';

            public function replay(ReplayRequest $request): ReplayResult
            {
                $xml = (string) ($request->queryParams()[$request->mutatedParameter() ?? 'xml'] ?? '');
                if (($request->payloadLabel() ?? '') === 'positive_entity') {
                    $url = $this->entityUrl($xml);
                    if (is_string($url)) {
                        parse_str((string) parse_url($url, PHP_URL_QUERY), $parsed);
                        $this->nonce = (string) ($parsed['name'] ?? '');
                    }

                    return new ReplayResult($request, 200, 'Hello ' . $this->nonce, null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'Hello ' . $this->nonce, null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }

            private function entityUrl(string $xml): ?string
            {
                if (preg_match('/<!ENTITY\s+[a-zA-Z0-9_:-]+\s+SYSTEM\s+["\']([^"\']+)["\']\s*>/i', $xml, $matches) !== 1) {
                    return null;
                }

                return trim((string) ($matches[1] ?? ''));
            }
        };

        $decision = (new XxeOracle())->verify(new OracleContext(
            $this->job('/xxe?xml=%3Croot%3Extanzi%3C%2Froot%3E'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xxe-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XXE_AMBIGUOUS_CONTROL_SIGNAL', $decision->reasonCodes());
    }

    public function testXxeOracleRejectsWeakDifferentialWhenNonceIsNeverObserved(): void
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

        $decision = (new XxeOracle())->verify(new OracleContext(
            $this->job('/xxe?xml=%3Croot%3Extanzi%3C%2Froot%3E'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xxe-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XXE_WEAK_DIFFERENTIAL', $decision->reasonCodes());
    }

    public function testXxeOracleRejectsUnstableDifferentialAcrossRepeatedAttempts(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                $xml = (string) ($request->queryParams()[$request->mutatedParameter() ?? 'xml'] ?? '');
                $label = (string) ($request->payloadLabel() ?? '');
                if (str_starts_with($label, 'positive_entity')) {
                    $url = $this->entityUrl($xml);
                    parse_str((string) parse_url((string) $url, PHP_URL_QUERY), $parsed);
                    $nonce = (string) ($parsed['name'] ?? '');
                    if ($label === 'positive_entity') {
                        return new ReplayResult($request, 200, 'Hello ' . $nonce, null, gmdate('c'), gmdate('c'));
                    }

                    return new ReplayResult($request, 200, 'control', null, gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'control', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }

            private function entityUrl(string $xml): ?string
            {
                if (preg_match('/<!ENTITY\s+[a-zA-Z0-9_:-]+\s+SYSTEM\s+["\']([^"\']+)["\']\s*>/i', $xml, $matches) !== 1) {
                    return null;
                }

                return trim((string) ($matches[1] ?? ''));
            }
        };

        $decision = (new XxeOracle())->verify(new OracleContext(
            $this->job('/xxe?xml=%3Croot%3Extanzi%3C%2Froot%3E'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xxe-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XXE_RESPONSE_INSTABILITY', $decision->reasonCodes());
    }

    public function testXxeOracleReturnsReplayFailedOnTransportError(): void
    {
        $runner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                if (($request->payloadLabel() ?? '') === 'positive_entity') {
                    return new ReplayResult($request, null, '', 'timeout', gmdate('c'), gmdate('c'));
                }

                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:8080';
            }
        };

        $decision = (new XxeOracle())->verify(new OracleContext(
            $this->job('/xxe?xml=%3Croot%3Extanzi%3C%2Froot%3E'),
            $runner,
            sys_get_temp_dir() . '/php-taint-oracle-xxe-' . uniqid('', true)
        ));

        self::assertSame(VerificationOutcome::REPLAY_FAILED, $decision->outcome());
        self::assertContains('VERIFIER_XXE_REPLAY_ERROR', $decision->reasonCodes());
    }

    private function job(string $requestUri): VerificationJob
    {
        return new VerificationJob(
            jobId: 'job-xxe',
            candidateId: 'candidate-xxe',
            sinkCategory: 'xxe',
            oracleType: 'xxe_oracle',
            replayProfile: 'local',
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: array(),
            replayPlan: array(
                'request_method' => 'GET',
                'request_uri' => $requestUri,
                'target_query_param' => 'xml',
            )
        );
    }
}

