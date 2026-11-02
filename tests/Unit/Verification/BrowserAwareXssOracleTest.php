<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Oracle\BrowserAwareXssOracle;
use PhpTaintTrace\Verification\Oracle\BrowserProbeRequest;
use PhpTaintTrace\Verification\Oracle\BrowserProbeResult;
use PhpTaintTrace\Verification\Oracle\BrowserProbeRunnerInterface;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Oracle\OracleDecision;
use PhpTaintTrace\Verification\Oracle\OracleInterface;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;
use PHPUnit\Framework\TestCase;

final class BrowserAwareXssOracleTest extends TestCase
{
    public function testBrowserAwareOracleFallsBackWhenProbeIsUnconfigured(): void
    {
        $oracle = new BrowserAwareXssOracle($this->fallbackOracle(VerificationOutcome::CONFIRMED));
        $decision = $oracle->verify($this->context($this->job('/xss?name=guest')));

        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XSS_BROWSER_PROBE_UNCONFIGURED', $decision->reasonCodes());
    }

    public function testBrowserAwareOracleAddsConfirmedReasonWhenProbeExecutes(): void
    {
        $runner = new class implements BrowserProbeRunnerInterface {
            public function probe(BrowserProbeRequest $request): BrowserProbeResult
            {
                return new BrowserProbeResult(
                    success: true,
                    executionObserved: true,
                    error: null,
                    exitCode: 0,
                    stdout: '{"executed":true}',
                    stderr: '',
                    metadata: array('url' => $request->url())
                );
            }
        };

        $oracle = new BrowserAwareXssOracle(
            $this->fallbackOracle(VerificationOutcome::CONFIRMED),
            browserProbeRunner: $runner,
            enforceBrowserExecution: false,
            probeTimeoutMs: 7000
        );

        $decision = $oracle->verify($this->context($this->job('/xss?name=guest')));
        self::assertSame(VerificationOutcome::CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XSS_BROWSER_EXECUTION_CONFIRMED', $decision->reasonCodes());
        self::assertNotEmpty($decision->artifacts());
    }

    public function testBrowserAwareOracleCanEnforceProbeExecution(): void
    {
        $runner = new class implements BrowserProbeRunnerInterface {
            public function probe(BrowserProbeRequest $request): BrowserProbeResult
            {
                return new BrowserProbeResult(
                    success: true,
                    executionObserved: false,
                    error: null,
                    exitCode: 0,
                    stdout: '{"executed":false}',
                    stderr: '',
                    metadata: array()
                );
            }
        };

        $oracle = new BrowserAwareXssOracle(
            $this->fallbackOracle(VerificationOutcome::CONFIRMED),
            browserProbeRunner: $runner,
            enforceBrowserExecution: true
        );

        $decision = $oracle->verify($this->context($this->job('/xss?name=guest')));
        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('VERIFIER_XSS_BROWSER_EXECUTION_NOT_OBSERVED', $decision->reasonCodes());
    }

    public function testBrowserAwareOracleSkipsProbeWhenFallbackNotConfirmed(): void
    {
        $probeRunner = new class implements BrowserProbeRunnerInterface {
            public int $calls = 0;

            public function probe(BrowserProbeRequest $request): BrowserProbeResult
            {
                $this->calls++;
                return new BrowserProbeResult(
                    success: true,
                    executionObserved: true,
                    error: null,
                    exitCode: 0,
                    stdout: '{"executed":true}',
                    stderr: ''
                );
            }
        };

        $oracle = new BrowserAwareXssOracle(
            $this->fallbackOracle(VerificationOutcome::NOT_CONFIRMED),
            browserProbeRunner: $probeRunner
        );
        $decision = $oracle->verify($this->context($this->job('/xss?name=guest')));

        self::assertSame(VerificationOutcome::NOT_CONFIRMED, $decision->outcome());
        self::assertContains('FALLBACK_NOT_CONFIRMED', $decision->reasonCodes());
        self::assertSame(0, $probeRunner->calls);
    }

    private function fallbackOracle(VerificationOutcome $outcome): OracleInterface
    {
        return new class ($outcome) implements OracleInterface {
            public function __construct(
                private readonly VerificationOutcome $outcome
            ) {
            }

            public function supports(VerificationJob $job): bool
            {
                return true;
            }

            public function verify(OracleContext $context): OracleDecision
            {
                return new OracleDecision(
                    outcome: $this->outcome,
                    reasonCodes: $this->outcome === VerificationOutcome::CONFIRMED
                        ? array('FALLBACK_CONFIRMED')
                        : array('FALLBACK_NOT_CONFIRMED'),
                    summary: 'fallback oracle result',
                    replayAttempts: array(),
                    artifacts: array(),
                    metadata: array('source' => 'fallback')
                );
            }
        };
    }

    private function context(VerificationJob $job): OracleContext
    {
        $replayRunner = new class implements ReplayRunnerInterface {
            public function replay(ReplayRequest $request): ReplayResult
            {
                return new ReplayResult($request, 200, 'ok', null, gmdate('c'), gmdate('c'));
            }

            public function callbackBaseUrl(): string
            {
                return 'http://127.0.0.1:18080';
            }
        };

        return new OracleContext(
            $job,
            $replayRunner,
            sys_get_temp_dir() . '/php-taint-trace-browser-aware-xss-' . uniqid('', true)
        );
    }

    private function job(string $requestUri, string $method = 'GET'): VerificationJob
    {
        return new VerificationJob(
            jobId: 'job-browser-aware-xss',
            candidateId: 'candidate-browser-aware-xss',
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
                'allowed_methods' => array($method),
            )
        );
    }
}

