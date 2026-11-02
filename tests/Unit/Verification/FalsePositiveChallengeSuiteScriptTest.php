<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

final class FalsePositiveChallengeSuiteScriptTest extends ScriptTestCase
{
    protected function tempRootPrefix(): string
    {
        return 'php-taint-trace-fp-challenge';
    }

    public function testFalsePositiveChallengeSuitePassesForBaselineOracles(): void
    {
        $runtimeDir = $this->tmpRoot . '/runtime';
        $metricsPath = $runtimeDir . '/metrics.json';
        mkdir($runtimeDir, 0775, true);

        $basePort = $this->allocateEphemeralPort();
        $callbackPort = $this->allocateEphemeralPort();
        if ($callbackPort === $basePort) {
            $callbackPort = $this->allocateEphemeralPort();
        }

        $result = $this->runScript(array(
            'bash',
            'scripts/run_false_positive_challenge_tests.sh',
            '--runtime-dir', $runtimeDir,
            '--metrics-output', $metricsPath,
            '--base-port', (string) $basePort,
            '--callback-port', (string) $callbackPort,
        ));

        self::assertSame(0, $result['exit_code'], $result['stderr']);
        self::assertStringContainsString('[fp-challenge] validation passed', $result['stdout']);
        self::assertFileExists($metricsPath);

        $metrics = json_decode((string) file_get_contents($metricsPath), true, 512, JSON_THROW_ON_ERROR);
        $expectedScenarioCount = $this->challengeScenarioCount();
        self::assertSame($expectedScenarioCount, (int) ($metrics['scenario_count'] ?? -1));
        self::assertGreaterThanOrEqual(24, $expectedScenarioCount);
        self::assertSame(0, (int) ($metrics['counts']['fp'] ?? -1));
        self::assertSame(0, (int) ($metrics['counts']['fn'] ?? -1));
        self::assertSame(array(), $metrics['reason_code_mismatches']);
    }

    private function challengeScenarioCount(): int
    {
        $root = dirname(__DIR__, 3);
        $files = glob($root . '/tests/fixtures/verification_corpus_false_positive_challenges/*.json');
        if (!is_array($files)) {
            return 0;
        }

        return count($files);
    }
}
