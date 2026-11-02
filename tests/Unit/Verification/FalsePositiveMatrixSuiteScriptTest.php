<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

final class FalsePositiveMatrixSuiteScriptTest extends ScriptTestCase
{
    protected function tempRootPrefix(): string
    {
        return 'php-taint-trace-fp-matrix';
    }

    public function testFalsePositiveMatrixSuitePassesWithZeroFalsePositivesAndNegatives(): void
    {
        $runtimeDir = $this->tmpRoot . '/runtime';
        $corpusDir = $this->tmpRoot . '/corpus';
        $metricsPath = $runtimeDir . '/metrics.json';
        mkdir($runtimeDir, 0775, true);

        $basePort = $this->allocateEphemeralPort();
        $callbackPort = $this->allocateEphemeralPort();
        if ($callbackPort === $basePort) {
            $callbackPort = $this->allocateEphemeralPort();
        }

        $result = $this->runScript(array(
            'bash',
            'scripts/run_false_positive_matrix_tests.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--metrics-output', $metricsPath,
            '--base-port', (string) $basePort,
            '--callback-port', (string) $callbackPort,
        ));

        self::assertSame(0, $result['exit_code'], $result['stderr']);
        self::assertStringContainsString('[fp-matrix] validation passed', $result['stdout']);
        self::assertFileExists($metricsPath);

        $corpusFiles = glob($corpusDir . '/*.json');
        self::assertIsArray($corpusFiles);
        self::assertGreaterThanOrEqual(60, count($corpusFiles));

        $metrics = json_decode((string) file_get_contents($metricsPath), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(count($corpusFiles), (int) ($metrics['scenario_count'] ?? -1));
        self::assertSame(0, (int) ($metrics['counts']['fp'] ?? -1));
        self::assertSame(0, (int) ($metrics['counts']['fn'] ?? -1));
        self::assertSame(array(), $metrics['reason_code_mismatches']);
    }
}
