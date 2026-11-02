<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

final class VerificationMetricsScriptTest extends ScriptTestCase
{
    protected function tempRootPrefix(): string
    {
        return 'php-taint-trace-metrics';
    }

    public function testMetricsScriptBuildsJsonSummary(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'rce',
            'scenario_kind' => 'vulnerable',
            'expected_confirmed' => true,
            'expected_outcome' => 'confirmed',
            'expected_decision_tier' => 'confirmed',
            'endpoint' => '/rce?cmd=id',
            'payload_plan' => array('target_query_param' => 'cmd'),
        )));
        file_put_contents($corpusDir . '/b.json', json_encode(array(
            'scenario_id' => 'scenario-b',
            'category' => 'xss',
            'scenario_kind' => 'safe',
            'expected_confirmed' => false,
            'expected_outcome' => 'not_confirmed',
            'expected_decision_tier' => 'invalid',
            'endpoint' => '/xss?name=test',
            'payload_plan' => array('target_query_param' => 'name'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', implode(PHP_EOL, array(
            json_encode(array('candidate_id' => 'scenario-a', 'outcome' => 'confirmed')),
            json_encode(array('candidate_id' => 'scenario-b', 'outcome' => 'not_confirmed')),
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', implode(PHP_EOL, array(
            json_encode(array('candidate_id' => 'scenario-a', 'decision_tier' => 'confirmed')),
            json_encode(array('candidate_id' => 'scenario-b', 'decision_tier' => 'invalid')),
        )) . PHP_EOL);

        $outputPath = $runtimeDir . '/metrics.json';
        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $outputPath,
        ));

        self::assertSame(0, $result['exit_code'], $result['stderr']);
        self::assertFileExists($outputPath);

        $payload = json_decode((string) file_get_contents($outputPath), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(2, $payload['scenario_count']);
        self::assertSame(1, $payload['counts']['tp']);
        self::assertSame(0, $payload['counts']['fp']);
        self::assertSame(0, $payload['counts']['fn']);
        self::assertSame(1, $payload['counts']['tn']);
        self::assertEquals(1.0, $payload['metrics']['precision']);
        self::assertEquals(1.0, $payload['metrics']['recall']);
        self::assertEquals(1.0, $payload['metrics']['f1']);
        self::assertSame(0, $payload['queue']['dead_letter_count']);
        self::assertEquals(0.0, $payload['queue']['dead_letter_rate']);
        self::assertSame(0, $payload['browser_xss_probe']['xss_confirmed_decisions']);
        self::assertEquals(0.0, $payload['browser_xss_probe']['execution_confirmed_rate']);
        self::assertEquals(0.0, $payload['browser_xss_probe']['failure_rate']);
        self::assertEquals(0.0, $payload['browser_xss_probe']['unconfigured_rate']);
    }

    public function testMetricsScriptFailsWhenUnexpectedConfirmedIsPresent(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'xss',
            'scenario_kind' => 'safe',
            'expected_confirmed' => false,
            'expected_outcome' => 'not_confirmed',
            'expected_decision_tier' => 'invalid',
            'endpoint' => '/xss?name=test',
            'payload_plan' => array('target_query_param' => 'name'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'outcome' => 'confirmed',
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'decision_tier' => 'confirmed',
        )) . PHP_EOL);

        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $runtimeDir . '/metrics.json',
            '--fail-on-unexpected-confirmed',
        ));

        self::assertNotSame(0, $result['exit_code']);
        self::assertStringContainsString('unexpected confirmed decisions detected', $result['stderr']);
    }

    public function testMetricsScriptFailsWhenFormulaVersionDrifts(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'rce',
            'scenario_kind' => 'vulnerable',
            'expected_confirmed' => true,
            'expected_outcome' => 'confirmed',
            'expected_decision_tier' => 'confirmed',
            'endpoint' => '/rce?cmd=id',
            'payload_plan' => array('target_query_param' => 'cmd'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'outcome' => 'confirmed',
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'decision_tier' => 'confirmed',
            'score_breakdown' => array(
                'formula_version' => 'phase_c_v0_legacy',
            ),
            'reason_codes' => array('VERIFIER_RCE_NONCE_CONFIRMED'),
        )) . PHP_EOL);

        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $runtimeDir . '/metrics.json',
            '--expected-formula-version', 'phase_c_v1_step27',
            '--fail-on-formula-version-drift',
        ));

        self::assertNotSame(0, $result['exit_code']);
        self::assertStringContainsString('formula version drift detected', $result['stderr']);
    }

    public function testMetricsScriptFailsWhenDriftAlertThresholdIsExceeded(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'rce',
            'scenario_kind' => 'vulnerable',
            'expected_confirmed' => true,
            'expected_outcome' => 'confirmed',
            'expected_decision_tier' => 'confirmed',
            'endpoint' => '/rce?cmd=id',
            'payload_plan' => array('target_query_param' => 'cmd'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'outcome' => 'confirmed',
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'decision_tier' => 'confirmed',
            'score_breakdown' => array(
                'formula_version' => 'phase_c_v1_step27',
            ),
            'reason_codes' => array('VERIFIER_RCE_NONCE_CONFIRMED'),
        )) . PHP_EOL);

        $baselinePath = $this->tmpRoot . '/baseline.json';
        file_put_contents($baselinePath, json_encode(array(
            'decision_tier_distribution' => array(
                'confirmed' => 0,
                'invalid' => 1,
            ),
            'replay' => array(
                'replay_failure_rate' => 0.0,
            ),
            'reason_code_distribution' => array(
                'DECISION_TIER_INVALID_NOT_CONFIRMED' => 1,
            ),
        )));

        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $runtimeDir . '/metrics.json',
            '--baseline', $baselinePath,
            '--fail-on-drift',
        ));

        self::assertNotSame(0, $result['exit_code']);
        self::assertStringContainsString('drift alerts detected', $result['stderr']);
    }

    public function testMetricsScriptFailsWhenBrowserExecutionRateDrifts(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'xss',
            'scenario_kind' => 'vulnerable',
            'expected_confirmed' => true,
            'expected_outcome' => 'confirmed',
            'expected_decision_tier' => 'confirmed',
            'endpoint' => '/xss?name=test',
            'payload_plan' => array('target_query_param' => 'name'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'outcome' => 'confirmed',
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'decision_tier' => 'confirmed',
            'metadata' => array(
                'sink_category' => 'xss',
            ),
            'score_breakdown' => array(
                'formula_version' => 'phase_c_v1_step27',
            ),
            'reason_codes' => array('VERIFIER_XSS_CONTEXT_CONFIRMED'),
        )) . PHP_EOL);

        $baselinePath = $this->tmpRoot . '/baseline_browser.json';
        file_put_contents($baselinePath, json_encode(array(
            'decision_tier_distribution' => array(
                'confirmed' => 1,
            ),
            'replay' => array(
                'replay_failure_rate' => 0.0,
            ),
            'reason_code_distribution' => array(
                'VERIFIER_XSS_BROWSER_EXECUTION_CONFIRMED' => 1,
            ),
            'browser_xss_probe' => array(
                'execution_confirmed_rate' => 1.0,
                'failure_rate' => 0.0,
                'unconfigured_rate' => 0.0,
            ),
        )));

        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $runtimeDir . '/metrics.json',
            '--baseline', $baselinePath,
            '--fail-on-drift',
            '--drift-xss-browser-exec-confirmed-rate-drop-threshold', '0.10',
        ));

        self::assertNotSame(0, $result['exit_code']);
        self::assertStringContainsString('xss_browser_exec_confirmed_rate_drop', $result['stderr']);
    }

    public function testMetricsScriptFailsWhenDeadLetterRateDrifts(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'rce',
            'scenario_kind' => 'vulnerable',
            'expected_confirmed' => true,
            'expected_outcome' => 'confirmed',
            'expected_decision_tier' => 'confirmed',
            'endpoint' => '/rce?cmd=id',
            'payload_plan' => array('target_query_param' => 'cmd'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'outcome' => 'confirmed',
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'decision_tier' => 'confirmed',
            'metadata' => array(
                'sink_category' => 'rce',
            ),
            'score_breakdown' => array(
                'formula_version' => 'phase_c_v1_step27',
            ),
            'reason_codes' => array('VERIFIER_RCE_NONCE_CONFIRMED'),
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/dead_letters.jsonl', json_encode(array(
            'job_id' => 'job-1',
            'reason_code' => 'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
        )) . PHP_EOL);

        $baselinePath = $this->tmpRoot . '/baseline_dead_letter.json';
        file_put_contents($baselinePath, json_encode(array(
            'decision_tier_distribution' => array(
                'confirmed' => 1,
            ),
            'replay' => array(
                'replay_failure_rate' => 0.0,
            ),
            'queue' => array(
                'dead_letter_rate' => 0.0,
            ),
            'reason_code_distribution' => array(
                'VERIFIER_RCE_NONCE_CONFIRMED' => 1,
            ),
        )));

        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $runtimeDir . '/metrics.json',
            '--baseline', $baselinePath,
            '--fail-on-drift',
            '--drift-dead-letter-rate-delta-threshold', '0.10',
        ));

        self::assertNotSame(0, $result['exit_code']);
        self::assertStringContainsString('dead_letter_rate_spike', $result['stderr']);
    }

    public function testMetricsScriptFailsWhenDeadLetterReasonBudgetIsExceeded(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'rce',
            'scenario_kind' => 'vulnerable',
            'expected_confirmed' => true,
            'expected_outcome' => 'confirmed',
            'expected_decision_tier' => 'confirmed',
            'endpoint' => '/rce?cmd=id',
            'payload_plan' => array('target_query_param' => 'cmd'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'outcome' => 'confirmed',
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'decision_tier' => 'confirmed',
            'metadata' => array(
                'sink_category' => 'rce',
            ),
            'score_breakdown' => array(
                'formula_version' => 'phase_c_v1_step27',
            ),
            'reason_codes' => array('VERIFIER_RCE_NONCE_CONFIRMED'),
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/dead_letters.jsonl', json_encode(array(
            'job_id' => 'job-1',
            'reason_code' => 'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
        )) . PHP_EOL);

        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $runtimeDir . '/metrics.json',
            '--dead-letter-reason-max-count', 'VERIFIER_EXCEPTION_=0',
        ));

        self::assertNotSame(0, $result['exit_code']);
        self::assertStringContainsString('dead-letter reason budget violations detected', $result['stderr']);
        self::assertStringContainsString('prefix=VERIFIER_EXCEPTION_', $result['stderr']);
    }

    public function testMetricsScriptFailsWhenDeadLetterReasonRateDriftThresholdIsExceeded(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'rce',
            'scenario_kind' => 'vulnerable',
            'expected_confirmed' => true,
            'expected_outcome' => 'confirmed',
            'expected_decision_tier' => 'confirmed',
            'endpoint' => '/rce?cmd=id',
            'payload_plan' => array('target_query_param' => 'cmd'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'outcome' => 'confirmed',
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'decision_tier' => 'confirmed',
            'metadata' => array(
                'sink_category' => 'rce',
            ),
            'score_breakdown' => array(
                'formula_version' => 'phase_c_v1_step27',
            ),
            'reason_codes' => array('VERIFIER_RCE_NONCE_CONFIRMED'),
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/dead_letters.jsonl', json_encode(array(
            'job_id' => 'job-1',
            'reason_code' => 'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
        )) . PHP_EOL);

        $baselinePath = $this->tmpRoot . '/baseline_dead_letter_reason_rate.json';
        file_put_contents($baselinePath, json_encode(array(
            'decision_tier_distribution' => array(
                'confirmed' => 1,
            ),
            'replay' => array(
                'total_results' => 1,
                'replay_failure_rate' => 0.0,
            ),
            'queue' => array(
                'dead_letter_rate' => 0.0,
                'dead_letter_reason_distribution' => array(),
            ),
            'reason_code_distribution' => array(
                'VERIFIER_RCE_NONCE_CONFIRMED' => 1,
            ),
        )));

        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $runtimeDir . '/metrics.json',
            '--baseline', $baselinePath,
            '--fail-on-drift',
            '--drift-dead-letter-reason-rate-threshold', 'VERIFIER_EXCEPTION_=0.10',
        ));

        self::assertNotSame(0, $result['exit_code']);
        self::assertStringContainsString('dead_letter_reason_rate_spike', $result['stderr']);
        self::assertStringContainsString('VERIFIER_EXCEPTION_', $result['stderr']);
    }

    public function testMetricsScriptReadsExtensionAssertionSummary(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'rce',
            'scenario_kind' => 'vulnerable',
            'expected_confirmed' => true,
            'expected_outcome' => 'confirmed',
            'expected_decision_tier' => 'confirmed',
            'endpoint' => '/rce?cmd=id',
            'payload_plan' => array('target_query_param' => 'cmd'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'outcome' => 'confirmed',
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'decision_tier' => 'confirmed',
            'score_breakdown' => array(
                'formula_version' => 'phase_c_v1_step27',
            ),
            'reason_codes' => array('VERIFIER_RCE_NONCE_CONFIRMED'),
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/extension_assertions_summary.json', json_encode(array(
            'profile' => 'extended_all',
            'strict' => true,
            'optional_assertions_total' => 8,
            'optional_assertions_executed' => 6,
            'optional_assertions_skipped' => 2,
            'skip_rate' => 0.25,
            'required_assertions_for_profile' => array('rce_pcntl_exec', 'sqli_pg_query_prepared'),
        )) . PHP_EOL);

        $outputPath = $runtimeDir . '/metrics.json';
        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $outputPath,
        ));

        self::assertSame(0, $result['exit_code'], $result['stderr']);

        $payload = json_decode((string) file_get_contents($outputPath), true, 512, JSON_THROW_ON_ERROR);
        self::assertTrue($payload['extension_assertions']['present']);
        self::assertSame('extended_all', $payload['extension_assertions']['profile']);
        self::assertTrue($payload['extension_assertions']['strict']);
        self::assertSame(8, $payload['extension_assertions']['optional_assertions_total']);
        self::assertSame(6, $payload['extension_assertions']['optional_assertions_executed']);
        self::assertSame(2, $payload['extension_assertions']['optional_assertions_skipped']);
        self::assertEquals(0.25, $payload['extension_assertions']['skip_rate']);
    }

    public function testMetricsScriptFailsWhenExtensionAssertionSkipRateDrifts(): void
    {
        $corpusDir = $this->tmpRoot . '/corpus';
        $runtimeDir = $this->tmpRoot . '/runtime';
        mkdir($corpusDir, 0775, true);
        mkdir($runtimeDir, 0775, true);

        file_put_contents($corpusDir . '/a.json', json_encode(array(
            'scenario_id' => 'scenario-a',
            'category' => 'rce',
            'scenario_kind' => 'vulnerable',
            'expected_confirmed' => true,
            'expected_outcome' => 'confirmed',
            'expected_decision_tier' => 'confirmed',
            'endpoint' => '/rce?cmd=id',
            'payload_plan' => array('target_query_param' => 'cmd'),
        )));

        file_put_contents($runtimeDir . '/results.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'outcome' => 'confirmed',
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/decisions.jsonl', json_encode(array(
            'candidate_id' => 'scenario-a',
            'decision_tier' => 'confirmed',
            'score_breakdown' => array(
                'formula_version' => 'phase_c_v1_step27',
            ),
            'reason_codes' => array('VERIFIER_RCE_NONCE_CONFIRMED'),
        )) . PHP_EOL);
        file_put_contents($runtimeDir . '/extension_assertions_summary.json', json_encode(array(
            'profile' => 'extended_all',
            'strict' => true,
            'optional_assertions_total' => 10,
            'optional_assertions_executed' => 5,
            'optional_assertions_skipped' => 5,
            'skip_rate' => 0.5,
        )) . PHP_EOL);

        $baselinePath = $this->tmpRoot . '/baseline_extension_assertions.json';
        file_put_contents($baselinePath, json_encode(array(
            'decision_tier_distribution' => array(
                'confirmed' => 1,
            ),
            'replay' => array(
                'replay_failure_rate' => 0.0,
            ),
            'reason_code_distribution' => array(
                'VERIFIER_RCE_NONCE_CONFIRMED' => 1,
            ),
            'extension_assertions' => array(
                'skip_rate' => 0.0,
            ),
        )));

        $result = $this->runScript(array(
            'bash',
            'scripts/report_verification_metrics.sh',
            '--runtime-dir', $runtimeDir,
            '--corpus-dir', $corpusDir,
            '--output', $runtimeDir . '/metrics.json',
            '--baseline', $baselinePath,
            '--fail-on-drift',
            '--drift-extension-assertion-skip-rate-delta-threshold', '0.10',
        ));

        self::assertNotSame(0, $result['exit_code']);
        self::assertStringContainsString('extension_assertion_skip_rate_spike', $result['stderr']);
    }

}
