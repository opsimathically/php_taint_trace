<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

final class DeadLetterRecoveryCycleScriptTest extends ScriptTestCase
{
    protected function tempRootPrefix(): string
    {
        return 'php-taint-trace-dead-letter-recovery';
    }

    public function testSummaryOnlyPrintsPrecheckSummaryAndExits(): void
    {
        $runtimeDir = $this->seedRuntime('summary');
        $result = $this->runScript(array(
            'bash',
            'scripts/run_dead_letter_recovery_cycle.sh',
            '--runtime-dir', $runtimeDir,
            '--summary-only',
            '--reason-code', 'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
        ));

        self::assertSame(0, $result['exit_code'], $result['stderr']);
        self::assertStringContainsString('[dead-letter-recovery] pre-check summary', $result['stdout']);
        self::assertStringContainsString('"mode": "summary_only"', $result['stdout']);
    }

    public function testDryRunDoesNotMutateJobsFile(): void
    {
        $runtimeDir = $this->seedRuntime('dry-run');
        $jobsPath = $runtimeDir . '/jobs.jsonl';
        $before = file($jobsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($before);
        self::assertCount(1, $before);

        $result = $this->runScript(array(
            'bash',
            'scripts/run_dead_letter_recovery_cycle.sh',
            '--runtime-dir', $runtimeDir,
            '--reason-code', 'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
            '--dry-run',
            '--worker-max-runs', '1',
        ));

        self::assertSame(0, $result['exit_code'], $result['stderr']);
        self::assertStringContainsString('"mode": "dry_run"', $result['stdout']);
        self::assertStringContainsString('[dead-letter-recovery] dry-run complete; no jobs enqueued.', $result['stdout']);

        $after = file($jobsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($after);
        self::assertCount(1, $after);
    }

    private function seedRuntime(string $suffix): string
    {
        $runtimeDir = $this->tmpRoot . '/' . $suffix;
        mkdir($runtimeDir, 0775, true);

        $jobRow = array(
            'job_id' => 'job-rce-1',
            'candidate_id' => 'scenario-rce-vulnerable',
            'sink_category' => 'rce',
            'oracle_type' => 'rce_oracle',
            'replay_profile' => 'remote_lab',
            'created_at' => gmdate('c'),
            'attempt_count' => 2,
            'status' => 'failed',
            'dedup_key' => hash('sha256', implode('|', array(
                'scenario-rce-vulnerable',
                'rce_oracle',
                'remote_lab',
            ))),
            'candidate_snapshot' => array('id' => 'scenario-rce-vulnerable'),
            'replay_plan' => array(
                'request_method' => 'GET',
                'request_uri' => '/?cmd=id',
                'request_params' => array('cmd' => 'id'),
            ),
            'metadata' => array(),
        );

        file_put_contents($runtimeDir . '/jobs.jsonl', json_encode($jobRow, JSON_UNESCAPED_SLASHES) . PHP_EOL);
        file_put_contents($runtimeDir . '/results.jsonl', '');
        file_put_contents($runtimeDir . '/claims.jsonl', '');
        file_put_contents($runtimeDir . '/queue.lock', '');
        mkdir($runtimeDir . '/artifacts', 0775, true);

        $deadLetterRow = array(
            'job_id' => 'job-rce-1',
            'candidate_id' => 'scenario-rce-vulnerable',
            'sink_category' => 'rce',
            'oracle_type' => 'rce_oracle',
            'attempt_count' => 2,
            'reason_code' => 'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
            'failed_at' => gmdate('c'),
            'metadata' => array('failure_stage' => 'oracle_verify'),
            'job' => $jobRow,
        );
        file_put_contents($runtimeDir . '/dead_letters.jsonl', json_encode($deadLetterRow, JSON_UNESCAPED_SLASHES) . PHP_EOL);

        return $runtimeDir;
    }
}
