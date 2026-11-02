<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

final class RequeueDeadLettersScriptTest extends ScriptTestCase
{
    protected function tempRootPrefix(): string
    {
        return 'php-taint-trace-requeue-dead-letters';
    }

    public function testSummaryOnlyReportsDeadLetterState(): void
    {
        $runtimeDir = $this->seedRuntime('summary');

        $result = $this->runScript(array(
            'php',
            'scripts/requeue_verifier_dead_letters.php',
            '--runtime-dir', $runtimeDir,
            '--summary-only',
        ));

        self::assertSame(0, $result['exit_code'], $result['stderr']);
        $payload = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('summary_only', $payload['mode']);
        self::assertSame(1, $payload['dead_letter_total']);
        self::assertSame(1, $payload['selected_rows']);
        self::assertSame(0, $payload['enqueued_rows']);
    }

    public function testDryRunDoesNotWriteJobs(): void
    {
        $runtimeDir = $this->seedRuntime('dry-run');
        $jobsPath = $runtimeDir . '/jobs.jsonl';
        $initialLines = file($jobsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($initialLines);
        self::assertCount(1, $initialLines);

        $result = $this->runScript(array(
            'php',
            'scripts/requeue_verifier_dead_letters.php',
            '--runtime-dir', $runtimeDir,
            '--reason-code', 'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
            '--requeue-tag', 'unit_dry_run',
            '--dry-run',
        ));

        self::assertSame(0, $result['exit_code'], $result['stderr']);
        $payload = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('dry_run', $payload['mode']);
        self::assertSame(1, $payload['processed_rows']);
        self::assertSame(1, $payload['enqueued_rows']);

        $finalLines = file($jobsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($finalLines);
        self::assertCount(1, $finalLines, 'dry-run must not append jobs');
    }

    public function testRequeueAppendsJobAndSkipsDuplicateOnSecondRun(): void
    {
        $runtimeDir = $this->seedRuntime('requeue');
        $jobsPath = $runtimeDir . '/jobs.jsonl';
        $requeuesPath = $runtimeDir . '/requeues.jsonl';

        $first = $this->runScript(array(
            'php',
            'scripts/requeue_verifier_dead_letters.php',
            '--runtime-dir', $runtimeDir,
            '--reason-code', 'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
            '--requeue-tag', 'unit_retry_001',
        ));
        self::assertSame(0, $first['exit_code'], $first['stderr']);
        $firstPayload = json_decode($first['stdout'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(1, $firstPayload['processed_rows']);
        self::assertSame(1, $firstPayload['enqueued_rows']);
        self::assertSame(0, $firstPayload['duplicate_skipped_rows']);

        $jobLines = file($jobsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($jobLines);
        self::assertCount(2, $jobLines);
        $newJob = json_decode($jobLines[1], true, 512, JSON_THROW_ON_ERROR);
        self::assertStringContainsString('|requeue:unit_retry_001:job-rce-1', (string) $newJob['replay_profile']);
        self::assertSame('job-rce-1', $newJob['metadata']['requeue_source_job_id']);
        self::assertSame('VERIFIER_EXCEPTION_RETRY_EXHAUSTED', $newJob['metadata']['requeue_source_reason_code']);

        $requeueRows = file($requeuesPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($requeueRows);
        self::assertCount(1, $requeueRows);

        $second = $this->runScript(array(
            'php',
            'scripts/requeue_verifier_dead_letters.php',
            '--runtime-dir', $runtimeDir,
            '--reason-code', 'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
            '--requeue-tag', 'unit_retry_001',
        ));
        self::assertSame(0, $second['exit_code'], $second['stderr']);
        $secondPayload = json_decode($second['stdout'], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(0, $secondPayload['enqueued_rows']);
        self::assertSame(1, $secondPayload['duplicate_skipped_rows']);

        $jobLinesAfterSecond = file($jobsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($jobLinesAfterSecond);
        self::assertCount(2, $jobLinesAfterSecond, 'duplicate requeue must not append duplicate-skipped rows');
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
