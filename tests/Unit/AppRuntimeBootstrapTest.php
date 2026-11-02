<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\AppRuntimeBootstrap;
use PhpTaintTrace\Runtime\AppRuntimeConfig;
use PhpTaintTrace\Runtime\BaselineRuntime;
use PHPUnit\Framework\TestCase;

final class AppRuntimeBootstrapTest extends TestCase
{
    public function testFlushFindingsWritesJsonLinesAndClearsStore(): void
    {
        $filePath = sys_get_temp_dir() . '/php-taint-trace-' . uniqid('', true) . '.jsonl';
        @unlink($filePath);

        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, true, 'full', true);
        $bootstrap = new AppRuntimeBootstrap(
            $runtime,
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: $filePath,
                emitErrorLog: false,
                clearFindingsAfterFlush: true
            )
        );

        $get = array('cmd' => 'id');
        $post = array();
        $cookie = array();
        $files = array();
        $request = array('cmd' => 'id');
        $server = array('HTTP_HOST' => 'example.test');
        $bootstrap->bootstrapRequest($get, $post, $cookie, $files, $request, $server);

        $backend->dispatchPreHook('sink.rce.system', array(
            TaintedValue::tainted('id', 'query.cmd'),
        ));
        self::assertCount(1, $runtime->findings());

        $count = $bootstrap->flushFindings();
        self::assertSame(1, $count);
        self::assertCount(0, $runtime->findings());
        self::assertFileExists($filePath);

        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($lines);
        self::assertCount(1, $lines);
        $payload = json_decode($lines[0], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('cli', $payload['sapi']);
        self::assertCount(1, $payload['findings']);
        self::assertSame('system', $payload['findings'][0]['sink_name']);
        self::assertArrayNotHasKey('candidates', $payload);
    }

    public function testFlushFindingsDoesNothingWhenStoreIsEmpty(): void
    {
        $filePath = sys_get_temp_dir() . '/php-taint-trace-' . uniqid('', true) . '.jsonl';
        @unlink($filePath);

        $bootstrap = new AppRuntimeBootstrap(
            new BaselineRuntime(new ArrayInstrumentationBackend()),
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: $filePath,
                emitErrorLog: false,
                clearFindingsAfterFlush: true
            )
        );

        self::assertSame(0, $bootstrap->flushFindings());
        self::assertFileDoesNotExist($filePath);
    }

    public function testFlushFindingsStillSkipsEmissionWhenOnlyCandidatesExist(): void
    {
        $filePath = sys_get_temp_dir() . '/php-taint-trace-' . uniqid('', true) . '.jsonl';
        @unlink($filePath);

        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, true, 'full', true);
        $bootstrap = new AppRuntimeBootstrap(
            $runtime,
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: $filePath,
                emitErrorLog: false,
                clearFindingsAfterFlush: true,
                emitCandidates: true
            )
        );

        $get = array();
        $post = array();
        $cookie = array();
        $files = array();
        $request = array();
        $server = array('HTTP_HOST' => 'example.test');
        $bootstrap->bootstrapRequest($get, $post, $cookie, $files, $request, $server);

        $backend->dispatchPreHook('sink.rce.system', array('safe-command'));
        self::assertCount(0, $runtime->findings());
        self::assertCount(1, $runtime->candidates());

        self::assertSame(0, $bootstrap->flushFindings());
        self::assertFileDoesNotExist($filePath);
    }

    public function testCreateFromEnvironmentUsesOpcodeToggle(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $bootstrap = AppRuntimeBootstrap::createFromEnvironment(
            $backend,
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: null,
                emitErrorLog: false,
                clearFindingsAfterFlush: true,
                enableOpcodeHooks: false,
                opcodeHookProfile: 'safe'
            )
        );

        $get = array('q' => 'xtanzi');
        $post = array();
        $cookie = array();
        $files = array();
        $request = array('q' => 'xtanzi');
        $server = array('HTTP_HOST' => 'example.test');
        $bootstrap->bootstrapRequest($get, $post, $cookie, $files, $request, $server);

        self::assertArrayNotHasKey('opcode.include_or_eval', $backend->hooks());
        self::assertArrayHasKey('sink.rce.system', $backend->hooks());
    }

    public function testCreateFromEnvironmentUsesSafeOpcodeProfileWhenEnabled(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $bootstrap = AppRuntimeBootstrap::createFromEnvironment(
            $backend,
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: null,
                emitErrorLog: false,
                clearFindingsAfterFlush: true,
                enableOpcodeHooks: true,
                opcodeHookProfile: 'safe'
            )
        );

        $get = array('q' => 'xtanzi');
        $post = array();
        $cookie = array();
        $files = array();
        $request = array('q' => 'xtanzi');
        $server = array('HTTP_HOST' => 'example.test');
        $bootstrap->bootstrapRequest($get, $post, $cookie, $files, $request, $server);

        self::assertArrayHasKey('opcode.include_or_eval', $backend->hooks());
        self::assertArrayHasKey('opcode.echo', $backend->hooks());
        self::assertArrayNotHasKey('opcode.do_fcall', $backend->hooks());
        self::assertArrayNotHasKey('opcode.concat', $backend->hooks());
    }

    public function testFlushFindingsCanEmitCandidatesWhenEnabled(): void
    {
        $filePath = sys_get_temp_dir() . '/php-taint-trace-' . uniqid('', true) . '.jsonl';
        @unlink($filePath);

        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, true, 'full', true);
        $bootstrap = new AppRuntimeBootstrap(
            $runtime,
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: $filePath,
                emitErrorLog: false,
                clearFindingsAfterFlush: true,
                emitCandidates: true
            )
        );

        $get = array('cmd' => 'id');
        $post = array();
        $cookie = array();
        $files = array();
        $request = array('cmd' => 'id');
        $server = array('HTTP_HOST' => 'example.test');
        $bootstrap->bootstrapRequest($get, $post, $cookie, $files, $request, $server);

        $backend->dispatchPreHook('sink.rce.system', array(
            TaintedValue::tainted('id', '_GET'),
        ));
        self::assertCount(1, $runtime->findings());
        self::assertCount(1, $runtime->candidates());

        $count = $bootstrap->flushFindings();
        self::assertSame(1, $count);
        self::assertCount(0, $runtime->findings());
        self::assertCount(0, $runtime->candidates());

        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($lines);
        self::assertCount(1, $lines);
        $payload = json_decode($lines[0], true, 512, JSON_THROW_ON_ERROR);

        self::assertArrayHasKey('findings', $payload);
        self::assertArrayHasKey('candidates', $payload);
        self::assertCount(1, $payload['findings']);
        self::assertCount(1, $payload['candidates']);
        self::assertSame('system', $payload['findings'][0]['sink_name']);
        self::assertSame('system', $payload['candidates'][0]['sink_name']);
    }

    public function testFlushFindingsEnqueuesVerifierJobsWhenEnabled(): void
    {
        $filePath = sys_get_temp_dir() . '/php-taint-trace-' . uniqid('', true) . '.jsonl';
        $verifierDir = sys_get_temp_dir() . '/php-taint-trace-verifier-' . uniqid('', true);
        @unlink($filePath);

        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, true, 'full', true);
        $bootstrap = new AppRuntimeBootstrap(
            $runtime,
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: $filePath,
                emitErrorLog: false,
                clearFindingsAfterFlush: true,
                emitCandidates: false,
                enableOpcodeHooks: false,
                opcodeHookProfile: 'safe',
                enableVerifier: true,
                verifierRuntimeDir: $verifierDir,
                verifierReplayTarget: 'local'
            )
        );

        $get = array('cmd' => 'id');
        $post = array();
        $cookie = array();
        $files = array();
        $request = array('cmd' => 'id');
        $server = array('HTTP_HOST' => 'example.test');
        $bootstrap->bootstrapRequest($get, $post, $cookie, $files, $request, $server);

        $backend->dispatchPreHook('sink.rce.system', array(
            TaintedValue::tainted('id', '_GET'),
        ));

        self::assertSame(1, $bootstrap->flushFindings());

        $jobsPath = $verifierDir . '/jobs.jsonl';
        self::assertFileExists($jobsPath);
        $rows = file($jobsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($rows);
        self::assertNotEmpty($rows);

        $job = json_decode($rows[0], true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('rce', $job['sink_category']);
        self::assertSame('rce_oracle', $job['oracle_type']);
        self::assertSame('local', $job['replay_profile']);
    }

    public function testFlushFindingsSkipsVerifierEnqueueForReplayRequests(): void
    {
        $this->assertReplayHeaderSkipsVerifierEnqueue('1');
    }

    public function testFlushFindingsSkipsVerifierEnqueueForReplayRequestsWithTruthyHeaderVariants(): void
    {
        $this->assertReplayHeaderSkipsVerifierEnqueue('true');
        $this->assertReplayHeaderSkipsVerifierEnqueue('yes');
    }

    public function testFlushFindingsCanWriteToSqliteReportingBackend(): void
    {
        if (!class_exists(\PDO::class) || !in_array('sqlite', \PDO::getAvailableDrivers(), true)) {
            self::markTestSkipped('PDO SQLite driver is not available.');
        }

        $jsonlPath = sys_get_temp_dir() . '/php-taint-trace-' . uniqid('', true) . '.jsonl';
        $sqlitePath = sys_get_temp_dir() . '/php-taint-trace-report-' . uniqid('', true) . '.sqlite3';
        @unlink($jsonlPath);
        @unlink($sqlitePath);

        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, true, 'full', true);
        $bootstrap = new AppRuntimeBootstrap(
            $runtime,
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: $jsonlPath,
                emitErrorLog: false,
                clearFindingsAfterFlush: true,
                emitCandidates: true,
                enableOpcodeHooks: false,
                opcodeHookProfile: 'safe',
                enableVerifier: false,
                verifierRuntimeDir: '.php_taint_trace_runtime/verifier',
                verifierReplayTarget: 'local',
                reportingBackend: 'sqlite',
                reportingDsn: $sqlitePath,
                reportingUsername: null,
                reportingPassword: null,
                reportingTable: 'request_reports'
            )
        );

        $get = array('cmd' => 'id');
        $post = array();
        $cookie = array();
        $files = array();
        $request = array('cmd' => 'id');
        $server = array('HTTP_HOST' => 'example.test');
        $bootstrap->bootstrapRequest($get, $post, $cookie, $files, $request, $server);

        $backend->dispatchPreHook('sink.rce.system', array(
            TaintedValue::tainted('id', '_GET'),
        ));

        self::assertSame(1, $bootstrap->flushFindings());
        self::assertFileDoesNotExist($jsonlPath);
        self::assertFileExists($sqlitePath);

        $pdo = new \PDO('sqlite:' . $sqlitePath);
        $rows = $pdo->query('SELECT findings_count, candidates_count, payload_json FROM request_reports')->fetchAll();
        self::assertCount(1, $rows);
        self::assertSame(1, (int) $rows[0]['findings_count']);
        self::assertSame(1, (int) $rows[0]['candidates_count']);

        $payload = json_decode((string) $rows[0]['payload_json'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);
        self::assertCount(1, $payload['findings']);
        self::assertCount(1, $payload['candidates']);
    }

    private function assertReplayHeaderSkipsVerifierEnqueue(string $headerValue): void
    {
        $filePath = sys_get_temp_dir() . '/php-taint-trace-' . uniqid('', true) . '.jsonl';
        $verifierDir = sys_get_temp_dir() . '/php-taint-trace-verifier-' . uniqid('', true);
        @unlink($filePath);

        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, true, 'full', true);
        $bootstrap = new AppRuntimeBootstrap(
            $runtime,
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: $filePath,
                emitErrorLog: false,
                clearFindingsAfterFlush: true,
                emitCandidates: false,
                enableOpcodeHooks: false,
                opcodeHookProfile: 'safe',
                enableVerifier: true,
                verifierRuntimeDir: $verifierDir,
                verifierReplayTarget: 'local'
            )
        );

        $get = array('cmd' => 'id');
        $post = array();
        $cookie = array();
        $files = array();
        $request = array('cmd' => 'id');
        $server = array('HTTP_HOST' => 'example.test');
        $bootstrap->bootstrapRequest($get, $post, $cookie, $files, $request, $server);

        $previousReplayHeader = $_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY'] ?? null;
        $_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY'] = $headerValue;
        try {
            $backend->dispatchPreHook('sink.rce.system', array(
                TaintedValue::tainted('id', '_GET'),
            ));

            self::assertSame(1, $bootstrap->flushFindings());
        } finally {
            if ($previousReplayHeader === null) {
                unset($_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY']);
            } else {
                $_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY'] = $previousReplayHeader;
            }
        }

        $jobsPath = $verifierDir . '/jobs.jsonl';
        if (!is_file($jobsPath)) {
            self::assertFileDoesNotExist($jobsPath);
            return;
        }

        $rows = file($jobsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($rows);
        self::assertCount(0, $rows);
    }
}
