<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Runtime\AppRuntimeConfig;
use PHPUnit\Framework\TestCase;

final class AppRuntimeConfigTest extends TestCase
{
    public function testFromEnvironmentParsesBooleansAndPath(): void
    {
        $config = AppRuntimeConfig::fromEnvironment(array(
            'PHP_TAINT_TRACE_ENABLED' => 'off',
            'PHP_TAINT_TRACE_FINDINGS_FILE' => ' /tmp/php-taint/findings.jsonl ',
            'PHP_TAINT_TRACE_ERROR_LOG' => '0',
            'PHP_TAINT_TRACE_CLEAR_AFTER_FLUSH' => 'no',
            'PHP_TAINT_TRACE_EMIT_CANDIDATES' => 'yes',
            'PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS' => 'true',
            'PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE' => 'full',
            'PHP_TAINT_TRACE_ENABLE_VERIFIER' => 'on',
            'PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR' => '/tmp/php-taint-trace/verifier',
            'PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET' => 'remote_lab',
            'PHP_TAINT_TRACE_REPORTING_BACKEND' => 'sqlite',
            'PHP_TAINT_TRACE_REPORTING_DSN' => '/tmp/php-taint/reporting.sqlite3',
            'PHP_TAINT_TRACE_REPORTING_USERNAME' => 'report_user',
            'PHP_TAINT_TRACE_REPORTING_PASSWORD' => 'report_password',
            'PHP_TAINT_TRACE_REPORTING_TABLE' => 'request_reports',
            'PHP_TAINT_TRACE_CONFIG_FILE' => '/tmp/php-taint/runtime.json',
        ));

        self::assertFalse($config->enabled());
        self::assertSame('/tmp/php-taint/findings.jsonl', $config->findingsFilePath());
        self::assertFalse($config->emitErrorLog());
        self::assertFalse($config->clearFindingsAfterFlush());
        self::assertTrue($config->emitCandidates());
        self::assertTrue($config->enableOpcodeHooks());
        self::assertSame('full', $config->opcodeHookProfile());
        self::assertTrue($config->enableVerifier());
        self::assertSame('/tmp/php-taint-trace/verifier', $config->verifierRuntimeDir());
        self::assertSame('remote_lab', $config->verifierReplayTarget());
        self::assertSame('sqlite', $config->reportingBackend());
        self::assertSame('sqlite:/tmp/php-taint/reporting.sqlite3', $config->reportingDsn());
        self::assertSame('report_user', $config->reportingUsername());
        self::assertSame('report_password', $config->reportingPassword());
        self::assertSame('request_reports', $config->reportingTable());
        self::assertSame('/tmp/php-taint/runtime.json', $config->configFilePath());
    }

    public function testFromEnvironmentUsesDefaults(): void
    {
        $config = AppRuntimeConfig::fromEnvironment(array());

        self::assertTrue($config->enabled());
        self::assertNull($config->findingsFilePath());
        self::assertTrue($config->emitErrorLog());
        self::assertTrue($config->clearFindingsAfterFlush());
        self::assertFalse($config->emitCandidates());
        self::assertFalse($config->enableOpcodeHooks());
        self::assertSame('safe', $config->opcodeHookProfile());
        self::assertFalse($config->enableVerifier());
        self::assertSame('.php_taint_trace_runtime/verifier', $config->verifierRuntimeDir());
        self::assertSame('local', $config->verifierReplayTarget());
        self::assertSame('jsonl', $config->reportingBackend());
        self::assertNull($config->reportingDsn());
        self::assertNull($config->reportingUsername());
        self::assertNull($config->reportingPassword());
        self::assertSame('php_taint_trace_request_reports', $config->reportingTable());
        self::assertSame('/etc/php_taint_trace/runtime.json', $config->configFilePath());
    }

    public function testFromEnvironmentLoadsRuntimeConfigFileAndAllowsEnvOverride(): void
    {
        $configFilePath = sys_get_temp_dir() . '/php-taint-trace-config-' . uniqid('', true) . '.json';
        $json = json_encode(array(
            'runtime' => array(
                'enabled' => false,
                'findings_file' => '/tmp/from-file-findings.jsonl',
                'reporting_backend' => 'sqlite',
                'reporting_dsn' => '/tmp/from-file-reporting.sqlite3',
                'reporting_table' => 'file_reports',
                'verifier_runtime_dir' => '/tmp/from-file-verifier',
                'verifier_replay_target' => 'remote_lab',
            ),
        ), JSON_UNESCAPED_SLASHES);
        self::assertIsString($json);
        file_put_contents($configFilePath, $json);

        $config = AppRuntimeConfig::fromEnvironment(array(
            'PHP_TAINT_TRACE_CONFIG_FILE' => $configFilePath,
            'PHP_TAINT_TRACE_REPORTING_TABLE' => 'env_reports',
        ));

        self::assertFalse($config->enabled());
        self::assertSame('/tmp/from-file-findings.jsonl', $config->findingsFilePath());
        self::assertSame('sqlite', $config->reportingBackend());
        self::assertSame('sqlite:/tmp/from-file-reporting.sqlite3', $config->reportingDsn());
        self::assertSame('env_reports', $config->reportingTable());
        self::assertSame('/tmp/from-file-verifier', $config->verifierRuntimeDir());
        self::assertSame('remote_lab', $config->verifierReplayTarget());
        self::assertSame($configFilePath, $config->configFilePath());
    }
}
