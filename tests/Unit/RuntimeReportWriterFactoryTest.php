<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Reporting\JsonlRuntimeReportWriter;
use PhpTaintTrace\Reporting\PdoRuntimeReportWriter;
use PhpTaintTrace\Reporting\RuntimeReportWriterFactory;
use PhpTaintTrace\Runtime\AppRuntimeConfig;
use PHPUnit\Framework\TestCase;

final class RuntimeReportWriterFactoryTest extends TestCase
{
    public function testFactoryReturnsJsonlWriterByDefault(): void
    {
        $writer = RuntimeReportWriterFactory::fromConfig(
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: null,
                emitErrorLog: false,
                clearFindingsAfterFlush: true
            )
        );

        self::assertInstanceOf(JsonlRuntimeReportWriter::class, $writer);
    }

    public function testFactoryFallsBackToJsonlWhenPdoBackendMissingDsn(): void
    {
        $writer = RuntimeReportWriterFactory::fromConfig(
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: null,
                emitErrorLog: false,
                clearFindingsAfterFlush: true,
                emitCandidates: false,
                enableOpcodeHooks: false,
                opcodeHookProfile: 'safe',
                enableVerifier: false,
                verifierRuntimeDir: '.php_taint_trace_runtime/verifier',
                verifierReplayTarget: 'local',
                reportingBackend: 'pdo',
                reportingDsn: null
            )
        );

        self::assertInstanceOf(JsonlRuntimeReportWriter::class, $writer);
    }

    public function testFactoryReturnsPdoWriterWhenSqliteBackendConfigured(): void
    {
        $writer = RuntimeReportWriterFactory::fromConfig(
            new AppRuntimeConfig(
                enabled: true,
                findingsFilePath: null,
                emitErrorLog: false,
                clearFindingsAfterFlush: true,
                emitCandidates: false,
                enableOpcodeHooks: false,
                opcodeHookProfile: 'safe',
                enableVerifier: false,
                verifierRuntimeDir: '.php_taint_trace_runtime/verifier',
                verifierReplayTarget: 'local',
                reportingBackend: 'sqlite',
                reportingDsn: '/tmp/php-taint-runtime-reporting.sqlite3'
            )
        );

        self::assertInstanceOf(PdoRuntimeReportWriter::class, $writer);
    }
}

