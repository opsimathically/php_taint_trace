<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\PayloadKeywordDetector;
use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\DetectorPipeline;
use PhpTaintTrace\Runtime\SqliRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class SqliRuntimeSliceTest extends TestCase
{
    public function testBootstrapRegistersSqliFunctionAndMethodHooks(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend);

        $report = $slice->bootstrap();

        self::assertSame(31, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(31, $backend->hooks());
        self::assertArrayHasKey('sink.sqli.mysqli_query', $backend->hooks());
        self::assertArrayHasKey('sink.sqli.mysqli_execute_query', $backend->hooks());
        self::assertArrayHasKey('sink.sqli.pg_execute', $backend->hooks());
        self::assertArrayHasKey('sink.sqli.oci_parse', $backend->hooks());
        self::assertArrayHasKey('sink.sqli.sqlsrv_prepare', $backend->hooks());
        self::assertArrayHasKey('method.sqli.mysqli.execute_query', $backend->hooks());
        self::assertArrayHasKey('method.sqli.pdo.prepare', $backend->hooks());
        self::assertArrayNotHasKey('sink.rce.system', $backend->hooks());
    }

    public function testFunctionHookDispatchProducesFindingsThroughDetectorPipeline(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $pipeline = new DetectorPipeline(
            new TaintInputDetector(),
            new PayloadKeywordDetector('xtanzi')
        );
        $slice = new SqliRuntimeSlice($backend, $pipeline);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.sqli.mysqli_query', array(
            new \stdClass(),
            TaintedValue::tainted('SELECT 1 FROM users WHERE id = xtanzi', 'query.id'),
            0,
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame('mysqli_query', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testMethodHookDispatchProducesFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('method.sqli.pdo.prepare', array(
            TaintedValue::tainted('SELECT * FROM users', 'query.sql'),
            array(),
        ));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('PDO::prepare', $findings[0]->sinkName());
    }

    public function testPgPrepareInspectsSqlArgumentPosition(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.sqli.pg_prepare', array(
            new \stdClass(),
            TaintedValue::tainted('statement_name', 'query.name'),
            'SELECT 1',
        ));
        self::assertCount(0, $slice->findings());

        $backend->dispatchPreHook('sink.sqli.pg_prepare', array(
            new \stdClass(),
            'statement_name',
            TaintedValue::tainted('SELECT 1', 'query.sql'),
        ));
        self::assertCount(1, $slice->findings());
        self::assertSame('pg_prepare', $slice->findings()[0]->sinkName());
    }

    public function testMysqliInitDoesNotProduceDetectionWithoutSqlInput(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.sqli.mysqli_init', array(
            TaintedValue::tainted('ignored', 'query.x'),
        ));

        self::assertCount(0, $slice->findings());
    }

    public function testMysqliExecuteQueryInspectsSqlArgumentPosition(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.sqli.mysqli_execute_query', array(
            new \stdClass(),
            TaintedValue::tainted('SELECT * FROM users WHERE id = xtanzi', 'query.sql'),
            array(),
        ));

        self::assertCount(1, $slice->findings());
        self::assertSame('mysqli_execute_query', $slice->findings()[0]->sinkName());
    }

    public function testPgQueryPreparedInspectsPreparedValueArgumentArraySlot(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.sqli.pg_query_prepared', array(
            new \stdClass(),
            'stmt_name',
            TaintedValue::tainted('id=xtanzi', 'query.id'),
        ));

        self::assertCount(1, $slice->findings());
        self::assertSame('pg_query_prepared', $slice->findings()[0]->sinkName());
    }

    public function testSqlsrvQueryInspectsSqlArgumentPosition(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.sqli.sqlsrv_query', array(
            new \stdClass(),
            TaintedValue::tainted('SELECT * FROM users WHERE id = xtanzi', 'query.sql'),
        ));

        self::assertCount(1, $slice->findings());
        self::assertSame('sqlsrv_query', $slice->findings()[0]->sinkName());
    }

    public function testSqlsrvPrepareInspectsSqlArgumentPosition(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.sqli.sqlsrv_prepare', array(
            new \stdClass(),
            TaintedValue::tainted('SELECT * FROM users WHERE id = xtanzi', 'query.sql'),
        ));

        self::assertCount(1, $slice->findings());
        self::assertSame('sqlsrv_prepare', $slice->findings()[0]->sinkName());
    }

    public function testOciExecuteDoesNotInspectStatementHandleAsSqlText(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.sqli.oci_execute', array(
            TaintedValue::tainted('statement-handle', 'query.sql'),
        ));

        self::assertCount(0, $slice->findings());
    }

    public function testMysqliExecuteQueryCapturesSqlQueryAndParametersInCandidateMetadata(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice(
            $backend,
            new DetectorPipeline(new TaintInputDetector()),
            emitCandidates: true
        );
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.sqli.mysqli_execute_query', array(
            new \stdClass(),
            TaintedValue::tainted('SELECT * FROM users WHERE id = ?', 'query.sql'),
            array(TaintedValue::tainted('1337', 'query.id')),
        ));

        $candidates = $slice->candidates();
        self::assertCount(1, $candidates);
        $sqlMetadata = $candidates[0]->sinkEvidence()->metadata()['sql'] ?? null;
        self::assertIsArray($sqlMetadata);
        self::assertSame('sink.sqli.mysqli_execute_query', $sqlMetadata['hook_id'] ?? null);
        self::assertSame('SELECT * FROM users WHERE id = ?', $sqlMetadata['query'] ?? null);
        self::assertSame(array('1337'), $sqlMetadata['parameters'] ?? null);
    }
}
