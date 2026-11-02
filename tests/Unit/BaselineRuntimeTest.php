<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\BaselineRuntime;
use PHPUnit\Framework\TestCase;

final class BaselineRuntimeTest extends TestCase
{
    public function testBootstrapRegistersFullBaselineHookSurface(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend);

        $report = $runtime->bootstrap();

        self::assertSame(130, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(130, $backend->hooks());
        self::assertArrayHasKey('sink.rce.system', $backend->hooks());
        self::assertArrayHasKey('sink.rce.mail', $backend->hooks());
        self::assertArrayHasKey('sink.sqli.mysqli_query', $backend->hooks());
        self::assertArrayHasKey('sink.sqli.mysqli_execute_query', $backend->hooks());
        self::assertArrayHasKey('sink.sqli.sqlsrv_prepare', $backend->hooks());
        self::assertArrayHasKey('sink.sqli.sqlsrv_query', $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.curl_exec', $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.curl_multi_exec', $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.stream_socket_client', $backend->hooks());
        self::assertArrayHasKey('method.ssrf.soapclient.__construct', $backend->hooks());
        self::assertArrayHasKey('method.ssrf.soapclient.__setLocation', $backend->hooks());
        self::assertArrayHasKey('aux.ssrf.curl_setopt', $backend->hooks());
        self::assertArrayHasKey('aux.ssrf.curl_multi_add_handle', $backend->hooks());
        self::assertArrayHasKey('sink.file.readfile', $backend->hooks());
        self::assertArrayHasKey('method.file.splfileobject.__construct', $backend->hooks());
        self::assertArrayHasKey('sink.xss.printf', $backend->hooks());
        self::assertArrayHasKey('sink.xxe.simplexml_load_string', $backend->hooks());
        self::assertArrayHasKey('method.xxe.domdocument.load', $backend->hooks());
        self::assertArrayHasKey('method.xxe.xmlreader.open', $backend->hooks());
        self::assertArrayHasKey('opcode.include_or_eval', $backend->hooks());
        self::assertArrayHasKey('filter.vsprintf', $backend->hooks());
    }

    public function testFindingsAreAggregatedAcrossSlices(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend);
        $runtime->bootstrap();

        $backend->dispatchPreHook('sink.rce.system', array(
            TaintedValue::tainted('id', 'query.cmd'),
        ));
        $backend->dispatchPreHook('sink.sqli.mysqli_query', array(
            new \stdClass(),
            'SELECT xtanzi',
            0,
        ));
        $backend->dispatchPreHook('sink.xss.print_r', array(
            TaintedValue::tainted('hello', 'query.q'),
        ));

        $findings = $runtime->findings();
        self::assertCount(3, $findings);
        self::assertSame('system', $findings[0]->sinkName());
        self::assertSame('mysqli_query', $findings[1]->sinkName());
        self::assertSame('print_r', $findings[2]->sinkName());
    }

    public function testClearFindingsClearsAllSlices(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend);
        $runtime->bootstrap();

        $backend->dispatchPreHook('sink.rce.system', array(
            TaintedValue::tainted('id', 'query.cmd'),
        ));
        self::assertCount(1, $runtime->findings());

        $runtime->clearFindings();
        self::assertCount(0, $runtime->findings());
    }

    public function testCandidatesAreAggregatedAndCanBeCleared(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, true, 'full', true);
        $runtime->bootstrap();

        $backend->dispatchPreHook('sink.rce.system', array(
            TaintedValue::tainted('id', '_GET'),
        ));
        $backend->dispatchPreHook('sink.xss.print_r', array(
            TaintedValue::tainted('hello', '_GET'),
        ));

        $candidates = $runtime->candidates();
        self::assertCount(2, $candidates);
        self::assertSame('system', $candidates[0]->sinkName());
        self::assertSame('print_r', $candidates[1]->sinkName());
        self::assertCount(2, $runtime->findings());

        $runtime->clearCandidates();
        self::assertCount(0, $runtime->candidates());
        self::assertCount(2, $runtime->findings());
    }

    public function testBootstrapCanDisableOpcodeSlice(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, false);

        $report = $runtime->bootstrap();

        self::assertSame(116, $report->registeredCount());
        self::assertArrayNotHasKey('opcode.include_or_eval', $backend->hooks());
        self::assertArrayHasKey('sink.rce.system', $backend->hooks());
    }

    public function testBootstrapSupportsSafeOpcodeProfile(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, true, 'safe');

        $report = $runtime->bootstrap();

        self::assertSame(120, $report->registeredCount());
        self::assertArrayHasKey('opcode.include_or_eval', $backend->hooks());
        self::assertArrayHasKey('opcode.echo', $backend->hooks());
        self::assertArrayNotHasKey('opcode.do_fcall', $backend->hooks());
        self::assertArrayNotHasKey('opcode.concat', $backend->hooks());
    }
}
