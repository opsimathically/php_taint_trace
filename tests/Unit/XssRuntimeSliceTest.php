<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\XssRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class XssRuntimeSliceTest extends TestCase
{
    public function testBootstrapRegistersXssHooksOnly(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new XssRuntimeSlice($backend);

        $report = $slice->bootstrap();

        self::assertSame(3, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(3, $backend->hooks());
        self::assertArrayHasKey('sink.xss.print_r', $backend->hooks());
        self::assertArrayHasKey('sink.xss.printf', $backend->hooks());
        self::assertArrayHasKey('sink.xss.vprintf', $backend->hooks());
        self::assertArrayNotHasKey('opcode.echo', $backend->hooks());
    }

    public function testPrintRHookDispatchProducesTaintFinding(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new XssRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.xss.print_r', array(
            TaintedValue::tainted('<script>x</script>', 'query.q'),
        ));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('print_r', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
    }

    public function testPrintfHookUsesRenderedStringWithTaintPropagation(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new XssRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.xss.printf', array(
            'hello %s',
            TaintedValue::tainted('world', 'query.name'),
        ));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('printf', $findings[0]->sinkName());
    }

    public function testVprintfHookUsesRenderedStringWithTaintPropagation(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new XssRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.xss.vprintf', array(
            'hello %s',
            array(TaintedValue::tainted('world', 'query.name')),
        ));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('vprintf', $findings[0]->sinkName());
    }

    public function testCleanInputProducesNoFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new XssRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.xss.printf', array('hello %s', 'safe'));
        self::assertCount(0, $slice->findings());
    }
}
