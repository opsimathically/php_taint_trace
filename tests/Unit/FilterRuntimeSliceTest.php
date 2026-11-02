<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\FilterRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class FilterRuntimeSliceTest extends TestCase
{
    public function testBootstrapRegistersFilterHooksOnly(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FilterRuntimeSlice($backend);

        $report = $slice->bootstrap();

        self::assertSame(28, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(28, $backend->hooks());
        self::assertArrayHasKey('filter.strtoupper', $backend->hooks());
        self::assertArrayHasKey('filter.json_decode', $backend->hooks());
        self::assertArrayNotHasKey('sink.file.readfile', $backend->hooks());
    }

    public function testSimpleStringFilterPropagatesTaint(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FilterRuntimeSlice($backend);
        $slice->bootstrap();

        $result = $backend->dispatchPreHook('filter.strtoupper', array(
            TaintedValue::tainted('hello', 'query.q'),
        ));

        self::assertInstanceOf(TaintedValue::class, $result);
        self::assertSame('HELLO', $result->value());
        self::assertTrue($result->isTainted());
    }

    public function testSprintfPropagatesTaintFromAnyArgument(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FilterRuntimeSlice($backend);
        $slice->bootstrap();

        $result = $backend->dispatchPreHook('filter.sprintf', array(
            'hello %s',
            TaintedValue::tainted('world', 'query.name'),
        ));

        self::assertInstanceOf(TaintedValue::class, $result);
        self::assertSame('hello world', $result->value());
    }

    public function testStringReplacePropagatesTaintFromSubjectOrReplace(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FilterRuntimeSlice($backend);
        $slice->bootstrap();

        $subjectResult = $backend->dispatchPreHook('filter.str_replace', array(
            'foo',
            'bar',
            TaintedValue::tainted('foo value', 'query.subject'),
        ));
        self::assertInstanceOf(TaintedValue::class, $subjectResult);
        self::assertSame('bar value', $subjectResult->value());

        $replaceResult = $backend->dispatchPreHook('filter.str_ireplace', array(
            'foo',
            TaintedValue::tainted('BAR', 'query.replace'),
            'foo value',
        ));
        self::assertInstanceOf(TaintedValue::class, $replaceResult);
    }

    public function testJsonDecodePreservesLegacyObjectVsAssocBehavior(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FilterRuntimeSlice($backend);
        $slice->bootstrap();

        $json = TaintedValue::tainted('{"e":"test"}', 'query.json');
        $objectResult = $backend->dispatchPreHook('filter.json_decode', array($json));
        self::assertFalse($backend->isTainted($objectResult, true));

        $assocResult = $backend->dispatchPreHook('filter.json_decode', array($json, true));
        self::assertTrue($backend->isTainted($assocResult, true));
    }

    public function testCleanInputProducesCleanResult(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FilterRuntimeSlice($backend);
        $slice->bootstrap();

        $result = $backend->dispatchPreHook('filter.trim', array("  safe  "));

        self::assertIsString($result);
        self::assertSame('safe', $result);
        self::assertFalse($backend->isTainted($result, true));
    }
}
