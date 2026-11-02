<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\OpcodeRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class OpcodeRuntimeSliceTest extends TestCase
{
    public function testBootstrapRegistersAllOpcodeHooks(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);

        $report = $slice->bootstrap();

        self::assertSame(14, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(14, $backend->hooks());
        self::assertArrayHasKey('opcode.concat', $backend->hooks());
        self::assertArrayHasKey('opcode.include_or_eval', $backend->hooks());
        self::assertArrayHasKey('opcode.echo', $backend->hooks());
        self::assertArrayNotHasKey('sink.rce.system', $backend->hooks());
    }

    public function testBootstrapRegistersSafeOpcodeProfileSubset(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend, hookProfile: OpcodeRuntimeSlice::HOOK_PROFILE_SAFE);

        $report = $slice->bootstrap();

        self::assertSame(4, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(4, $backend->hooks());
        self::assertArrayHasKey('opcode.include_or_eval', $backend->hooks());
        self::assertArrayHasKey('opcode.echo', $backend->hooks());
        self::assertArrayNotHasKey('opcode.do_fcall', $backend->hooks());
        self::assertArrayNotHasKey('opcode.concat', $backend->hooks());
    }

    public function testDynamicCallOpcodeDispatchProducesRceFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('opcode.init_dynamic_call', array(
            TaintedValue::tainted('init_dynamic_call_hello', 'query.fn'),
        ));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('init_dynamic_call', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
    }

    public function testIncludeOrEvalPayloadProducesRcePayloadFinding(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('opcode.include_or_eval', array('../xtanzi/config.php'));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('include_or_eval', $findings[0]->sinkName());
        self::assertSame('payload-keyword-detector', $findings[0]->detector());
    }

    public function testEchoOpcodeDispatchProducesXssTaintFinding(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('opcode.echo', array(TaintedValue::tainted('hello', 'query.q')));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('echo', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
    }

    public function testDoIcallOpcodeDispatchProducesTaintAndPayloadFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('opcode.do_icall', array(
            'call_user_func',
            array(TaintedValue::tainted('xtanzi', 'query.cb')),
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame('do_icall', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testDoUcallOpcodeDispatchProducesTaintAndPayloadFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('opcode.do_ucall', array(
            'dynamic_fn',
            array(TaintedValue::tainted('prefix_xtanzi_suffix', 'query.fn')),
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame('do_ucall', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testExitOpcodeDispatchProducesXssTaintFinding(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('opcode.exit', array(
            TaintedValue::tainted('bye', 'query.msg'),
        ));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('exit', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
    }

    public function testConcatOpcodePostHookReturnsTaintAwareResult(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $result = $backend->dispatchPostHook('opcode.concat', array(
            'prefix-',
            TaintedValue::tainted('value', 'query.v'),
        ), 'ignored');

        self::assertInstanceOf(TaintedValue::class, $result);
        self::assertSame('prefix-value', $result->value());
        self::assertTrue($result->isTainted());
    }

    public function testRopeEndOpcodePostHookReturnsTaintAwareResult(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $result = $backend->dispatchPostHook('opcode.rope_end', array(
            array('hello ', TaintedValue::tainted('world', 'query.w')),
        ), 'ignored');

        self::assertInstanceOf(TaintedValue::class, $result);
        self::assertSame('hello world', $result->value());
        self::assertTrue($result->isTainted());
    }
}
