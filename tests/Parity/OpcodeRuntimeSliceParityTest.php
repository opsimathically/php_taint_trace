<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\OpcodeRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class OpcodeRuntimeSliceParityTest extends TestCase
{
    public function testOpcodeParityContractsAreCoveredByStage9HookPlan(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $hookSet = array_fill_keys(array_keys($backend->hooks()), true);
        $contractIds = array_map(
            static fn (array $contract): string => $contract['id'],
            array_values(array_filter(
                LegacyParityCatalog::contracts(),
                static fn (array $contract): bool => str_starts_with($contract['id'], 'opcode.')
            ))
        );

        foreach ($contractIds as $contractId) {
            self::assertArrayHasKey(
                $contractId,
                $hookSet,
                sprintf('Opcode contract hook missing from Stage 9 plan: %s', $contractId)
            );
        }
    }

    public function testDoIcallContractHasActionableBehaviorInRewrite(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('opcode.do_icall', array(
            'call_user_func',
            array(TaintedValue::tainted('xtanzi', 'query.cb')),
        ));

        self::assertSame(
            array('taint-input-detector', 'payload-keyword-detector'),
            $this->detectorNames($slice)
        );
    }

    public function testDoUcallContractHasActionableBehaviorInRewrite(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('opcode.do_ucall', array(
            'dynamic_fn',
            array(TaintedValue::tainted('xtanzi', 'query.cb')),
        ));

        self::assertSame(
            array('taint-input-detector', 'payload-keyword-detector'),
            $this->detectorNames($slice)
        );
    }

    public function testExitContractHasActionableBehaviorInRewrite(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new OpcodeRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('opcode.exit', array(
            TaintedValue::tainted('bye', 'query.msg'),
        ));

        self::assertSame(
            array('taint-input-detector'),
            $this->detectorNames($slice)
        );
    }

    /**
     * @return string[]
     */
    private function detectorNames(OpcodeRuntimeSlice $slice): array
    {
        return array_map(
            static fn ($finding): string => $finding->detector(),
            $slice->findings()
        );
    }
}
