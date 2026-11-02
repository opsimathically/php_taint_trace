<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\RceRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class RceRuntimeSliceParityTest extends TestCase
{
    public function testRceParityContractsAreCoveredByRuntimeHookPlan(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new RceRuntimeSlice($backend);
        $slice->bootstrap();

        $hookSet = array_fill_keys(array_keys($backend->hooks()), true);
        $contractIds = array_map(
            static fn (array $contract): string => $contract['id'],
            array_values(array_filter(
                LegacyParityCatalog::contracts(),
                static fn (array $contract): bool => str_starts_with($contract['id'], 'sink.rce.')
            ))
        );

        foreach ($contractIds as $contractId) {
            self::assertArrayHasKey(
                $contractId,
                $hookSet,
                sprintf('RCE contract hook missing from runtime plan: %s', $contractId)
            );
        }
    }

    public function testUnserializePayloadContractIsActionableInRewrite(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new RceRuntimeSlice($backend);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.rce.unserialize', array(
            'a:1:{s:1:"k";s:6:"xtanzi";}',
        ));

        $detectors = array_map(
            static fn ($finding): string => $finding->detector(),
            $slice->findings()
        );
        self::assertSame(array('payload-keyword-detector'), $detectors);
    }
}
